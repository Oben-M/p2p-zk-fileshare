// public/spake2-ec.js
//
// The same SPAKE2 protocol as spake2.js, but over the NIST P-256 elliptic
// curve instead of a finite field -- this is the variant production
// systems actually use (smaller keys for equivalent security: ~256-bit
// points here vs. our 2048-bit modulus in the finite-field version).
//
// Unlike spake2.js, this uses the REAL IETF-standardized M and N points
// from RFC 9382 Section 6 (the P-256 ciphersuite), not self-derived NUMS
// points -- that's only possible now because we have a real EC library
// (@noble/curves) capable of representing arbitrary published curve
// points, which our hand-rolled finite-field math couldn't do safely.
//
// CRITICAL DEPENDENCY: @noble/curves, an audited, widely-used library
// (used inside several production wallet/crypto codebases). We do NOT
// hand-roll elliptic curve point arithmetic -- unlike modular
// exponentiation over a finite field, EC point arithmetic has real,
// well-documented side-channel and point-validation pitfalls that are
// genuinely dangerous to get subtly wrong. Pinned to a specific version
// (1.6.0) deliberately, loaded as a real ES module import rather than a
// global script tag.

import { p256 } from 'https://cdn.jsdelivr.net/npm/@noble/curves@1.6.0/p256/+esm';

const G = p256.ProjectivePoint.BASE;
const ORDER = p256.CURVE.n;

// RFC 9382 Section 6, SPAKE2-P256-SHA256-HKDF-HMAC ciphersuite.
// M: seed "1.2.840.10045.3.1.7 point generation seed (M)"
// N: seed "1.2.840.10045.3.1.7 point generation seed (N)"
const M = p256.ProjectivePoint.fromHex('02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f');
const N = p256.ProjectivePoint.fromHex('03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49');

function bytesToBigInt(bytes) {
  let hex = '0x';
  for (const b of bytes) hex += b.toString(16).padStart(2, '0');
  return BigInt(hex);
}

function bytesToHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}

async function sha256Concat(...parts) {
  const encoder = new TextEncoder();
  const buffers = parts.map((p) => (typeof p === 'string' ? encoder.encode(p) : p));
  const totalLen = buffers.reduce((sum, b) => sum + b.length, 0);
  const merged = new Uint8Array(totalLen);
  let offset = 0;
  for (const b of buffers) {
    merged.set(b, offset);
    offset += b.length;
  }
  const digest = await crypto.subtle.digest('SHA-256', merged);
  return new Uint8Array(digest);
}

async function deriveScalar(code) {
  const hash = await sha256Concat('p2p-zk-fileshare:SPAKE2-EC:password:' + code);
  let w = bytesToBigInt(hash) % ORDER;
  if (w === 0n) w = 1n;
  return w;
}

function randomScalar() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  let x = bytesToBigInt(bytes) % ORDER;
  if (x === 0n) x = 1n;
  return x;
}

export class Spake2ECParty {
  constructor(role) {
    if (role !== 'A' && role !== 'B') throw new Error('role must be "A" or "B"');
    this.role = role;
  }

  // Step 1: produce the outgoing PAKE message (a compressed EC point,
  // 33 bytes / 66 hex chars). Safe to send over the signaling channel.
  async start(code) {
    this.w = await deriveScalar(code);
    this.x = randomScalar();

    const X = G.multiply(this.x);
    const myBlindPoint = this.role === 'A' ? M : N;
    this.outgoingPoint = X.add(myBlindPoint.multiply(this.w));
    this.outgoingHex = bytesToHex(this.outgoingPoint.toRawBytes(true));
    return this.outgoingHex;
  }

  // Step 2: feed in the peer's point, derive the shared session key and
  // our own key-confirmation tag.
  async finish(peerHex) {
    const T_peer = p256.ProjectivePoint.fromHex(hexToBytes(peerHex));
    const theirBlindPoint = this.role === 'A' ? N : M;
    const Y = T_peer.subtract(theirBlindPoint.multiply(this.w)); // peer's bare y*G, blinding removed
    const sharedPoint = Y.multiply(this.x); // xy*G, same on both sides iff w matched

    const sharedHex = bytesToHex(sharedPoint.toRawBytes(true));
    const transcriptA = this.role === 'A' ? this.outgoingHex : peerHex;
    const transcriptB = this.role === 'A' ? peerHex : this.outgoingHex;
    const keyMaterial = await sha256Concat('p2p-zk-fileshare:SPAKE2-EC:key', sharedHex, transcriptA, transcriptB);

    this.sessionKey = keyMaterial; // Uint8Array(32), usable directly as an AES-256 key
    this.confirmTag = await sha256Concat('confirm', this.role, keyMaterial);
    return {
      sessionKey: this.sessionKey,
      confirmTagHex: bytesToHex(this.confirmTag),
    };
  }

  // Step 3: verify the peer's confirmation tag. Mismatched codes fail
  // here cleanly rather than silently producing garbage keys.
  async verifyPeerConfirmation(peerConfirmTagHex) {
    const peerRole = this.role === 'A' ? 'B' : 'A';
    const expected = await sha256Concat('confirm', peerRole, this.sessionKey);
    return bytesToHex(expected) === peerConfirmTagHex;
  }
}
