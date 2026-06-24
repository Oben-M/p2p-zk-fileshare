// public/crypto-utils.js
//
// Thin wrapper around the browser's native SubtleCrypto for AES-256-GCM.
// Each chunk gets a unique nonce (IV) derived from a per-session random
// salt plus a monotonically increasing chunk counter -- this is what
// prevents GCM nonce reuse, which would otherwise be a real vulnerability
// if you encrypted many chunks under one key with a fixed or random-but-
// collidable IV.

export const CHUNK_SIZE = 64 * 1024; // 64 KiB plaintext per chunk

export async function importAesKey(rawKeyBytes) {
  return crypto.subtle.importKey('raw', rawKeyBytes, { name: 'AES-GCM' }, false, [
    'encrypt',
    'decrypt',
  ]);
}

export function randomSalt4() {
  const salt = new Uint8Array(4);
  crypto.getRandomValues(salt);
  return salt;
}

// 12-byte GCM nonce = 4-byte session salt + 8-byte big-endian chunk counter.
// Unique as long as no chunk counter repeats within one session key's
// lifetime, which holds here since counters are sequential per transfer
// and every transfer derives a brand new key via SPAKE2.
export function makeIv(salt4, counter) {
  const iv = new Uint8Array(12);
  iv.set(salt4, 0);
  const view = new DataView(iv.buffer);
  view.setBigUint64(4, BigInt(counter), false);
  return iv;
}

export async function encryptChunk(key, plaintextBytes, iv) {
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintextBytes);
  return new Uint8Array(ciphertext); // GCM auth tag (16 bytes) is appended automatically
}

export async function decryptChunk(key, ciphertextBytes, iv) {
  // Throws if the auth tag doesn't verify -- i.e. tampering or a wrong key
  // surfaces as a hard decryption failure, not silently-corrupted output.
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertextBytes);
  return new Uint8Array(plaintext);
}
