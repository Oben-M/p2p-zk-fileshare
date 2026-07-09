// public/webrtc-transfer.js
import { CHUNK_SIZE, makeIv, encryptChunk, decryptChunk } from './crypto-utils.js';

function parseCandidateType(s) {
  const m = /typ (\w+)/.exec(s || '');
  return m ? m[1] : 'unknown';
}

export class WebRTCTransfer {
  constructor(role, signalingSend, onLog = () => {}, onDebug = () => {}) {
    this.role = role;
    this.signalingSend = signalingSend;
    this.onLog = onLog;
    this.onDebug = onDebug;
    this.dataChannel = null;
    this.pendingCandidates = [];
    this.pc = null;
    this.chunkCounter = 0;
    this.connectionDead = false;
  }

  async connect(iceServers, { relayOnly = false } = {}) {
    this.pc = new RTCPeerConnection({ iceServers, iceTransportPolicy: relayOnly ? 'relay' : 'all' });
    if (relayOnly) this.onLog('Relay-only mode active — using TURN server.');

    this.pc.onicecandidate = (e) => {
      if (e.candidate) {
        this.onDebug(`ICE candidate: ${parseCandidateType(e.candidate.candidate)}`);
        this.signalingSend({ type: 'ice-candidate', candidate: e.candidate });
      }
    };

    this.pc.onconnectionstatechange = () => {
      const s = this.pc.connectionState;
      this.onDebug(`Connection state: ${s}`);
      if (s === 'connected') { this.connectionDead = false; this._logSelectedPair(); }
      if (s === 'failed' || s === 'closed') {
        this.connectionDead = true;
        this.onLog('Connection lost. Refresh both sides to reconnect.', true);
      }
    };

    this.pc.oniceconnectionstatechange = () => {
      this.onDebug(`ICE state: ${this.pc.iceConnectionState}`);
    };

    const channelReady = new Promise((resolve) => {
      if (this.role === 'A') {
        const dc = this.pc.createDataChannel('file-transfer', { ordered: true });
        this._wireChannel(dc, resolve);
      } else {
        this.pc.ondatachannel = (e) => this._wireChannel(e.channel, resolve);
      }
    });

    if (this.role === 'A') {
      const offer = await this.pc.createOffer();
      await this.pc.setLocalDescription(offer);
      this.onDebug('Sending SDP offer');
      this.signalingSend({ type: 'sdp-offer', sdp: this.pc.localDescription });
    }

    return channelReady;
  }

  _wireChannel(dc, resolve) {
    this.dataChannel = dc;
    dc.binaryType = 'arraybuffer';
    dc.bufferedAmountLowThreshold = 256 * 1024;
    dc.onopen = () => { this.onLog('Ready to transfer files.'); resolve(dc); };
    dc.onerror = (e) => this.onLog(`Channel error: ${e.message || e}`, true);
  }

  async handleSignal(msg) {
    if (msg.type === 'sdp-offer' && this.role === 'B') {
      this.onDebug('Received SDP offer');
      await this.pc.setRemoteDescription(msg.sdp);
      await this._flushCandidates();
      const answer = await this.pc.createAnswer();
      await this.pc.setLocalDescription(answer);
      this.onDebug('Sending SDP answer');
      this.signalingSend({ type: 'sdp-answer', sdp: this.pc.localDescription });
      return;
    }
    if (msg.type === 'sdp-answer' && this.role === 'A') {
      this.onDebug('Received SDP answer');
      await this.pc.setRemoteDescription(msg.sdp);
      await this._flushCandidates();
      return;
    }
    if (msg.type === 'ice-candidate') {
      if (this.pc.remoteDescription) {
        await this.pc.addIceCandidate(msg.candidate).catch(e => this.onDebug(`addIceCandidate: ${e.message}`));
      } else {
        this.pendingCandidates.push(msg.candidate);
      }
    }
  }

  async _flushCandidates() {
    while (this.pendingCandidates.length) {
      const c = this.pendingCandidates.shift();
      await this.pc.addIceCandidate(c).catch(e => this.onDebug(`addIceCandidate: ${e.message}`));
    }
  }

  async _logSelectedPair() {
    try {
      const stats = await this.pc.getStats();
      let pair = null;
      for (const r of stats.values()) {
        if (r.type === 'candidate-pair' && r.state === 'succeeded' && (r.nominated || r.selected)) { pair = r; break; }
      }
      if (!pair) for (const r of stats.values()) {
        if (r.type === 'candidate-pair' && r.state === 'succeeded') { pair = r; break; }
      }
      if (!pair) return;
      const local = stats.get(pair.localCandidateId);
      const remote = stats.get(pair.remoteCandidateId);
      const lt = local?.candidateType || '?';
      const rt = remote?.candidateType || '?';
      const label = lt === 'relay' ? 'TURN relay' : lt === 'srflx' ? 'STUN (direct across NAT)' : 'direct (same network)';
      this.onLog(`Connected via ${label} (local=${lt}, remote=${rt})`);
    } catch (e) { this.onDebug(`getStats failed: ${e.message}`); }
  }

  async _waitForBufferSpace() {
    const dc = this.dataChannel;
    if (dc.bufferedAmount <= dc.bufferedAmountLowThreshold) return;
    if (this.connectionDead) throw new Error('Connection failed — aborting send.');
    await new Promise((resolve, reject) => {
      const cleanup = () => { dc.removeEventListener('bufferedamountlow', h); clearInterval(di); clearTimeout(ti); };
      const h = () => { cleanup(); resolve(); };
      const di = setInterval(() => { if (this.connectionDead) { cleanup(); reject(new Error('Connection failed.')); } }, 500);
      const ti = setTimeout(() => { cleanup(); reject(new Error('Timed out waiting to send (30s).')); }, 30000);
      dc.addEventListener('bufferedamountlow', h);
    });
  }

  async _sendFrame(aesKey, salt4, frameType, plaintext) {
    const counter = this.chunkCounter++;
    const iv = makeIv(salt4, counter);
    const ciphertext = await encryptChunk(aesKey, plaintext, iv);
    const frame = new Uint8Array(5 + ciphertext.length);
    new DataView(frame.buffer).setUint32(0, counter, false);
    frame[4] = frameType;
    frame.set(ciphertext, 5);
    this.dataChannel.send(frame);
  }

  async sendFile(file, aesKey, salt4, { onProgress } = {}) {
    const meta = { name: file.name, size: file.size, mime: file.type || 'application/octet-stream' };
    await this._sendFrame(aesKey, salt4, 0, new TextEncoder().encode(JSON.stringify(meta)));
    const totalChunks = Math.ceil(file.size / CHUNK_SIZE) || 1;
    const t0 = performance.now();
    let sent = 0;
    for (let i = 0; i < totalChunks; i++) {
      const buf = new Uint8Array(await file.slice(i * CHUNK_SIZE, (i + 1) * CHUNK_SIZE).arrayBuffer());
      await this._waitForBufferSpace();
      await this._sendFrame(aesKey, salt4, 1, buf);
      sent += buf.length;
      onProgress?.({ sent, total: file.size });
    }
    return { elapsedMs: performance.now() - t0, bytes: file.size };
  }

  setupReceiver(aesKey, salt4, { onMeta, onProgress, onComplete } = {}) {
    let meta = null, received = 0, chunks = [], t0 = null;
    this.dataChannel.onmessage = async (event) => {
      const data = new Uint8Array(event.data);
      const counter = new DataView(data.buffer, data.byteOffset, 4).getUint32(0, false);
      const frameType = data[4];
      const ciphertext = data.slice(5);
      let plaintext;
      try { plaintext = await decryptChunk(aesKey, ciphertext, makeIv(salt4, counter)); }
      catch { this.onLog('Decryption failed — file may be corrupted or tampered with.', true); return; }
      if (frameType === 0) {
        meta = JSON.parse(new TextDecoder().decode(plaintext));
        received = 0; chunks = []; t0 = performance.now();
        onMeta?.(meta); return;
      }
      chunks.push(plaintext); received += plaintext.length;
      onProgress?.({ received, total: meta.size });
      if (received >= meta.size) {
        const elapsedMs = performance.now() - t0;
        onComplete?.({ blob: new Blob(chunks, { type: meta.mime }), meta, elapsedMs });
      }
    };
  }

  close() { this.dataChannel?.close(); this.pc?.close(); }
}