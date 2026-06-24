// public/webrtc-transfer.js
import { CHUNK_SIZE, makeIv, encryptChunk, decryptChunk } from './crypto-utils.js';

function parseCandidateType(candidateStr) {
  // e.g. "candidate:842163049 1 udp 1677729535 203.0.113.141 54609 typ srflx raddr ..."
  const m = /typ (\w+)/.exec(candidateStr || '');
  return m ? m[1] : 'unknown'; // host | srflx (via STUN) | relay (via TURN) | prflx
}

export class WebRTCTransfer {
  /**
   * @param {'A'|'B'} role  A = room creator = WebRTC offerer. B = joiner = answerer.
   * @param {(msg: object) => void} signalingSend  function that sends a JSON message over the signaling WebSocket
   * @param {(line: string) => void} onLog  for surfacing what's happening in the UI log panel
   */
  constructor(role, signalingSend, onLog = () => {}) {
    this.role = role;
    this.signalingSend = signalingSend;
    this.onLog = onLog;
    this.dataChannel = null;
    this.pendingCandidates = [];
    this.pc = null;
  }

  async connect(iceServers, { relayOnly = false } = {}) {
    this.pc = new RTCPeerConnection({
      iceServers,
      iceTransportPolicy: relayOnly ? 'relay' : 'all',
    });
    if (relayOnly) this.onLog('Forcing relay-only mode -- every candidate that isn\'t a TURN relay will be discarded, even on a friendly network.');

    this.pc.onicecandidate = (e) => {
      if (e.candidate) {
        this.onLog(`ICE candidate gathered: ${parseCandidateType(e.candidate.candidate)}`);
        this.signalingSend({ type: 'ice-candidate', candidate: e.candidate });
      }
    };

    this.pc.onconnectionstatechange = () => {
      this.onLog(`Peer connection state: ${this.pc.connectionState}`);
      if (this.pc.connectionState === 'connected') {
        this._logSelectedCandidatePair();
      }
    };

    this.pc.oniceconnectionstatechange = () => {
      this.onLog(`ICE connection state: ${this.pc.iceConnectionState}`);
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
      this.onLog('Sending SDP offer');
      this.signalingSend({ type: 'sdp-offer', sdp: this.pc.localDescription });
    }

    return channelReady; // resolves once the DataChannel is open and ready to use
  }

  _wireChannel(dc, resolve) {
    this.dataChannel = dc;
    dc.binaryType = 'arraybuffer';
    dc.bufferedAmountLowThreshold = 256 * 1024;
    dc.onopen = () => {
      this.onLog('DataChannel open -- direct P2P link established');
      resolve(dc);
    };
    dc.onerror = (e) => this.onLog(`DataChannel error: ${e.message || e}`);
  }

  // Call this with every signaling message of type sdp-offer / sdp-answer / ice-candidate.
  async handleSignal(msg) {
    if (msg.type === 'sdp-offer' && this.role === 'B') {
      this.onLog('Received SDP offer');
      await this.pc.setRemoteDescription(msg.sdp);
      await this._flushPendingCandidates();
      const answer = await this.pc.createAnswer();
      await this.pc.setLocalDescription(answer);
      this.onLog('Sending SDP answer');
      this.signalingSend({ type: 'sdp-answer', sdp: this.pc.localDescription });
      return;
    }
    if (msg.type === 'sdp-answer' && this.role === 'A') {
      this.onLog('Received SDP answer');
      await this.pc.setRemoteDescription(msg.sdp);
      await this._flushPendingCandidates();
      return;
    }
    if (msg.type === 'ice-candidate') {
      if (this.pc.remoteDescription) {
        await this.pc.addIceCandidate(msg.candidate).catch((e) => this.onLog(`addIceCandidate failed: ${e.message}`));
      } else {
        this.pendingCandidates.push(msg.candidate);
      }
    }
  }

  async _flushPendingCandidates() {
    while (this.pendingCandidates.length) {
      const c = this.pendingCandidates.shift();
      await this.pc.addIceCandidate(c).catch((e) => this.onLog(`addIceCandidate failed: ${e.message}`));
    }
  }

  // Gathered candidates (logged via onicecandidate) are just the options
  // that were *offered* -- this looks at getStats() to report which pair
  // actually won and is carrying real traffic. That's the only way to
  // know for certain whether STUN (srflx) or TURN (relay) made the
  // connection, versus a direct host-to-host link.
  async _logSelectedCandidatePair() {
    try {
      const stats = await this.pc.getStats();
      let pair = null;
      for (const report of stats.values()) {
        if (report.type === 'candidate-pair' && report.state === 'succeeded' && (report.nominated || report.selected)) {
          pair = report;
          break;
        }
      }
      if (!pair) {
        for (const report of stats.values()) {
          if (report.type === 'candidate-pair' && report.state === 'succeeded') {
            pair = report;
            break;
          }
        }
      }
      if (!pair) {
        this.onLog('Could not find a succeeded candidate pair in getStats() yet.');
        return;
      }
      const local = stats.get(pair.localCandidateId);
      const remote = stats.get(pair.remoteCandidateId);
      const localType = local?.candidateType || 'unknown';
      const remoteType = remote?.candidateType || 'unknown';
      this.onLog(`CONNECTED VIA: local=${localType} / remote=${remoteType} (this is the actual winning path, confirmed via getStats)`);
    } catch (e) {
      this.onLog(`getStats() lookup failed: ${e.message}`);
    }
  }

  async _waitForBufferSpace() {
    const dc = this.dataChannel;
    if (dc.bufferedAmount <= dc.bufferedAmountLowThreshold) return;
    await new Promise((resolve) => {
      const handler = () => {
        dc.removeEventListener('bufferedamountlow', handler);
        resolve();
      };
      dc.addEventListener('bufferedamountlow', handler);
    });
  }

  async _sendEncryptedFrame(aesKey, salt4, index, plaintextBytes) {
    const iv = makeIv(salt4, index);
    const ciphertext = await encryptChunk(aesKey, plaintextBytes, iv);
    const frame = new Uint8Array(4 + ciphertext.length);
    new DataView(frame.buffer).setUint32(0, index, false);
    frame.set(ciphertext, 4);
    this.dataChannel.send(frame);
  }

  // SENDER SIDE: streams the file in CHUNK_SIZE pieces, encrypting each one
  // as it goes (never holding the whole file in memory at once) and
  // respecting WebRTC backpressure so large files don't overrun the
  // DataChannel's internal buffer.
  async sendFile(file, aesKey, salt4, { onProgress } = {}) {
    const meta = { name: file.name, size: file.size, mime: file.type || 'application/octet-stream' };
    await this._sendEncryptedFrame(aesKey, salt4, 0, new TextEncoder().encode(JSON.stringify(meta)));

    const totalChunks = Math.ceil(file.size / CHUNK_SIZE) || 1;
    const startTime = performance.now();
    let sentBytes = 0;

    for (let i = 0; i < totalChunks; i++) {
      const start = i * CHUNK_SIZE;
      const slice = file.slice(start, start + CHUNK_SIZE);
      const buf = new Uint8Array(await slice.arrayBuffer());
      await this._waitForBufferSpace();
      await this._sendEncryptedFrame(aesKey, salt4, i + 1, buf);
      sentBytes += buf.length;
      onProgress?.({ sent: sentBytes, total: file.size, chunk: i + 1, totalChunks });
    }

    return { elapsedMs: performance.now() - startTime, bytes: file.size };
  }

  // RECEIVER SIDE: decrypts each frame as it arrives and reassembles once
  // the declared file size has been received.
  setupReceiver(aesKey, salt4, { onMeta, onProgress, onComplete } = {}) {
    let meta = null;
    let receivedBytes = 0;
    const chunks = [];
    let startTime = null;

    this.dataChannel.onmessage = async (event) => {
      const data = new Uint8Array(event.data);
      const index = new DataView(data.buffer, data.byteOffset, 4).getUint32(0, false);
      const ciphertext = data.slice(4);
      const iv = makeIv(salt4, index);

      let plaintext;
      try {
        plaintext = await decryptChunk(aesKey, ciphertext, iv);
      } catch (e) {
        this.onLog(`Decryption failed on chunk ${index} -- aborting (wrong key or tampered data)`);
        return;
      }

      if (index === 0) {
        meta = JSON.parse(new TextDecoder().decode(plaintext));
        startTime = performance.now();
        onMeta?.(meta);
        return;
      }

      chunks.push(plaintext);
      receivedBytes += plaintext.length;
      onProgress?.({ received: receivedBytes, total: meta.size });

      if (receivedBytes >= meta.size) {
        const elapsedMs = performance.now() - startTime;
        const blob = new Blob(chunks, { type: meta.mime });
        onComplete?.({ blob, meta, elapsedMs });
      }
    };
  }

  close() {
    this.dataChannel?.close();
    this.pc?.close();
  }
}
