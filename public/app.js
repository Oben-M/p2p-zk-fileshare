// public/app.js
import { Spake2Party, generatePairingCode } from './spake2.js';
import { WebRTCTransfer } from './webrtc-transfer.js';
import { importAesKey, randomSalt4, CHUNK_SIZE, makeIv, encryptChunk } from './crypto-utils.js';

// ---------- DOM ----------
const $ = (id) => document.getElementById(id);
const logEl = $('log');

function log(line, isErr = false) {
  const el = document.createElement('div');
  if (isErr) el.className = 'err';
  el.textContent = `${new Date().toLocaleTimeString()}  ${line}`;
  logEl.appendChild(el);
  logEl.scrollTop = logEl.scrollHeight;
  console.log(line);
}

// Anything that throws and isn't caught locally still ends up visible here,
// instead of silently dying in the devtools console (which you often can't
// even reach on a phone mid-test).
window.addEventListener('error', (e) => log(`Uncaught error: ${e.message}`, true));
window.addEventListener('unhandledrejection', (e) => log(`Unhandled error: ${e.reason?.message || e.reason}`, true));

// The single most common silent-failure cause we've hit: the page loaded
// over plain HTTP on something other than localhost, so crypto.subtle
// doesn't exist and every pairing attempt fails the moment it's touched.
if (!window.isSecureContext || !window.crypto?.subtle) {
  log(`Not a secure context (${location.protocol}//${location.host}) -- crypto.subtle is unavailable here. Use HTTPS or localhost.`, true);
}

function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`;
  return `${(n / 1024 ** 3).toFixed(2)} GB`;
}

function formatThroughput(bytes, ms) {
  const mbps = bytes / (ms / 1000) / (1024 * 1024);
  return `${mbps.toFixed(2)} MB/s`;
}

function getIceServers() {
  const servers = [
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'stun:stun1.l.google.com:19302' },
  ];
  const turnUrl = $('turnUrl').value.trim();
  if (turnUrl) {
    servers.push({
      urls: turnUrl,
      username: $('turnUser').value.trim(),
      credential: $('turnPass').value.trim(),
    });
    log(`Using custom TURN server: ${turnUrl}`);
  } else {
    log('No TURN server configured -- fine for same-machine testing, required for real NATs.');
  }
  return servers;
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

// ---------- Shared pairing + transport state ----------
let ws = null;
let role = null; // 'A' (creator/sender) or 'B' (joiner/receiver)
let spake = null;
let transfer = null;
let aesKey = null;
let salt4 = null;
let pendingSignals = [];
let pairingComplete = false;

function setWaveState(state) {
  document.querySelectorAll('#createWave, #joinWave').forEach((el) => {
    el.classList.remove('is-pairing', 'is-synced');
    if (state === 'pairing') el.classList.add('is-pairing');
    if (state === 'synced') el.classList.add('is-synced');
  });
}

function wsSend(obj) {
  ws.send(JSON.stringify(obj));
}

function connectSignaling(roomId) {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  ws = new WebSocket(`${proto}//${location.host}/ws`);

  ws.onopen = () => {
    log(`Signaling connected, joining room ${roomId}`);
    wsSend({ type: 'join', room: roomId });
  };

  ws.onclose = () => {
    if (pairingComplete) {
      log('Signaling connection closed (expected -- pairing already finished, file transfer runs P2P from here).');
    } else {
      log('Signaling connection closed before pairing finished. If you were mid-way through entering the code, the connection likely sat idle too long and a proxy/tunnel dropped it -- refresh both sides and try again quickly.', true);
    }
  };
  ws.onerror = () => log('Signaling connection error -- see browser devtools console for details.', true);

  ws.onmessage = async (event) => {
    let msg;
    try {
      msg = JSON.parse(event.data);
      await handleSignalingMessage(msg);
    } catch (err) {
      log(`Error handling "${msg?.type ?? 'unknown'}" message: ${err.message || err}`, true);
      console.error(err);
    }
  };
}

async function handleSignalingMessage(msg) {
  switch (msg.type) {
      case 'ping':
        wsSend({ type: 'pong' });
        break;

      case 'joined':
        log(`Joined room (${msg.peers}/2 peers present)`);
        break;

      case 'room-full':
        log('Room already has two peers -- this code was already used.', true);
        break;

      case 'peer-joined':
        log('Recipient/sender is here. Starting zero-knowledge pairing (SPAKE2)...');
        setWaveState('pairing');
        await beginPairing();
        break;

      case 'peer-left':
        log('The other side disconnected.', true);
        break;

      case 'pake': {
        log('Received peer PAKE message, deriving shared key...');
        const t0 = performance.now();
        const { confirmTagHex } = await spake.finish(msg.value);
        const deriveMs = performance.now() - t0;
        log(`SPAKE2 key derivation + confirmation (finish): ${deriveMs.toFixed(2)}ms`);
        const out = { type: 'confirm', value: confirmTagHex };
        if (role === 'A') {
          salt4 = randomSalt4();
          out.salt = bytesToHex(salt4);
        }
        wsSend(out);
        break;
      }

      case 'confirm': {
        const ok = await spake.verifyPeerConfirmation(msg.value);
        if (!ok) {
          log('Pairing FAILED -- the two sides used different codes. Check for a typo and try again.', true);
          return;
        }
        log('Pairing verified: both sides proved knowledge of the same code without ever sending it. Zero-knowledge property holds.');
        setWaveState('synced');
        pairingComplete = true;
        if (role === 'B' && msg.salt) salt4 = hexToBytes(msg.salt);
        aesKey = await importAesKey(spake.sessionKey);
        await startWebRtc();
        break;
      }

      case 'sdp-offer':
      case 'sdp-answer':
      case 'ice-candidate':
        if (transfer) await transfer.handleSignal(msg);
        else pendingSignals.push(msg);
        break;
  }
}

async function beginPairing() {
  spake = new Spake2Party(role);
  const password = role === 'A' ? createdPassword : enteredPassword;
  const t0 = performance.now();
  const myMessage = await spake.start(password);
  const genMs = performance.now() - t0;
  log(`SPAKE2 proof generation (start): ${genMs.toFixed(2)}ms`);
  wsSend({ type: 'pake', value: myMessage });
}

async function startWebRtc() {
  transfer = new WebRTCTransfer(role, wsSend, log);
  const relayOnly = $('forceRelay').checked;
  const connected = transfer.connect(getIceServers(), { relayOnly });
  for (const m of pendingSignals) await transfer.handleSignal(m);
  pendingSignals = [];
  await connected;

  if (role === 'A') {
    $('sendControls').classList.remove('hidden');
    $('waitingForPeer').classList.add('hidden');
    $('btnSend').disabled = false;
    log('Direct encrypted channel ready. Pick a file and send.');
  } else {
    $('receiveStatus').textContent = 'Connected. Waiting for the file...';
    $('receiveStatus').classList.remove('hidden');
    transfer.setupReceiver(aesKey, salt4, {
      onMeta: (meta) => {
        log(`Incoming file: ${meta.name} (${formatBytes(meta.size)})`);
        $('receiveStatus').textContent = `Receiving ${meta.name}...`;
      },
      onProgress: ({ received, total }) => {
        $('receiveProgressFill').style.width = `${Math.min(100, (received / total) * 100)}%`;
        $('receiveStats').textContent = `${formatBytes(received)} / ${formatBytes(total)}`;
      },
      onComplete: ({ blob, meta, elapsedMs }) => {
        const url = URL.createObjectURL(blob);
        const a = $('downloadLink');
        a.href = url;
        a.download = meta.name;
        a.textContent = `Download ${meta.name}`;
        a.classList.remove('hidden');
        $('receiveStatus').textContent = 'Transfer complete and verified (AES-GCM auth tag checked on every chunk).';
        $('receiveStats').textContent =
          `${formatBytes(meta.size)} in ${(elapsedMs / 1000).toFixed(2)}s -- ${formatThroughput(meta.size, elapsedMs)}`;
        log(`Transfer complete: ${formatBytes(meta.size)} in ${(elapsedMs / 1000).toFixed(2)}s (${formatThroughput(meta.size, elapsedMs)})`);
      },
    });
  }
}

// ---------- UI: create/send flow ----------
let createdPassword = null;
let enteredPassword = null;

$('btnCreate').addEventListener('click', () => {
  role = 'A';
  $('hero').classList.add('hidden');
  $('createPanel').classList.remove('hidden');

  const roomId = String(crypto.getRandomValues(new Uint32Array(1))[0] % 100000).padStart(5, '0');
  createdPassword = generatePairingCode();
  const fullCode = `${roomId}#${createdPassword}`;
  $('codeDisplay').textContent = fullCode;
  log(`Generated room ${roomId} (not secret, just routing) and a separate pairing code (secret, never sent to the server).`);

  connectSignaling(roomId);
});

$('btnSend').addEventListener('click', async () => {
  const file = $('filePicker').files[0];
  if (!file) {
    log('Pick a file first.', true);
    return;
  }
  $('btnSend').disabled = true;
  log(`Sending ${file.name} (${formatBytes(file.size)})...`);

  const { elapsedMs, bytes } = await transfer.sendFile(file, aesKey, salt4, {
    onProgress: ({ sent, total }) => {
      $('sendProgressFill').style.width = `${Math.min(100, (sent / total) * 100)}%`;
      $('sendStats').textContent = `${formatBytes(sent)} / ${formatBytes(total)}`;
    },
  });

  $('sendStats').textContent = `Done: ${formatBytes(bytes)} in ${(elapsedMs / 1000).toFixed(2)}s -- ${formatThroughput(bytes, elapsedMs)}`;
  log(`Transfer complete: ${formatBytes(bytes)} in ${(elapsedMs / 1000).toFixed(2)}s (${formatThroughput(bytes, elapsedMs)})`);
});

// ---------- Centralized baseline benchmark ----------
// Encrypts the file with the exact same AES-256-GCM scheme as the P2P
// path (so encryption overhead isn't what's being measured), then
// uploads it to this server and immediately downloads it back. That
// upload+download round trip is the centralized-relay equivalent of one
// sender-to-receiver transfer -- the number to set against the P2P
// throughput you already have.
async function runCentralizedBaseline(file) {
  const keyBytes = crypto.getRandomValues(new Uint8Array(32));
  const baselineKey = await importAesKey(keyBytes);
  const baselineSalt = randomSalt4();

  const totalChunks = Math.ceil(file.size / CHUNK_SIZE) || 1;
  const parts = [];
  for (let i = 0; i < totalChunks; i++) {
    const start = i * CHUNK_SIZE;
    const buf = new Uint8Array(await file.slice(start, start + CHUNK_SIZE).arrayBuffer());
    const iv = makeIv(baselineSalt, i);
    const ct = await encryptChunk(baselineKey, buf, iv);
    const frame = new Uint8Array(4 + ct.length);
    new DataView(frame.buffer).setUint32(0, i, false);
    frame.set(ct, 4);
    parts.push(frame);
  }
  const encryptedBlob = new Blob(parts);

  const t0 = performance.now();
  const uploadResp = await fetch('/baseline/upload', { method: 'POST', body: encryptedBlob });
  const { token } = await uploadResp.json();
  const uploadMs = performance.now() - t0;

  const t1 = performance.now();
  const downloadResp = await fetch(`/baseline/download/${token}`);
  await downloadResp.arrayBuffer();
  const downloadMs = performance.now() - t1;

  return { uploadMs, downloadMs, totalMs: uploadMs + downloadMs, bytes: file.size };
}

$('btnBaseline').addEventListener('click', async () => {
  const file = $('baselineFilePicker').files[0];
  if (!file) {
    log('Pick a file for the baseline test first.', true);
    return;
  }
  $('btnBaseline').disabled = true;
  log(`Running centralized baseline for ${file.name} (${formatBytes(file.size)})...`);
  try {
    const { uploadMs, downloadMs, totalMs, bytes } = await runCentralizedBaseline(file);
    $('baselineStats').textContent =
      `Upload: ${(uploadMs / 1000).toFixed(2)}s, Download: ${(downloadMs / 1000).toFixed(2)}s, ` +
      `Total: ${(totalMs / 1000).toFixed(2)}s -- ${formatThroughput(bytes, totalMs)}`;
    log(`Centralized baseline complete: ${formatBytes(bytes)} via upload+download in ${(totalMs / 1000).toFixed(2)}s (${formatThroughput(bytes, totalMs)})`);
  } catch (err) {
    log(`Centralized baseline failed: ${err.message}`, true);
  } finally {
    $('btnBaseline').disabled = false;
  }
});

// ---------- UI: join/receive flow ----------
$('btnJoin').addEventListener('click', () => {
  role = 'B';
  $('hero').classList.add('hidden');
  $('joinPanel').classList.remove('hidden');
});

$('btnJoinSubmit').addEventListener('click', () => {
  const full = $('codeInput').value.trim();
  const sep = full.indexOf('#');
  if (sep < 0) {
    log('Code should look like 58213#123-456-789 (room # password).', true);
    return;
  }
  const roomId = full.slice(0, sep);
  enteredPassword = full.slice(sep + 1);
  $('btnJoinSubmit').disabled = true;
  $('codeInput').disabled = true;
  connectSignaling(roomId);
});
