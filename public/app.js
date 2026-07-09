// public/app.js
import { Spake2Party, generatePairingCode } from './spake2.js';
import { Spake2ECParty } from './spake2-ec.js';
import { WebRTCTransfer } from './webrtc-transfer.js';
import { importAesKey, randomSalt4, CHUNK_SIZE, makeIv, encryptChunk } from './crypto-utils.js';

const $ = (id) => document.getElementById(id);
const logEl = $('log');

// log() → on-screen panel + console. Only meaningful user-facing events.
function log(line, isErr = false) {
  const el = document.createElement('div');
  if (isErr) el.className = 'err';
  el.textContent = `${new Date().toLocaleTimeString()}  ${line}`;
  logEl.appendChild(el);
  logEl.scrollTop = logEl.scrollHeight;
  console.log(line);
}

// debug() → browser console only. Protocol internals, crypto values.
function debug(line) { console.log(`[debug] ${line}`); }

window.addEventListener('error', (e) => log(`Error: ${e.message}`, true));
window.addEventListener('unhandledrejection', (e) => log(`Error: ${e.reason?.message || e.reason}`, true));

if (!window.isSecureContext || !window.crypto?.subtle) {
  log('This page needs HTTPS or localhost to work. Check your connection.', true);
}

function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`;
  return `${(n / 1024 ** 3).toFixed(2)} GB`;
}

function formatThroughput(bytes, ms) {
  return `${(bytes / (ms / 1000) / (1024 * 1024)).toFixed(2)} MB/s`;
}

function getIceServers() {
  const servers = [
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'stun:stun1.l.google.com:19302' },
  ];
  const turnUrl = $('turnUrl').value.trim();
  if (turnUrl) {
    servers.push({ urls: turnUrl, username: $('turnUser').value.trim(), credential: $('turnPass').value.trim() });
    debug(`Using TURN: ${turnUrl}`);
  }
  return servers;
}

function hexToBytes(hex) {
  const b = new Uint8Array(hex.length / 2);
  for (let i = 0; i < b.length; i++) b[i] = parseInt(hex.substr(i * 2, 2), 16);
  return b;
}
function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ---------- state ----------
let ws = null, role = null, spake = null, transfer = null;
let aesKey = null, salt4 = null, pendingSignals = [];
let pairingComplete = false, pairingVariant = 'ff';
let receivedCount = 0;
let connectionMode = 'distance'; // 'distance' = tunnel/QR code, 'local' = same network

// ---------- download history ----------
const downloadHistory = [];
function addToHistory(blob, meta, elapsedMs) {
  const url = URL.createObjectURL(blob);
  downloadHistory.unshift({ url, name: meta.name, size: meta.size, elapsedMs });
  renderHistory();
  // Show badge if user is on Send tab
  if (!$('receivedTab') || $('receivedTab').classList.contains('hidden')) {
    receivedCount++;
    $('receivedBadge').textContent = receivedCount;
    $('receivedBadge').classList.remove('hidden');
  }
}
  renderHistory();

function renderHistory() {
  const el = $('downloadHistory');
  if (!el) return;
  el.innerHTML = '';
  if (downloadHistory.length === 0) {
    el.innerHTML = '<div class="hint" style="padding:0.5rem 0">No files received yet this session.</div>';
    return;
  }
  downloadHistory.forEach(({ url, name, size, elapsedMs }) => {
    const row = document.createElement('div');
    row.className = 'history-row';
    row.innerHTML = `<a href="${url}" download="${name}" class="history-link">${name}</a>
      <span class="history-meta">${formatBytes(size)} · ${(elapsedMs / 1000).toFixed(2)}s · ${formatThroughput(size, elapsedMs)}</span>`;
    el.appendChild(row);
  });
}

// ---------- wave state ----------
function setWaveState(state) {
  const captions = {
    pairing: 'Pairing in progress...',
    synced: 'Paired — encrypted channel ready',
  };
  ['createWave', 'joinWave', 'waitingWave'].forEach(id => {
    const el = $(id);
    if (!el) return;
    el.classList.remove('is-pairing', 'is-synced');
    if (state === 'pairing') el.classList.add('is-pairing');
    if (state === 'synced') el.classList.add('is-synced');
    const cap = el.querySelector('.wave-caption');
    if (cap && captions[state]) cap.textContent = captions[state];
  });
  const connCap = $('connectedWaveCaption');
  if (connCap && state === 'synced') connCap.textContent = captions.synced;
}

function wsSend(obj) { ws.send(JSON.stringify(obj)); }

function connectSignaling(roomId) {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  ws = new WebSocket(`${proto}//${location.host}/ws`);
  ws.onopen = () => { debug(`Signaling connected, room ${roomId}`); wsSend({ type: 'join', room: roomId }); };
  ws.onclose = () => {
    if (pairingComplete) debug('Signaling closed after pairing — normal.');
    else log('Connection dropped before pairing. Refresh both sides and try again.', true);
  };
  ws.onerror = () => log('Connection error — check your internet and try again.', true);
  ws.onmessage = async (event) => {
    let msg;
    try { msg = JSON.parse(event.data); await handleSignal(msg); }
    catch (err) { log(`Error: ${err.message}`, true); console.error(err); }
  };
}

async function handleSignal(msg) {
  switch (msg.type) {
    case 'ping': wsSend({ type: 'pong' }); break;
    case 'joined': debug(`Joined room (${msg.peers}/2)`); break;
    case 'room-full': log('This code has already been used — refresh both sides and generate a new one.', true); break;
    case 'peer-joined':
      log('Other device connected. Authenticating...');
      setWaveState('pairing');
      await beginPairing();
      break;
    case 'peer-left': log('The other device disconnected.', true); break;
    case 'pake': {
      const byteLen = msg.value.length / 2;
      const groupLabel = byteLen === 33 ? 'P-256 elliptic curve (33 bytes)' : `finite field (${byteLen} bytes)`;
      debug(`Received PAKE message — ${groupLabel}: ${msg.value.slice(0, 32)}...`);
      const t0 = performance.now();
      const { confirmTagHex } = await spake.finish(msg.value);
      debug(`Key derivation: ${(performance.now() - t0).toFixed(2)}ms`);
      const out = { type: 'confirm', value: confirmTagHex };
      if (role === 'A') { salt4 = randomSalt4(); out.salt = bytesToHex(salt4); }
      wsSend(out);
      break;
    }
    case 'confirm': {
      const ok = await spake.verifyPeerConfirmation(msg.value);
      if (!ok) { log('Pairing failed — wrong code. Try again.', true); return; }
      log('Authenticated. Connection is end-to-end encrypted.');
      setWaveState('synced');
      pairingComplete = true;
      if (role === 'B' && msg.salt) salt4 = hexToBytes(msg.salt);
      aesKey = await importAesKey(spake.sessionKey);
      debug(`Session key: ${bytesToHex(spake.sessionKey)}`);
      await startWebRtc();
      break;
    }
    case 'sdp-offer': case 'sdp-answer': case 'ice-candidate':
      if (transfer) await transfer.handleSignal(msg);
      else pendingSignals.push(msg);
      break;
  }
}

async function beginPairing() {
  spake = pairingVariant === 'ec' ? new Spake2ECParty(role) : new Spake2Party(role);
  const password = role === 'A' ? createdPassword : enteredPassword;
  const t0 = performance.now();
  const myMessage = await spake.start(password);
  const byteLen = myMessage.length / 2;
  const groupLabel = byteLen === 33 ? 'P-256 elliptic curve' : `finite field (${byteLen} bytes)`;
  debug(`SPAKE2 start — ${groupLabel}, ${(performance.now() - t0).toFixed(2)}ms`);
  debug(`My blinded value: ${myMessage}`);
  wsSend({ type: 'pake', value: myMessage });
}

async function startWebRtc() {
  transfer = new WebRTCTransfer(role, wsSend, log, debug);
  const relayOnly = $('forceRelay')?.checked || false;
  const connected = transfer.connect(getIceServers(), { relayOnly });
  for (const m of pendingSignals) await transfer.handleSignal(m);
  pendingSignals = [];
  await connected;

  // Both sides land on the same connected panel with Send + Received tabs.
  // The WebRTC offerer/answerer roles (A/B) stay for the handshake but
  // are invisible to the user from this point on.
  $('createPanel').classList.add('hidden');
  $('joinPanel').classList.add('hidden');
  $('connectedPanel').classList.remove('hidden');
  $('btnSend').disabled = false;

  // Both sides can send AND receive after pairing.
  transfer.setupReceiver(aesKey, salt4, {
    onMeta: (meta) => {
      log(`Receiving ${meta.name} (${formatBytes(meta.size)})...`);
    },
    onProgress: ({ received, total }) => {
      // Show progress in the received tab
      $('receiveProgressFill') && ($('receiveProgressFill').style.width = `${Math.min(100, (received / total) * 100)}%`);
    },
    onComplete: ({ blob, meta, elapsedMs }) => {
      addToHistory(blob, meta, elapsedMs);
      log(`Received ${meta.name} — ${formatBytes(meta.size)} in ${(elapsedMs / 1000).toFixed(2)}s (${formatThroughput(meta.size, elapsedMs)})`);
      // Switch to received tab and show badge
      switchTab('received');
    },
  });
}

// Tab switching
window.switchTab = function(tab) {
  $('sendTab').classList.toggle('hidden', tab !== 'send');
  $('receivedTab').classList.toggle('hidden', tab !== 'received');
  $('tabSend').classList.toggle('active', tab === 'send');
  $('tabReceived').classList.toggle('active', tab === 'received');
  if (tab === 'received') {
    receivedCount = 0;
    $('receivedBadge').textContent = '0';
    $('receivedBadge').classList.add('hidden');
  }
};

// ---------- mode selection flow ----------
let createdPassword = null, enteredPassword = null;

$('btnSend').addEventListener('click', async () => {
  const file = $('filePicker').files[0];
  if (!file) { log('Pick a file first.', true); return; }
  $('btnSend').disabled = true;
  $('sendProgressFill').style.width = '0%';
  log(`Sending ${file.name} (${formatBytes(file.size)})...`);
  try {
    const { elapsedMs, bytes } = await transfer.sendFile(file, aesKey, salt4, {
      onProgress: ({ sent, total }) => {
        $('sendProgressFill').style.width = `${Math.min(100, (sent / total) * 100)}%`;
        $('sendStats').textContent = `${formatBytes(sent)} / ${formatBytes(total)}`;
      },
    });
    $('sendStats').textContent = `Done — ${formatBytes(bytes)} in ${(elapsedMs / 1000).toFixed(2)}s (${formatThroughput(bytes, elapsedMs)})`;
    log(`Sent ${file.name} — ${formatBytes(bytes)} in ${(elapsedMs / 1000).toFixed(2)}s (${formatThroughput(bytes, elapsedMs)})`);
  } catch (err) {
    log(`Send failed: ${err.message}`, true);
  } finally {
    $('btnSend').disabled = false;
  }
});

// ---------- mode picker (replaces the old password/QR toggle) ----------
// "Local" = same network, devices discover each other via LAN IP
// "Distance" = different networks, pairing code shared as text or QR
$('btnModeLocal').addEventListener('click', () => {
  connectionMode = 'local';
  $('modeScreen').classList.add('hidden');
  $('roleScreen').classList.remove('hidden');
});

$('btnModeDistance').addEventListener('click', () => {
  connectionMode = 'distance';
  $('modeScreen').classList.add('hidden');
  $('roleScreen').classList.remove('hidden');
});

$('btnBecomeSender').addEventListener('click', () => {
  role = 'A';
  $('roleScreen').classList.add('hidden');
  $('createPanel').classList.remove('hidden');

  const roomId = String(crypto.getRandomValues(new Uint32Array(1))[0] % 100000).padStart(5, '0');
  createdPassword = generatePairingCode();
  pairingVariant = $('spakeVariant').value;
  const fullCode = `${roomId}#${pairingVariant}#${createdPassword}`;
  $('codeDisplay').textContent = fullCode;

  if (connectionMode === 'local') {
    $('codeSection').classList.add('hidden');
    $('qrSection').classList.add('hidden');
    $('localHint').classList.remove('hidden');
  } else {
    $('codeSection').classList.remove('hidden');
    try {
      if (typeof QRCode !== 'undefined') {
        $('qrSection').classList.remove('hidden');
        QRCode.toCanvas($('qrCanvas'), fullCode, { width: 220, margin: 1 }, (err) => {
          if (err) debug(`QR error: ${err.message}`);
        });
      }
    } catch (e) { debug(`QR error: ${e.message}`); }
  }

  connectSignaling(roomId);
});

$('btnBecomeReceiver').addEventListener('click', () => {
  role = 'B';
  $('roleScreen').classList.add('hidden');
  $('joinPanel').classList.remove('hidden');

  if (connectionMode === 'local') {
    $('scanSection').classList.add('hidden');
    $('codeInputSection').classList.remove('hidden');
    $('joinHint').textContent = 'Enter the code shown on the sender\'s screen.';
  } else {
    $('scanSection').classList.remove('hidden');
    $('codeInputSection').classList.remove('hidden');
    $('joinHint').textContent = 'Type the code or scan the QR shown on the sender\'s screen.';
  }
});

$('btnJoinSubmit').addEventListener('click', () => {
  const full = $('codeInput').value.trim().replace(/\s+/g, '');
  const parts = full.split('#');
  const variant = parts[1]?.toLowerCase();
  if (parts.length !== 3 || !['ff', 'ec'].includes(variant)) {
    log('Code should look like 58213#ff#123-456-789', true);
    return;
  }
  const [roomId, , password] = parts;
  pairingVariant = variant;
  enteredPassword = password;
  $('btnJoinSubmit').disabled = true;
  $('codeInput').disabled = true;
  connectSignaling(roomId);
});

// ---------- QR scanning ----------
let qrStream = null, qrAnimationFrame = null;

function stopQrScan() {
  if (qrAnimationFrame) cancelAnimationFrame(qrAnimationFrame);
  qrAnimationFrame = null;
  if (qrStream) { qrStream.getTracks().forEach(t => t.stop()); qrStream = null; }
  $('qrVideo').classList.add('hidden');
  $('qrScanStatus').classList.add('hidden');
}

$('btnScanQr').addEventListener('click', async () => {
  const video = $('qrVideo');
  try { qrStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: { ideal: 'environment' } } }); }
  catch (err) { log(`Camera access failed: ${err.message}`, true); return; }
  video.srcObject = qrStream;
  video.classList.remove('hidden');
  $('qrScanStatus').classList.remove('hidden');
  await video.play();
  const canvas = $('qrScanCanvas');
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  function tick() {
    if (video.readyState === video.HAVE_ENOUGH_DATA) {
      canvas.width = video.videoWidth; canvas.height = video.videoHeight;
      ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      if (typeof jsQR === 'undefined') { log('QR scanner unavailable — type the code instead.', true); stopQrScan(); return; }
      const code = jsQR(imageData.data, imageData.width, imageData.height);
      if (code?.data) { stopQrScan(); $('codeInput').value = code.data; log(`QR scanned.`); $('btnJoinSubmit').click(); return; }
    }
    qrAnimationFrame = requestAnimationFrame(tick);
  }
  qrAnimationFrame = requestAnimationFrame(tick);
});
$('btnCancelScan').addEventListener('click', stopQrScan);

// ---------- baseline benchmark ----------
async function runCentralizedBaseline(file) {
  const keyBytes = crypto.getRandomValues(new Uint8Array(32));
  const baselineKey = await importAesKey(keyBytes);
  const baselineSalt = randomSalt4();
  const parts = [];
  for (let i = 0; i < Math.ceil(file.size / CHUNK_SIZE) || 1; i++) {
    const buf = new Uint8Array(await file.slice(i * CHUNK_SIZE, (i + 1) * CHUNK_SIZE).arrayBuffer());
    const iv = makeIv(baselineSalt, i);
    const ct = await encryptChunk(baselineKey, buf, iv);
    const frame = new Uint8Array(4 + ct.length);
    new DataView(frame.buffer).setUint32(0, i, false);
    frame.set(ct, 4);
    parts.push(frame);
  }
  const encryptedBlob = new Blob(parts);
  const t0 = performance.now();
  const upResp = await fetch('/baseline/upload', { method: 'POST', body: encryptedBlob });
  const { token } = await upResp.json();
  const uploadMs = performance.now() - t0;
  const t1 = performance.now();
  const downResp = await fetch(`/baseline/download/${token}`);
  await downResp.arrayBuffer();
  const downloadMs = performance.now() - t1;
  return { uploadMs, downloadMs, totalMs: uploadMs + downloadMs, bytes: file.size };
}

$('btnBaseline').addEventListener('click', async () => {
  const file = $('baselineFilePicker').files[0];
  if (!file) { log('Pick a file for the baseline test first.', true); return; }
  $('btnBaseline').disabled = true;
  log(`Running centralized baseline for ${file.name} (${formatBytes(file.size)})...`);
  try {
    const { uploadMs, downloadMs, totalMs, bytes } = await runCentralizedBaseline(file);
    $('baselineStats').textContent = `Upload: ${(uploadMs / 1000).toFixed(2)}s · Download: ${(downloadMs / 1000).toFixed(2)}s · Total: ${(totalMs / 1000).toFixed(2)}s — ${formatThroughput(bytes, totalMs)}`;
    log(`Baseline complete: ${formatBytes(bytes)} in ${(totalMs / 1000).toFixed(2)}s (${formatThroughput(bytes, totalMs)})`);
  } catch (err) { log(`Baseline failed: ${err.message}`, true); }
  finally { $('btnBaseline').disabled = false; }
});
$('btnStart').addEventListener('click', () => {
  $('hero').classList.add('hidden');
  $('roleScreen').classList.remove('hidden');
});
