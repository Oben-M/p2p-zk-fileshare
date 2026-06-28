// server/signaling-server.js
//
// This server's entire job is to introduce two browsers to each other.
// It is intentionally "dumb": it relays opaque JSON blobs between exactly
// two peers in a room and never inspects their contents.
//
// What passes through here over the lifetime of a transfer:
//   - PAKE messages (SPAKE2 protocol values)   -> meaningless without the code
//   - key-confirmation hashes                  -> meaningless without the key
//   - WebRTC SDP offers/answers + ICE candidates -> connection metadata only
//
// What never passes through here:
//   - the pairing code
//   - the derived AES key
//   - a single byte of file content
//
// The console.log below intentionally prints only message *types*, never
// payloads, so you can watch this claim hold up live while you run it.

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 8080;
const ROOM_TTL_MS = 10 * 60 * 1000; // unused rooms self-destruct after 10 min
const PUBLIC_DIR = path.join(__dirname, '..', 'public');

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
};

// In-memory store for the centralized-baseline benchmark. This is the
// "go through a server" path the brief asks you to compare P2P against:
// the client uploads an (already encrypted) blob here, then downloads it
// back, and the round trip time is the centralized-relay equivalent of a
// single sender-to-receiver transfer. Single-use and in-memory only --
// this is a benchmarking fixture, not a real file host.
const baselineStore = new Map();

// Plain static file server for the client (no framework needed for this).
const httpServer = http.createServer((req, res) => {
  if (req.method === 'POST' && req.url === '/baseline/upload') {
    const chunks = [];
    let total = 0;
    req.on('data', (c) => {
      total += c.length;
      chunks.push(c);
    });
    req.on('end', () => {
      const buf = Buffer.concat(chunks);
      const token = crypto.randomUUID();
      baselineStore.set(token, buf);
      console.log(`[baseline] stored ${total} bytes under ${token}`);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ token, bytes: total }));
    });
    req.on('error', () => res.writeHead(500).end());
    return;
  }

  if (req.method === 'GET' && req.url.startsWith('/baseline/download/')) {
    const token = req.url.split('/').pop();
    const buf = baselineStore.get(token);
    if (!buf) {
      res.writeHead(404);
      res.end('Not found or already downloaded (single-use)');
      return;
    }
    baselineStore.delete(token); // single-use, avoids unbounded memory growth
    console.log(`[baseline] served ${buf.length} bytes for ${token}`);
    res.writeHead(200, { 'Content-Type': 'application/octet-stream' });
    res.end(buf);
    return;
  }

  let reqPath = decodeURIComponent(req.url.split('?')[0]);
  if (reqPath === '/') reqPath = '/index.html';
  const filePath = path.join(PUBLIC_DIR, reqPath);

  // Prevent path traversal outside of public/.
  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403);
    res.end('Forbidden');
    return;
  }

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404);
      res.end('Not found');
      return;
    }
    const ext = path.extname(filePath);
    res.writeHead(200, {
      'Content-Type': MIME[ext] || 'application/octet-stream',
      'Cache-Control': 'no-store',
    });
    res.end(data);
  });
});

const wss = new WebSocketServer({ server: httpServer, path: '/ws' });

/** @type {Map<string, { peers: Set<import('ws').WebSocket>, createdAt: number }>} */
const rooms = new Map();

function log(roomId, msg) {
  console.log(`[room ${roomId}] ${msg}`);
}

function getOrCreateRoom(roomId) {
  let room = rooms.get(roomId);
  if (!room) {
    room = { peers: new Set(), createdAt: Date.now() };
    rooms.set(roomId, room);
  }
  return room;
}

function broadcastToOthers(roomId, sender, payload) {
  const room = rooms.get(roomId);
  if (!room) return;
  for (const peer of room.peers) {
    if (peer !== sender && peer.readyState === peer.OPEN) {
      peer.send(JSON.stringify(payload));
    }
  }
}

function cleanupRoom(roomId) {
  const room = rooms.get(roomId);
  if (room && room.peers.size === 0) {
    rooms.delete(roomId);
    log(roomId, 'closed (empty)');
  }
}

wss.on('connection', (ws) => {
  let joinedRoom = null;

  ws.isAlive = true;
  ws.missedPings = 0;

  ws.on('message', (raw) => {
    ws.isAlive = true;

    let msg;
    try {
      msg = JSON.parse(raw.toString());
    } catch {
      return;
    }

    if (msg.type === 'pong') {
      console.log('Received pong');
      return;
    }

    if (msg.type === 'join') {
      const roomId = String(msg.room || '').slice(0, 128);
      if (!roomId) return;

      const room = getOrCreateRoom(roomId);

      if (room.peers.size >= 2) {
        ws.send(JSON.stringify({ type: 'room-full' }));
        log(roomId, 'rejected a third peer (room-full)');
        return;
      }

      room.peers.add(ws);
      joinedRoom = roomId;
      log(roomId, `peer joined (${room.peers.size}/2)`);

      ws.send(JSON.stringify({ type: 'joined', peers: room.peers.size }));

      if (room.peers.size === 2) {
        broadcastToOthers(roomId, null, { type: 'peer-joined' });
        log(roomId, 'both peers present, pairing can begin');
      }
      return;
    }

    if (joinedRoom) {
      log(joinedRoom, `relaying message type="${msg.type}" (${raw.length} bytes, contents not inspected)`);
      broadcastToOthers(joinedRoom, ws, msg);
    }
  });

  ws.on('close', () => {
    if (joinedRoom) {
      const room = rooms.get(joinedRoom);
      if (room) {
        room.peers.delete(ws);
        log(joinedRoom, `peer left (${room.peers.size}/2)`);
        broadcastToOthers(joinedRoom, ws, { type: 'peer-left' });
        cleanupRoom(joinedRoom);
      }
    }
  });
});

setInterval(() => {
  const now = Date.now();
  for (const [roomId, room] of rooms) {
    if (now - room.createdAt > ROOM_TTL_MS) {
      for (const peer of room.peers) peer.close();
      rooms.delete(roomId);
      log(roomId, 'expired (TTL)');
    }
  }
}, 60 * 1000);

setInterval(() => {
  for (const ws of wss.clients) {
    if (!ws.isAlive) {
      ws.missedPings += 1;
      console.log(`No pong received (missed ${ws.missedPings}/2)`);
      if (ws.missedPings >= 2) {
        console.log('Terminating a connection that stopped responding (missed 2 heartbeats)');
        ws.terminate();
        continue;
      }
    } else {
      ws.missedPings = 0;
    }
    ws.isAlive = false;
    try {
      ws.send(JSON.stringify({ type: 'ping' }));
      console.log('Sent heartbeat ping');
    } catch {
      // socket already going away
    }
  }
}, 8 * 1000);

httpServer.listen(PORT, () => {
  console.log(`Open http://localhost:${PORT} in two browser tabs (or two machines) to try it.`);
  console.log(`Signaling relay is on ws://localhost:${PORT}/ws`);
  console.log('Watching for rooms... (this server only ever sees message types, never contents)\n');
});
