# p2p-zk-fileshare

Accountless, end-to-end encrypted, peer-to-peer file sharing. No usernames,
no passwords, no database. Two people share a one-time code; the file
travels directly between their browsers over WebRTC, encrypted with a key
neither the signaling server nor anyone watching the wire ever sees.

## Run it

```bash
npm install
npm start
```

Open `http://localhost:8080` in two browser tabs (or two machines on the
same network). In one tab click **Send a file**, in the other click
**Receive a file** and paste in the code shown by the sender.

Watch the terminal running `npm start` while you do this -- it logs every
message it relays, by type only, never by content. That's the "server
never sees credentials" claim, made visible.

## What's actually happening, step by step

1. **Pairing code, not a password.** The sender gets a code like
   `58213#123-456-789`. The part before `#` is a room ID -- just a
   rendezvous point, sent to the server so it knows which two browsers to
   introduce. It is *not secret* and doesn't need to be. The part after
   `#` is the actual pairing secret and is **never sent to the server**.

   This split matters: if the room ID were derived from the password
   (e.g. `room = hash(password)`), anyone who saw the room ID could brute
   -force a 9-digit password offline in well under a second. Keeping them
   independent is what makes the short, human-shareable code safe.

2. **SPAKE2 (`public/spake2.js`).** Both browsers run a password-
   authenticated key exchange over a finite-field Diffie-Hellman group
   (RFC 3526's 2048-bit MODP group). Each side sends one blinded protocol
   message, derives a 256-bit session key, and exchanges a confirmation
   hash. If the codes matched, the keys match and confirmation succeeds.
   If not, it fails cleanly -- no fallback to "well, decrypt it anyway."

   This is the zero-knowledge proof of password knowledge: the code
   itself is never transmitted in any form, and a recorded transcript
   can't be brute-forced offline (see the comments in `spake2.js` for
   exactly why).

3. **WebRTC handshake (`public/webrtc-transfer.js`).** Once pairing
   succeeds, the two browsers exchange an SDP offer/answer and ICE
   candidates *through the same signaling server*, but this is just
   connection metadata (IP/port candidates) -- not file content. The log
   panel in the UI shows each ICE candidate's type as it's gathered:
   `host` (local network), `srflx` (found via STUN), or `relay` (via
   TURN). On a single machine you'll only ever see `host`. To actually
   exercise STUN/TURN, test across two separate networks (e.g. your
   laptop + a phone hotspot) -- see "Testing NAT traversal" below.

4. **Encrypted transfer.** The file is read and encrypted in 64 KB
   chunks (never loaded into memory all at once), AES-256-GCM, with a
   unique nonce per chunk derived from a per-session random salt + chunk
   counter (reusing a GCM nonce under one key would be a real
   vulnerability -- this avoids it by construction). The sender respects
   `RTCDataChannel.bufferedAmount` so a 1 GB file doesn't overrun the
   channel's internal buffer.

## Testing NAT traversal (the part that fails silently without a plan)

On `localhost`, every ICE candidate will be type `host` and you'll never
touch STUN or TURN. To actually test this:

- **STUN only:** run the sender and receiver on two different networks
  (e.g. home WiFi + phone hotspot). The default config already includes
  Google's public STUN servers. Watch the log panel for `srflx`
  candidates.
- **TURN (the fallback that matters):** STUN fails behind symmetric NATs
  and many corporate/mobile networks -- exactly the "fails silently"
  case from the brief. To test it, run your own TURN server:

  ```bash
  sudo apt install coturn
  # minimal /etc/turnserver.conf:
  #   listening-port=3478
  #   fingerprint
  #   lt-cred-mech
  #   user=demo:demo-password
  #   realm=yourdomain.example
  ```

  Then in the app's "Advanced" panel, fill in:
  - TURN URL: `turn:<your-server-ip>:3478`
  - Username: `demo`
  - Credential: `demo-password`

  To force a relay candidate even on a friendly network (for a clean
  demo), temporarily set `iceTransportPolicy: 'relay'` in
  `webrtc-transfer.js`'s `RTCPeerConnection` config -- that's a quick way
  to *prove* TURN works without needing two genuinely hostile networks.

## Benchmarking (what the assignment asks for, not yet automated here)

This build gives you the live numbers in the UI and log panel (bytes
transferred, elapsed time, MB/s) for any file you drag in -- that covers
the P2P side at 10 MB / 100 MB / 1 GB.

Still to add for the comparison the brief asks for:
- **Centralized baseline:** a trivial `POST` of the encrypted blob to an
  HTTP endpoint on the signaling server, timed the same way, for the
  same three file sizes. Worth keeping the encryption identical between
  both paths so the comparison isolates *transport*, not crypto overhead.
- **Proof generation overhead:** time `Spake2Party.start()` and
  `.finish()` directly (they're already isolated, easy to wrap in
  `performance.now()`), and report on whatever machine you're using as
  "mid-range" -- name the CPU in your write-up so it's reproducible.

## Honest limitations (worth stating yourself before a reviewer finds them)

- One-directional in this build: the room creator always sends, the
  joiner always receives. Bidirectional is a natural extension (just run
  two `WebRTCTransfer` flows, or interleave `sendFile`/`setupReceiver` on
  both sides).
- The SPAKE2 implementation is hand-written for transparency, not
  independently audited, and isn't constant-time. That's an appropriate
  level of rigor for demonstrating you understand and can implement the
  protocol; say so plainly if asked.
- File metadata (name, size, MIME type) is encrypted the same way as the
  file content, but the *room ID* is visible to the server -- by design,
  since it's not the secret.
- A leaked-but-unused pairing code can still be raced by an attacker who
  connects before the intended recipient; the room is single-use and
  short-lived (10 minutes), which limits but doesn't eliminate this --
  the same property real tools like Magic Wormhole accept.
