# SecureShare — Chapter 4 Results Checklist

Everything here is real data your reader can trust, collected in about
15–20 minutes. Each section says exactly what to do and where the number
comes from in the app you already built — nothing extra to install.

---

## 1. Centralized baseline (10 MB / 100 MB / 1 GB)

Already automated. From the project root:

```
npm start
```

In a second terminal:

```
node benchmark-baseline.mjs
```

It prints a markdown table at the end — paste it directly into Chapter 4,
Section 4 ("Presentation and interpretation of results"). This is your
"centralized transfer baseline" column.

---

## 2. P2P (WebRTC) transfer timing — 10 MB / 100 MB / 1 GB

The app already times and logs every real transfer, so you just need to
run three real transfers and copy the numbers it already shows you.

1. Open SecureShare in **two browser tabs** (or two devices on the same
   network, or over your Cloudflare tunnel for a true long-distance test).
2. Tab A: **Get started → Send a file**. Tab B: **Get started → Receive a
   file**, enter the code (or scan the QR).
3. Once paired, drag a **10 MB** file into the dropzone on either tab and
   send it.
4. Go to the **History** page — it will show a row like:
   `SENT  filename.bin   10.0 MB · 1.84s · 5.43 MB/s · 10:32:15 AM`
5. Repeat for a **100 MB** file, then a **1 GB** file (you already have
   `test-10mb.bin` in the project root — create larger ones for the other
   two sizes, e.g. on macOS/Linux: `dd if=/dev/urandom of=test-100mb.bin
   bs=1M count=100` and `count=1000` for the 1 GB file).
6. Copy the three History rows into your own table next to the
   centralized-baseline numbers from Section 1. This side-by-side table
   is exactly what H4 (per-megabyte throughput comparison) in Chapter 1
   asks you to test.

**Tip:** do this once on the same WiFi network, and once with each tab on
a *different* network (e.g. one on WiFi, one on mobile data / your
Cloudflare tunnel) — you'll want both for Section 4 below anyway, and it
shows the throughput cost of a TURN relay if one is used.

---

## 3. ZKP (SPAKE2) pairing computation time

This is already instrumented — it's just printed to the browser's
DevTools console rather than the visible UI, so it doesn't clutter the
interface during normal use.

1. Open DevTools (F12 or Cmd+Opt+I) → **Console** tab, on the **sender's**
   browser tab, before pairing.
2. Start a pairing (Get started → Send a file). Watch the console for a
   line like:
   `[debug] SPAKE2 start — EC (P-256), 4.32ms`
3. When the receiver joins and pairing completes, watch for:
   `[debug] Key derivation: 3.87ms`
4. Repeat the full pairing flow **10 times** for the EC variant (default)
   and **10 times** for the finite-field variant (switch the dropdown on
   the home page to "Finite-field (2048-bit)" before clicking Get
   started).
5. Record all 20 numbers, then compute min / mean / max for each variant.
   This is your evidence for H2 (the <2 second threshold stated in
   Chapter 1) — in practice both variants typically complete in single-
   digit milliseconds since this is local computation, not network time,
   but report your own real numbers.

A simple table:

| Variant | Min | Mean | Max |
|---|---|---|---|
| EC (P-256) | | | |
| Finite-field (2048-bit) | | | |

---

## 4. NAT traversal matrix

The app already logs exactly which connection type was used, via a line
in the Activity Log that reads:

```
Connected via <TYPE> (local=..., remote=...)
```

where `<TYPE>` is one of: **direct (same network)**, **STUN (direct
across NAT)**, or **TURN relay**.

Test and record this line for each of the three rows below:

| Test condition | How to set it up | Logged result |
|---|---|---|
| Same network | Both tabs/devices on the same WiFi | |
| Different networks | One on WiFi, one on mobile data (or your Cloudflare tunnel from a remote device) | |
| Forced relay | Go to the **Testing** page, check "Force relay-only", then pair and transfer | |

This table is your direct evidence for H3 and for the "Resolution of
Problem 3" claim already written in Chapter 3.

---

## 5. Screenshots to capture

Take these with the app running normally (not DevTools open) — they go
directly into Chapter 4, Section 4, next to the explanation of each step:

1. **Home page** — hero + "Get started" button
2. **Role picker** — Send a file / Receive a file
3. **Sender waiting screen** — pairing code + QR code visible
4. **Receiver entry screen** — code input / QR scan option
5. **Connected panel** — the green "Connected — end-to-end encrypted"
   state with the drag-and-drop zone
6. **A transfer in progress** — progress bar mid-fill
7. **Transfer History page** — after at least 2–3 completed transfers
8. **Testing page** — TURN config + benchmark section
9. **Activity log** showing a `Connected via TURN relay (...)` line
   (from the forced-relay test in Section 4 above) — this one screenshot
   alone is strong evidence for your NAT traversal claims

---

Once you have the two tables (baseline+P2P throughput, ZKP timing), the
NAT matrix, and the 9 screenshots, send them back and I'll drop them
straight into the placeholders in Chapter 4.
