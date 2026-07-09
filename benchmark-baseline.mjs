// benchmark-baseline.mjs
//
// Produces REAL measured numbers for the "centralized baseline" comparison
// in Chapter 4 (Presentation and interpretation of results). This talks to
// the /baseline/upload and /baseline/download endpoints already built into
// your own signaling-server.js — it does not touch WebRTC/P2P at all, so it
// can run headlessly with no browser.
//
// HOW TO RUN:
//   1. In one terminal:  npm start          (starts signaling-server.js on :8080)
//   2. In another terminal, from the project root:
//        node benchmark-baseline.mjs
//   3. Copy the printed markdown table straight into Chapter 4, Section 4
//      ("Presentation and interpretation of results").
//
// It generates temporary random test files of 10 MB, 100 MB, and 1 GB,
// uploads and downloads each THREE times against the baseline endpoint,
// and reports min/mean/max so you can show consistency, not just one run.
//
// Adjust BASE_URL / RUNS_PER_SIZE below if needed.

import { unlinkSync, readFileSync, openSync, writeSync, closeSync } from 'node:fs';
import { randomBytes } from 'node:crypto';

const BASE_URL = process.env.BASELINE_URL || 'http://localhost:8080';
const RUNS_PER_SIZE = 3;
const SIZES_MB = [10, 100, 1000]; // 10 MB, 100 MB, 1 GB

function formatThroughput(bytes, ms) {
  const mbps = (bytes / (1024 * 1024)) / (ms / 1000);
  return `${mbps.toFixed(2)} MB/s`;
}

function makeTestFile(sizeMb, path) {
  // Random bytes so the encryption step in the real app can't trivially
  // compress/deduplicate them — matches worst-case, representative content.
  const size = sizeMb * 1024 * 1024;
  const CHUNK = 8 * 1024 * 1024;
  const fd = openSync(path, 'w');
  let written = 0;
  while (written < size) {
    const n = Math.min(CHUNK, size - written);
    writeSync(fd, randomBytes(n));
    written += n;
  }
  closeSync(fd);
}

async function runOnce(filePath, fileSizeBytes) {
  // Stream the file instead of reading it fully into memory — a readFileSync
  // on a 1 GB file can use well over 1 GB of RAM once Node/fetch internals
  // copy the buffer, which is enough to freeze a memory-constrained machine
  // (e.g. a Chromebook's Linux container). Streaming keeps memory flat
  // regardless of file size.
  const { createReadStream } = await import('node:fs');

  const t0 = performance.now();
  const upResp = await fetch(`${BASE_URL}/baseline/upload`, {
    method: 'POST',
    body: createReadStream(filePath),
    duplex: 'half',
    headers: { 'Content-Length': String(fileSizeBytes) },
  });
  if (!upResp.ok) throw new Error(`upload failed: HTTP ${upResp.status}`);
  const { token } = await upResp.json();
  const uploadMs = performance.now() - t0;

  const t1 = performance.now();
  const downResp = await fetch(`${BASE_URL}/baseline/download/${token}`);
  if (!downResp.ok) throw new Error(`download failed: HTTP ${downResp.status}`);
  // Drain the response body without buffering it all at once.
  let received = 0;
  for await (const chunk of downResp.body) received += chunk.length;
  const downloadMs = performance.now() - t1;

  return { uploadMs, downloadMs, totalMs: uploadMs + downloadMs, bytes: received };
}

function stats(nums) {
  const min = Math.min(...nums);
  const max = Math.max(...nums);
  const mean = nums.reduce((a, b) => a + b, 0) / nums.length;
  return { min, mean, max };
}

async function main() {
  console.log(`Benchmarking centralized baseline against ${BASE_URL}`);
  console.log(`(${RUNS_PER_SIZE} runs per file size — this can take a while for 1 GB)\n`);

  const rows = [];

  for (const sizeMb of SIZES_MB) {
    const path = `/tmp/bench-${sizeMb}mb.bin`;
    process.stdout.write(`Generating ${sizeMb} MB test file... `);
    makeTestFile(sizeMb, path);
    console.log('done.');

    const totals = [];
    const uploads = [];
    const downloads = [];

    for (let i = 1; i <= RUNS_PER_SIZE; i++) {
      process.stdout.write(`  [${sizeMb} MB] run ${i}/${RUNS_PER_SIZE}... `);
      try {
        const fileSizeBytes = sizeMb * 1024 * 1024;
        const { uploadMs, downloadMs, totalMs, bytes } = await runOnce(path, fileSizeBytes);
        totals.push(totalMs);
        uploads.push(uploadMs);
        downloads.push(downloadMs);
        console.log(`${(totalMs / 1000).toFixed(2)}s total (${formatThroughput(bytes, totalMs)})`);
      } catch (err) {
        console.log(`FAILED: ${err.message}`);
      }
    }

    unlinkSync(path);

    if (totals.length > 0) {
      const t = stats(totals);
      const bytesForThroughput = sizeMb * 1024 * 1024;
      rows.push({
        sizeMb,
        min: t.min,
        mean: t.mean,
        max: t.max,
        throughput: formatThroughput(bytesForThroughput, t.mean),
      });
    }
    console.log('');
  }

  console.log('\n=== Markdown table — paste into Chapter 4 ===\n');
  console.log('| File size | Min time | Mean time | Max time | Mean throughput |');
  console.log('|---|---|---|---|---|');
  for (const r of rows) {
    console.log(
      `| ${r.sizeMb} MB | ${(r.min / 1000).toFixed(2)}s | ${(r.mean / 1000).toFixed(2)}s | ${(r.max / 1000).toFixed(2)}s | ${r.throughput} |`
    );
  }
  console.log('\n(Values are the centralized-baseline column of Table 4.x — the P2P column comes from BENCHMARK_CHECKLIST.md, section 2.)');
}

main().catch((err) => {
  console.error('Benchmark script failed:', err);
  process.exit(1);
});
