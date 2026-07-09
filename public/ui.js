// public/ui.js
//
// Presentation-layer only. This file never touches WebRTC, SPAKE2, or
// crypto logic in app.js — it only adds navigation, drag-and-drop, and a
// unified transfer history view by *observing* the DOM app.js already
// updates (the activity log). Safe to remove without breaking transfers.

(function () {
  const $ = (id) => document.getElementById(id);

  // ---------------- Nav / view switching ----------------
  const views = ['home', 'transfer', 'history', 'testing'];

  function switchView(name) {
    if (!views.includes(name)) return;
    views.forEach((v) => {
      const el = $(`view-${v}`);
      if (el) el.classList.toggle('hidden', v !== name);
    });
    document.querySelectorAll('.nav-link').forEach((btn) => {
      btn.classList.toggle('active', btn.dataset.view === name);
    });

    // If landing directly on Transfer without having clicked "Get started"
    // on the home view, make sure the role picker is reachable.
    if (name === 'transfer') {
      const anyVisible = ['modeScreen', 'roleScreen', 'createPanel', 'joinPanel', 'connectedPanel']
        .some((id) => {
          const el = $(id);
          return el && !el.classList.contains('hidden');
        });
      if (!anyVisible) {
        const roleScreen = $('roleScreen');
        if (roleScreen) roleScreen.classList.remove('hidden');
      }
    }
  }

  document.querySelectorAll('.nav-link[data-view]').forEach((btn) => {
    btn.addEventListener('click', () => switchView(btn.dataset.view));
  });

  document.querySelectorAll('[data-goto-view]').forEach((btn) => {
    btn.addEventListener('click', () => switchView(btn.dataset.gotoView));
  });

  // "Get started" also jumps the nav to the Transfer view.
  // (app.js has its own listener on the same button that shows roleScreen —
  // both listeners fire independently.)
  const btnStart = $('btnStart');
  if (btnStart) btnStart.addEventListener('click', () => switchView('transfer'));

  // ---------- Send queue (multi-file) ----------
  // Drives the EXISTING #btnSend click handler in app.js one file at a time —
  // it never duplicates or reimplements the send/transfer logic itself. We
  // just watch #btnSend's `disabled` attribute: when app.js's own handler
  // re-enables it (its `finally` block, after success or failure), we know
  // the previous file is done, so we load the next queued file and click
  // the button again, exactly as a user would.
  const queueListEl = $('sendQueueList');
  let sendQueue = []; // { file, status: 'queued' | 'sending' | 'done' | 'failed' }
  let queueActive = false;

  function renderQueue() {
    if (!queueListEl) return;
    if (sendQueue.length === 0) {
      queueListEl.innerHTML = '';
      return;
    }
    queueListEl.innerHTML = sendQueue
      .map(({ file, status }) => {
        const sizeKb = file.size / 1024;
        const sizeLabel = sizeKb < 1024 ? `${sizeKb.toFixed(1)} KB` : `${(sizeKb / 1024).toFixed(2)} MB`;
        const statusLabel = { queued: 'Queued', sending: 'Sending…', done: 'Sent', failed: 'Failed' }[status];
        const cls = { queued: '', sending: 'is-active', done: 'is-done', failed: 'is-failed' }[status];
        return `
          <div class="queue-item ${cls}">
            <span class="queue-name">${escapeHtml(file.name)} · ${sizeLabel}</span>
            <span class="queue-status">${statusLabel}</span>
          </div>`;
      })
      .join('');
  }

  function loadFileIntoPicker(file) {
    const dt = new DataTransfer();
    dt.items.add(file);
    filePicker.files = dt.files;
    showPickedFile(file);
  }

  function advanceQueue() {
    const next = sendQueue.find((item) => item.status === 'queued');
    if (!next) {
      queueActive = false;
      return;
    }
    queueActive = true;
    next.status = 'sending';
    renderQueue();
    loadFileIntoPicker(next.file);
    // Let app.js's own click handler take it from here.
    setTimeout(() => $('btnSend')?.click(), 150);
  }

  function enqueueFiles(fileList) {
    const files = Array.from(fileList || []);
    if (files.length === 0) return;
    files.forEach((file) => sendQueue.push({ file, status: 'queued' }));
    renderQueue();
    if (!queueActive) advanceQueue();
  }

  // Watch #btnSend's disabled attribute to know when app.js's send handler
  // has finished the file we just handed it.
  const btnSendEl = $('btnSend');
  if (btnSendEl) {
    const btnObserver = new MutationObserver(() => {
      if (!queueActive) return;
      const stillDisabled = btnSendEl.disabled;
      if (!stillDisabled) {
        const current = sendQueue.find((item) => item.status === 'sending');
        if (current) {
          current.status = 'done';
          renderQueue();
        }
        advanceQueue();
      }
    });
    btnObserver.observe(btnSendEl, { attributes: true, attributeFilter: ['disabled'] });
  }

  // ---------- Drag & drop (multi-file aware) ----------
  const dropzone = $('dropzone');
  const filePicker = $('filePicker');
  const dropzoneFilename = $('dropzoneFilename');

  function showPickedFile(file) {
    if (!file || !dropzoneFilename) return;
    const sizeKb = file.size / 1024;
    const sizeLabel = sizeKb < 1024 ? `${sizeKb.toFixed(1)} KB` : `${(sizeKb / 1024).toFixed(2)} MB`;
    dropzoneFilename.textContent = `${file.name} · ${sizeLabel}`;
  }

  if (dropzone && filePicker) {
    filePicker.addEventListener('change', () => enqueueFiles(filePicker.files));

    ['dragenter', 'dragover'].forEach((evt) => {
      dropzone.addEventListener(evt, (e) => {
        e.preventDefault();
        dropzone.classList.add('is-dragover');
      });
    });
    ['dragleave', 'drop'].forEach((evt) => {
      dropzone.addEventListener(evt, (e) => {
        e.preventDefault();
        dropzone.classList.remove('is-dragover');
      });
    });
    dropzone.addEventListener('drop', (e) => {
      enqueueFiles(e.dataTransfer?.files);
    });
  }
    

  // ---------------- Unified transfer history ----------------
  // app.js writes lines like:
  //   "Sent report.pdf — 2.1 MB in 0.42s (5.00 MB/s)"
  //   "Received report.pdf — 2.1 MB in 0.42s (5.00 MB/s)"
  // into #log (with a "HH:MM:SS  " time prefix). We parse those instead of
  // touching app.js's internals.
  const logEl = $('log');
  const historyListEl = $('unifiedHistoryList');
  const LINE_RE = /^(Sent|Received) (.+?) — (.+?) in ([\d.]+)s \((.+)\)$/;
  let entries = [];

  function renderUnifiedHistory() {
    if (!historyListEl) return;
    if (entries.length === 0) {
      historyListEl.innerHTML = '<div class="empty-state">No transfers yet this session — head to the Transfer tab to send or receive a file.</div>';
      return;
    }
    historyListEl.innerHTML = entries
      .map(({ direction, name, size, secs, throughput, time }) => `
        <div class="history-row">
          <div class="hr-left">
            <span class="history-direction ${direction.toLowerCase()}">${direction}</span>
            <span class="history-name">${escapeHtml(name)}</span>
          </div>
          <span class="history-meta">${size} · ${secs}s · ${throughput} · ${time}</span>
        </div>`)
      .join('');
  }

  function escapeHtml(str) {
    const d = document.createElement('div');
    d.textContent = str;
    return d.innerHTML;
  }

  function handleNewLogLine(text) {
    // format: "10:32:15 AM  Sent file.pdf — 2.1 MB in 0.42s (5.00 MB/s)"
    const sepIdx = text.indexOf('  ');
    if (sepIdx === -1) return;
    const time = text.slice(0, sepIdx);
    const rest = text.slice(sepIdx + 2);
    const m = rest.match(LINE_RE);
    if (!m) return;
    const [, direction, name, size, secs, throughput] = m;
    entries.unshift({ direction, name, size, secs, throughput, time });
    renderUnifiedHistory();
  }

  if (logEl) {
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mut) => {
        mut.addedNodes.forEach((node) => {
          if (node.nodeType === 1 && node.textContent) handleNewLogLine(node.textContent);
        });
      });
    });
    observer.observe(logEl, { childList: true });
  }

  renderUnifiedHistory();
})();
