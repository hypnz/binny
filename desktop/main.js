// BINNY Desktop — Electron shell.
//
// The entire backend is the `binny --serve` binary (the same one the CLI uses).
// This process is only a shell: it starts binny as a loopback sidecar, waits for
// it to answer, and opens a window on it. Nothing here re-implements analysis.
//
// Finding the binary:
//   - BINNY_BIN env var, if set (dev: point it at your `go build` output); else
//   - a bundled binary at <resources>/bin/binny[.exe] (packaged app); else
//   - `binny` on PATH.
//
// Run in dev:  BINNY_BIN=/path/to/binny npm start

const { app, BrowserWindow, Menu, dialog, shell } = require('electron');
const { spawn } = require('child_process');
const http = require('http');
const net = require('net');
const path = require('path');
const fs = require('fs');

let sidecar = null;
let win = null;
let port = 0;
let serveDir = process.env.BINNY_DIR || '';

function binnyPath() {
  if (process.env.BINNY_BIN) return process.env.BINNY_BIN;
  const exe = process.platform === 'win32' ? 'binny.exe' : 'binny';
  const bundled = path.join(process.resourcesPath || '', 'bin', exe);
  if (fs.existsSync(bundled)) return bundled;
  return 'binny'; // from PATH
}

function freePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.on('error', reject);
    s.listen(0, '127.0.0.1', () => {
      const p = s.address().port;
      s.close(() => resolve(p));
    });
  });
}

function waitHealth(p, tries = 60) {
  return new Promise((resolve, reject) => {
    const tick = (n) => {
      const req = http.get({ host: '127.0.0.1', port: p, path: '/api/health', timeout: 500 }, (res) => {
        res.resume();
        if (res.statusCode === 200) return resolve();
        retry(n);
      });
      req.on('error', () => retry(n));
      req.on('timeout', () => { req.destroy(); retry(n); });
    };
    const retry = (n) => {
      if (n <= 0) return reject(new Error('binny --serve did not become healthy'));
      setTimeout(() => tick(n - 1), 150);
    };
    tick(tries);
  });
}

async function startSidecar() {
  if (sidecar) { try { sidecar.kill(); } catch (_) {} sidecar = null; }
  port = await freePort();
  const args = ['--serve', '--serve-addr', `127.0.0.1:${port}`];
  if (serveDir) args.push('--serve-dir', serveDir);
  sidecar = spawn(binnyPath(), args, { stdio: 'inherit' });
  sidecar.on('exit', (code) => {
    if (code && !app.isQuitting) {
      dialog.showErrorBox('BINNY', `binny --serve exited (code ${code}).`);
    }
  });
  await new Promise((resolve, reject) => {
    sidecar.once('error', reject);
    waitHealth(port).then(resolve, reject);
  });
}

async function createWindow() {
  win = new BrowserWindow({
    width: 1320, height: 860, minWidth: 900, minHeight: 600,
    backgroundColor: '#0d0f14', title: 'BINNY Desktop',
    webPreferences: { contextIsolation: true, nodeIntegration: false, preload: path.join(__dirname, 'preload.js') },
  });
  await win.loadURL(`http://127.0.0.1:${port}/`);
  win.on('closed', () => { win = null; });
}

// --- bighelp mobile gateway control (backend at /api/bighelp/*) ---

function apiRequest(method, path, body) {
  return new Promise((resolve, reject) => {
    const data = body ? Buffer.from(JSON.stringify(body)) : null;
    const req = http.request(
      { host: '127.0.0.1', port, path, method, headers: { 'Content-Type': 'application/json', ...(data ? { 'Content-Length': data.length } : {}) }, timeout: 8000 },
      (res) => {
        let buf = '';
        res.on('data', (c) => (buf += c));
        res.on('end', () => {
          try { resolve({ status: res.statusCode, json: buf ? JSON.parse(buf) : null }); }
          catch (_) { resolve({ status: res.statusCode, json: null }); }
        });
      }
    );
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    if (data) req.write(data);
    req.end();
  });
}

let connectWin = null;
function openConnectWindow() {
  if (connectWin && !connectWin.isDestroyed()) { connectWin.focus(); connectWin.reload(); return; }
  connectWin = new BrowserWindow({
    width: 440, height: 680, title: 'Connect your phone', backgroundColor: '#0d0f14',
    parent: win || undefined, webPreferences: { contextIsolation: true },
  });
  connectWin.setMenuBarVisibility(false);
  connectWin.loadURL(`http://127.0.0.1:${port}/api/bighelp/connect`);
  connectWin.on('closed', () => { connectWin = null; });
}

async function startSharing() {
  try {
    const st = await apiRequest('GET', '/api/bighelp/status');
    if (st.json && st.json.available === false) {
      dialog.showErrorBox('BINNY Mobile', 'Mobile sharing is unavailable: ' + (st.json.reason || 'unknown'));
      return;
    }
    // Share whatever project Desktop currently has open. The user can refine
    // selection from the connection page; this makes the common case one click.
    const proj = await currentProjectRef();
    if (!proj) {
      dialog.showMessageBox(win, { type: 'info', title: 'BINNY Mobile',
        message: 'Open or decompile a project first, then start mobile sharing.' });
      return;
    }
    const resp = await apiRequest('POST', '/api/bighelp/start', {
      addr: '0.0.0.0:8787',
      projects: [{ ref: proj.ref, mode: 'malware', sample: '' }],
    });
    if (resp.status !== 200) {
      dialog.showErrorBox('BINNY Mobile', 'Could not start sharing: ' + ((resp.json && resp.json.error) || resp.status));
      return;
    }
    openConnectWindow();
    buildMenu();
  } catch (e) {
    dialog.showErrorBox('BINNY Mobile', 'Could not start sharing: ' + e.message);
  }
}

async function stopSharing() {
  try { await apiRequest('POST', '/api/bighelp/stop'); } catch (_) {}
  if (connectWin && !connectWin.isDestroyed()) connectWin.close();
  buildMenu();
}

async function sharingRunning() {
  try {
    const st = await apiRequest('GET', '/api/bighelp/status');
    return !!(st.json && st.json.status && st.json.status.running);
  } catch (_) { return false; }
}

// currentProjectRef asks the backend what project is open (id or local tree).
async function currentProjectRef() {
  try {
    const cfgResp = await apiRequest('GET', '/api/config');
    const pid = cfgResp.json && cfgResp.json.projectId;
    if (pid) return { ref: pid };
  } catch (_) {}
  return null;
}

async function openFolder() {
  const r = await dialog.showOpenDialog(win, {
    title: 'Open a decompiled tree',
    properties: ['openDirectory'],
  });
  if (r.canceled || !r.filePaths[0]) return;
  serveDir = r.filePaths[0];
  try {
    await startSidecar();
    if (win) await win.loadURL(`http://127.0.0.1:${port}/`);
  } catch (e) {
    dialog.showErrorBox('BINNY', 'Could not restart with that folder: ' + e.message);
  }
}

async function buildMenu() {
  const isMac = process.platform === 'darwin';
  const running = await sharingRunning();
  const template = [
    ...(isMac ? [{ role: 'appMenu' }] : []),
    {
      label: 'File',
      submenu: [
        { label: 'Open Decompiled Folder…', accelerator: 'CmdOrCtrl+O', click: openFolder },
        { type: 'separator' },
        { label: 'Reload', accelerator: 'CmdOrCtrl+R', click: () => win && win.reload() },
        isMac ? { role: 'close' } : { role: 'quit' },
      ],
    },
    { role: 'editMenu' },
    { role: 'viewMenu' },
    {
      label: 'Mobile',
      submenu: [
        { label: 'Start Sharing to Phone…', enabled: !running, click: startSharing },
        { label: 'Stop Sharing', enabled: running, click: stopSharing },
        { type: 'separator' },
        { label: 'Show Connection…', enabled: running, click: openConnectWindow },
        { type: 'separator' },
        { label: 'About bighelp Sharing', click: () => shell.openExternal('https://github.com/promptclickrun/bighelp') },
      ],
    },
    {
      role: 'help',
      submenu: [{ label: 'BINNY on GitHub', click: () => shell.openExternal('https://github.com/openbin-ai/binny') }],
    },
  ];
  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

app.whenReady().then(async () => {
  try {
    await startSidecar();
  } catch (e) {
    dialog.showErrorBox('BINNY', 'Could not start the binny backend: ' + e.message +
      '\n\nSet BINNY_BIN to your binny binary, or put it on PATH.');
    app.quit();
    return;
  }
  buildMenu();
  await createWindow();
  app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
});

app.on('before-quit', () => {
  app.isQuitting = true;
  // Best-effort: stop mobile sharing so the port is freed with the app.
  apiRequest('POST', '/api/bighelp/stop').catch(() => {});
  if (sidecar) { try { sidecar.kill(); } catch (_) {} }
});
app.on('window-all-closed', () => { app.quit(); });
