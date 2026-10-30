// Installed Node only. Serves fixed local UI assets and synthetic Controller snapshots.
const fs = require('node:fs');
const path = require('node:path');
const { startLocalPreview } = require('./local-preview-server.cjs');
const { createReplay } = require('./paired-ui-replay.cjs');
const root = path.resolve(process.argv[2] || '');
const input = path.join(root, 'workflow-demo.json');
const fd = fs.openSync(input, 'r');
const buffer = Buffer.alloc(2 * 1024 * 1024 + 1);
let size;
try { size = fs.readSync(fd, buffer, 0, buffer.length, 0); } finally { fs.closeSync(fd); }
if (size > 2 * 1024 * 1024) throw new Error('Replay snapshot exceeds its bound');
const data = JSON.parse(buffer.subarray(0, size).toString('utf8'));
createReplay(data); // Validate the synthetic envelope before opening a listener.
const ui = path.resolve(__dirname, '../gui/ui');
const escapeHtml = text => String(text).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;');
const banner = `<section class="notice replay-banner"><strong>OFFLINE · SYNTHETIC UI REPLAY · NO PROVIDER BACKEND</strong><p>${escapeHtml(data.scope)}</p><p>Use operator identity <code>${escapeHtml(data.states.review.review.operatorIdentity)}</code>. Existing summary files were exported by the real Rust Results service.</p></section>`;
const html = fs.readFileSync(path.join(ui, 'index.html'), 'utf8').replace('</head>', '<link rel="stylesheet" href="replay.css"></head>').replace('<body>', `<body>${banner}`).replace('value="assessment" checked', 'value="assessment"').replace('value="paired">', 'value="paired" checked>').replace('<script src="display.js">', '<script src="preview.js"></script><script src="display.js">');
const preview = `const createReplay=${createReplay.toString()};window.__TAURI__={core:{invoke:createReplay(${JSON.stringify(data).replaceAll('<', '\\u003c')})}};`;
const files = new Map([['/', ['text/html; charset=utf-8', html]], ['/preview.js', ['text/javascript; charset=utf-8', preview]]]);
files.set('/replay.css', ['text/css; charset=utf-8', '.replay-banner{position:sticky;top:0;z-index:20;background:#fffbe8;color:#111827;max-height:160px;overflow:auto;margin:0}.card,#startBox{scroll-margin-top:170px}']);
for (const name of ['styles.css', 'display.js', 'app.js', 'results.js']) files.set(`/${name}`, [name.endsWith('.css') ? 'text/css; charset=utf-8' : 'text/javascript; charset=utf-8', fs.readFileSync(path.join(ui, name))]);
startLocalPreview(files).then(({ url }) => console.log(`PAIRED_UI_REPLAY=${url}`)).catch(error => { console.error(error.message); process.exitCode = 1; });
