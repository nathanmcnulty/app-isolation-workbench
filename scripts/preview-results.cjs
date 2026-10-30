// Offline UI preview of test-produced projections. Production never imports these reports.
// Usage: node scripts/preview-results.cjs C:\absolute\results-explorer-<id>
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const root = path.resolve(process.argv[2] || '');
const data = JSON.parse(fs.readFileSync(path.join(root, 'demo-view.json'), 'utf8'));
if (!data.summary.scope.startsWith('DEMONSTRATION:')) throw new Error('Expected explicitly labeled demonstration data');
const scope = String(data.summary.scope).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;');
const ui = path.resolve(__dirname, '../gui/ui');
const source = fs.readFileSync(path.join(ui, 'index.html'), 'utf8');
const panel = source.slice(source.indexOf('    <nav aria-label="Workbench views"'), source.indexOf('    <div id="workflowPanel">'));
const html = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Results Explorer — OFFLINE DEMONSTRATION</title><link rel="stylesheet" href="styles.css"><main class="shell"><h1>Results Explorer — offline demonstration</h1><p class="notice">${scope} This preview has no run backend. The accompanying verified-summary files were exported by the real Rust backend.</p>${panel}<div id="workflowPanel"><p>Read-only preview. Use Results to inspect the demonstration.</p></div></main><script src="preview.js"></script><script src="results.js"></script></html>`;
const files = new Map([
  ['/', ['text/html; charset=utf-8', html]],
  ['/styles.css', ['text/css; charset=utf-8', fs.readFileSync(path.join(ui, 'styles.css'))]],
  ['/results.js', ['text/javascript; charset=utf-8', fs.readFileSync(path.join(ui, 'results.js'))]],
  ['/preview.js', ['text/javascript; charset=utf-8', `window.__TAURI__={core:{invoke:async(name)=>{if(name==='open_results')return ${JSON.stringify(data).replaceAll('<','\\u003c')};if(name==='export_results')throw new Error('Preview: use the pre-generated Rust backend exports or the native desktop export dialog.');throw new Error('No execution backend in this preview');}}};`]],
]);
const server = http.createServer((request, response) => {
  const file = request.method === 'GET' && files.get(request.url);
  if (!file) { response.writeHead(404); response.end(); return; }
  response.writeHead(200, { 'Content-Type': file[0], 'Cache-Control': 'no-store', 'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'none'" }); response.end(file[1]);
});
server.listen(0, '127.0.0.1', () => console.log(`OFFLINE_DEMO=http://127.0.0.1:${server.address().port}/`));
