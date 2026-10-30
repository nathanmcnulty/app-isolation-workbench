// Fixed loopback preview assets. Prevent foreign pages from importing local snapshots.
const http = require('node:http');
async function startLocalPreview(files) {
  const server = http.createServer((request, response) => {
    const authority = `127.0.0.1:${server.address().port}`;
    const origin = `http://${authority}`;
    response.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    response.setHeader('X-Content-Type-Options', 'nosniff');
    response.setHeader('Cache-Control', 'no-store');
    const foreignResource = request.headers['sec-fetch-site'] === 'cross-site' && request.headers['sec-fetch-dest'] !== 'document';
    if (request.headers.host !== authority || (request.headers.origin && request.headers.origin !== origin) || foreignResource) {
      response.writeHead(403); response.end(); return;
    }
    const file = request.method === 'GET' && files.get(request.url);
    if (!file) { response.writeHead(404); response.end(); return; }
    response.writeHead(200, { 'Content-Type': file[0], 'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'" }); response.end(file[1]);
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  return { server, url: `http://127.0.0.1:${server.address().port}/` };
}
module.exports = { startLocalPreview };
