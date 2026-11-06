const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { startLocalPreview } = require('../../scripts/local-preview-server.cjs');
const get = (url, headers = {}) => new Promise((resolve, reject) => {
  http.get(url, { headers }, response => { const chunks = []; response.on('data', c => chunks.push(c)); response.on('end', () => resolve({ status: response.statusCode, headers: response.headers, body: Buffer.concat(chunks).toString() })); }).on('error', reject);
});
test('local previews refuse foreign hosts/origins and mark executable snapshots same-origin', async t => {
  const { server, url } = await startLocalPreview(new Map([['/preview.js', ['text/javascript', 'synthetic snapshot']]]));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const valid = await get(`${url}preview.js`);
  assert.equal(valid.status, 200); assert.equal(valid.body, 'synthetic snapshot');
  assert.equal(valid.headers['cross-origin-resource-policy'], 'same-origin');
  assert.equal((await get(`${url}preview.js`, { Host: 'foreign.invalid' })).status, 403);
  assert.equal((await get(`${url}preview.js`, { Origin: 'https://foreign.invalid' })).status, 403);
  assert.equal((await get(`${url}preview.js`, { 'Sec-Fetch-Site': 'cross-site' })).status, 403);
  assert.equal((await get(`${url}preview.js`, { 'Sec-Fetch-Site': 'cross-site', 'Sec-Fetch-Dest': 'document' })).status, 200);
  assert.equal((await get(`${url}arbitrary-file`)).status, 404);
});
