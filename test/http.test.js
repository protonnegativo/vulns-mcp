// The remote mode: start the HTTP server on a random port, with the bundled snapshot and no
// network, and talk to it with the MCP client's Streamable HTTP transport.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

const cache = mkdtempSync(path.join(tmpdir(), 'vulns-mcp-http-'));
process.env.VULNS_CACHE_DIR = cache;
const { openArchive } = await import('../src/server.js');
const { startHttp } = await import('../src/http.js');

let server;
let base;

before(async () => {
  server = await startHttp({ port: 0, host: '127.0.0.1', getArchive: openArchive({ offline: true }) });
  base = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  await new Promise((r) => server.close(r));
  rmSync(cache, { recursive: true, force: true });
});

test('serves MCP over Streamable HTTP', async () => {
  const client = new Client({ name: 'vulns-mcp-http-test', version: '0.0.0' });
  await client.connect(new StreamableHTTPClientTransport(new URL(`${base}/mcp`)));
  const { tools } = await client.listTools();
  assert.ok(tools.some((t) => t.name === 'search_reports'));
  assert.ok(tools.some((t) => t.name === 'list_techniques'));
  const res = await client.callTool({ name: 'search_reports', arguments: { query: 'ssrf', limit: 2 } });
  assert.match(res.content[0].text, /results for "ssrf"/);
  assert.match(client.getInstructions() || '', /search_reports/);
  await client.close();
});

test('answers health checks and describes itself', async () => {
  const health = await fetch(`${base}/health`).then((r) => r.json());
  assert.equal(health.ok, true);
  assert.ok(health.reports > 10000);
  const root = await fetch(`${base}/`).then((r) => r.json());
  assert.equal(root.mcp.endpoint, '/mcp');
});

test('allows browsers from any origin (CORS)', async () => {
  const pre = await fetch(`${base}/mcp`, { method: 'OPTIONS', headers: { Origin: 'https://chatgpt.com', 'Access-Control-Request-Method': 'POST' } });
  assert.equal(pre.status, 204);
  assert.equal(pre.headers.get('access-control-allow-origin'), '*');
  assert.match(pre.headers.get('access-control-allow-headers'), /Mcp-Protocol-Version/);
});

test('rejects other methods and bad bodies with JSON-RPC errors', async () => {
  const get = await fetch(`${base}/mcp`);
  assert.equal(get.status, 405);
  const bad = await fetch(`${base}/mcp`, { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' }, body: '{nope' });
  assert.equal(bad.status, 400);
  assert.equal((await bad.json()).error.code, -32700);
  const missing = await fetch(`${base}/nope`);
  assert.equal(missing.status, 404);
});
