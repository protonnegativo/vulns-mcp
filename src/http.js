// Remote mode: MCP over Streamable HTTP, so web apps that only accept a URL (ChatGPT connectors,
// grok.com, the xAI API, Claude's remote MCP) can use the archive without installing anything.
//
//   POST /mcp     the MCP endpoint (stateless: each request is complete on its own, JSON responses)
//   GET  /health  liveness and archive size
//   GET  /        what this server is and how to connect
//
// Read-only, no accounts. Every response allows any origin (CORS), and each client IP gets a
// request budget per minute.

import http from 'node:http';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { createServer, pkg, log } from './server.js';

const MAX_BODY = 1_000_000; // bytes
const RATE = { windowMs: 60_000, max: 120 };

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Accept, Authorization, Mcp-Session-Id, Mcp-Protocol-Version, Last-Event-ID',
  'Access-Control-Expose-Headers': 'Mcp-Session-Id, Mcp-Protocol-Version',
  'Access-Control-Max-Age': '86400',
};

const json = (res, status, body, extra = {}) => {
  res.writeHead(status, { ...CORS, 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...extra });
  res.end(JSON.stringify(body));
};
const rpcError = (res, status, code, message) => json(res, status, { jsonrpc: '2.0', error: { code, message }, id: null });

// The client's address: behind a proxy (Hostinger, a CDN) the first X-Forwarded-For entry.
const clientIp = (req) => String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || 'unknown';

function rateLimiter() {
  const hits = new Map(); // ip → { start, count }
  setInterval(() => {
    const now = Date.now();
    for (const [ip, h] of hits) if (now - h.start > RATE.windowMs) hits.delete(ip);
  }, RATE.windowMs).unref();
  return (ip) => {
    const now = Date.now();
    let h = hits.get(ip);
    if (!h || now - h.start > RATE.windowMs) hits.set(ip, (h = { start: now, count: 0 }));
    h.count++;
    return h.count <= RATE.max ? 0 : Math.ceil((h.start + RATE.windowMs - now) / 1000);
  };
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY) { reject(Object.assign(new Error('body too large'), { status: 413 })); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

// Starts the HTTP server. Resolves with the node http.Server once it is listening.
export function startHttp({ port = 3000, host, getArchive }) {
  const limited = rateLimiter();

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://localhost');
    try {
      if (req.method === 'OPTIONS') { res.writeHead(204, CORS); res.end(); return; }

      if (url.pathname === '/health') {
        const archive = await getArchive();
        json(res, 200, { ok: true, name: 'vulns-mcp', version: pkg.version, reports: archive?.db.reports.length ?? 0, dataFetchedAt: archive?.db.meta.fetchedAt ?? null });
        return;
      }

      if (url.pathname === '/' && req.method === 'GET') {
        json(res, 200, {
          name: 'vulns-mcp',
          version: pkg.version,
          description: 'MCP server for publicly disclosed bug bounty reports from HackerOne and Bugcrowd (vulns.today).',
          mcp: { endpoint: '/mcp', transport: 'streamable-http' },
          docs: 'https://github.com/protonnegativo/vulns-mcp#readme',
          site: 'https://vulns.today/#/agents',
        });
        return;
      }

      if (url.pathname !== '/mcp') { json(res, 404, { error: 'not found', mcp: '/mcp' }); return; }

      const wait = limited(clientIp(req));
      if (wait) { rpcError(res, 429, -32000, `Too many requests: try again in ${wait} s.`); return; }

      // Stateless: there is no session to stream to or to end.
      if (req.method !== 'POST') { rpcError(res, 405, -32000, 'Method not allowed: send JSON-RPC with POST.'); return; }

      let body;
      try { body = JSON.parse(await readBody(req)); } catch (err) {
        if (err.status === 413) { rpcError(res, 413, -32600, 'Request body too large.'); return; }
        rpcError(res, 400, -32700, 'Parse error: the body must be JSON.');
        return;
      }

      const mcp = createServer(getArchive);
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
      res.on('close', () => { transport.close(); mcp.close(); });
      for (const [k, v] of Object.entries(CORS)) res.setHeader(k, v);
      await mcp.connect(transport);
      await transport.handleRequest(req, res, body);
    } catch (err) {
      log('request failed:', err?.stack || err);
      if (!res.headersSent) rpcError(res, 500, -32603, 'Internal error.');
      else res.end();
    }
  });

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => {
      const addr = server.address();
      log(`vulns-mcp ${pkg.version} ready over HTTP on port ${addr.port} (POST /mcp)`);
      resolve(server);
    });
  });
}
