#!/usr/bin/env node
// vulns-mcp — an MCP server that lets AI agents search publicly disclosed bug bounty reports
// from HackerOne and Bugcrowd.
// Speaks MCP over stdio by default (everything it logs goes to stderr; stdout belongs to the
// protocol), or over Streamable HTTP with --http, to be hosted as a remote server.

import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { cacheDir } from './data.js';
import { openArchive, createServer, pkg, log } from './server.js';
import { startHttp } from './http.js';

const HELP = `vulns-mcp ${pkg.version} — MCP server for publicly disclosed HackerOne and Bugcrowd reports

Usage: vulns-mcp [--data-dir <folder>] [--offline] [--http [--port <n>] [--host <addr>]]

  --data-dir <folder>  read reports.json, taxonomy.json, summaries/, playbook/ and bugcrowd.json
                       from this folder (same as VULNS_DATA_DIR)
  --offline            never contact the network for archive updates (VULNS_OFFLINE=1)
  --http               serve MCP over Streamable HTTP at /mcp instead of stdio (a remote server)
  --port <n>           HTTP port (default: $PORT or 3000)
  --host <addr>        HTTP address to listen on (default: all)
  --version, --help

Environment:
  VULNS_DATA_URL   where to refresh the archive from (default https://vulns.today/data)
  VULNS_CACHE_DIR  where refreshed data is cached (default ${cacheDir()})
  VULNS_FULL_TEXT  set to 0 to stop get_report from fetching full text from hackerone.com
                   and bugcrowd.com

Without --http it speaks MCP over stdio: add it to your MCP client rather than running it by hand.`;

function parseArgs(argv) {
  const opts = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--help' || a === '-h') { console.log(HELP); process.exit(0); }
    if (a === '--version' || a === '-v') { console.log(pkg.version); process.exit(0); }
    if (a === '--offline') opts.offline = true;
    else if (a === '--http') opts.http = true;
    else if (a === '--port') opts.port = Number(argv[++i]);
    else if (a.startsWith('--port=')) opts.port = Number(a.slice('--port='.length));
    else if (a === '--host') opts.host = argv[++i];
    else if (a.startsWith('--host=')) opts.host = a.slice('--host='.length);
    else if (a === '--data-dir') opts.dataDir = argv[++i];
    else if (a.startsWith('--data-dir=')) opts.dataDir = a.slice('--data-dir='.length);
    else { console.error(`Unknown option: ${a}\n\n${HELP}`); process.exit(2); }
  }
  return opts;
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.http) {
    // A long-running server looks for newer data every hour.
    const getArchive = openArchive(opts, { refreshEveryMs: 60 * 60 * 1000 });
    await startHttp({ port: opts.port || Number(process.env.PORT) || 3000, host: opts.host, getArchive });
    return;
  }
  const server = createServer(openArchive(opts));
  await server.connect(new StdioServerTransport());
  log(`vulns-mcp ${pkg.version} ready on stdio`);
}

main().catch((err) => {
  log('fatal:', err?.stack || err);
  process.exit(1);
});
