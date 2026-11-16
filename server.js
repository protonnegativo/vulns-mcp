// Entry point for hosting vulns-mcp as a remote MCP server (Streamable HTTP at /mcp), e.g. as a
// Node.js app on Hostinger, which sets PORT. Same as `node src/index.js --http`.
// Not part of the npm package: `npx vulns-mcp` keeps running over stdio.
//
// No top-level await: Hostinger's LiteSpeed loads this file with require(), which cannot load an
// ES module that awaits at the top level. PORT may be a number or a socket path; both work.

import { openArchive, log } from './src/server.js';
import { startHttp } from './src/http.js';

const getArchive = openArchive({}, { refreshEveryMs: 60 * 60 * 1000 });
startHttp({ port: process.env.PORT || 3000, getArchive }).catch((err) => {
  log('could not start the HTTP server:', err?.stack || err);
  process.exit(1);
});
