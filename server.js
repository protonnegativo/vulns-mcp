// Entry point for hosting vulns-mcp as a remote MCP server (Streamable HTTP at /mcp), e.g. as a
// Node.js app on Hostinger, which sets PORT. Same as `node src/index.js --http`.
// Not part of the npm package: `npx vulns-mcp` keeps running over stdio.

import { openArchive } from './src/server.js';
import { startHttp } from './src/http.js';

const getArchive = openArchive({}, { refreshEveryMs: 60 * 60 * 1000 });
await startHttp({ port: Number(process.env.PORT) || 3000, getArchive });
