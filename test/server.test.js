// End-to-end tests: start the real server over stdio and talk to it with the MCP client SDK.
// Uses the bundled snapshot and never refreshes it. The live HackerOne fetch runs only with
// VULNS_TEST_NETWORK=1.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const cache = mkdtempSync(path.join(tmpdir(), 'vulns-mcp-test-'));
let client;

before(async () => {
  client = new Client({ name: 'vulns-mcp-test', version: '0.0.0' });
  await client.connect(new StdioClientTransport({
    command: process.execPath,
    args: [path.join(ROOT, 'src', 'index.js'), '--offline'],
    env: { ...process.env, VULNS_CACHE_DIR: cache },
    stderr: 'ignore',
  }));
});

after(async () => {
  await client?.close();
  rmSync(cache, { recursive: true, force: true });
});

const call = async (name, args = {}) => {
  const res = await client.callTool({ name, arguments: args });
  return { text: res.content.map((c) => c.text).join('\n'), isError: !!res.isError };
};

test('lists the tools', async () => {
  const { tools } = await client.listTools();
  const names = tools.map((t) => t.name).sort();
  assert.deepEqual(names, ['archive_stats', 'find_similar', 'get_category_guide', 'get_program', 'get_report', 'list_categories', 'list_techniques', 'search_reports']);
  for (const t of tools) {
    assert.ok(t.description.length > 40, `${t.name} has a description`);
    assert.equal(t.annotations?.readOnlyHint, true, `${t.name} is read-only`);
  }
});

test('search_reports rejects unknown techniques', async () => {
  const { text, isError } = await call('search_reports', { technique: ['not-a-technique'] });
  assert.equal(isError, true);
  assert.match(text, /list_techniques/);
});

test('ships server instructions', () => {
  assert.match(client.getInstructions() || '', /search_reports/);
});

test('search_reports ranks by relevance', async () => {
  const { text, isError } = await call('search_reports', { query: 'CVE-2021-44228', limit: 3 });
  assert.equal(isError, false);
  assert.match(text, /results for "CVE-2021-44228"/);
  assert.match(text, /^1\. \[\d+\] .*(CVE-2021-44228|[Ll]og4)/m);
  assert.match(text, /https:\/\/hackerone\.com\/reports\/\d+/);
});

test('search_reports expands acronyms and applies filters', async () => {
  const { text } = await call('search_reports', { query: 'sqli', severity: ['critical'], limit: 5 });
  assert.match(text, /severity critical/);
  const lines = text.split('\n').filter((l) => /^ {3}\S.* · (critical|high|medium|low|none|unrated)/.test(l));
  assert.ok(lines.length > 0);
  for (const l of lines) assert.match(l, / · critical/);
});

test('search_reports with no query lists the newest', async () => {
  const { text } = await call('search_reports', { limit: 2 });
  assert.match(text, /sorted by newest/);
});

test('search_reports resolves programs and CWE ids', async () => {
  const { text } = await call('search_reports', { program: 'gitlab', weakness: 'CWE-918', sort: 'votes', limit: 3 });
  assert.match(text, /program GitLab \[gitlab\]/);
  assert.match(text, /CWE-918/);
});

test('search_reports pages', async () => {
  const first = await call('search_reports', { query: 'xss', limit: 2 });
  const second = await call('search_reports', { query: 'xss', limit: 2, offset: 2 });
  assert.match(first.text, /offset=2/);
  assert.match(second.text, /^3\. /m);
});

test('search_reports rejects unknown categories with the valid ids', async () => {
  const { text, isError } = await call('search_reports', { category: 'nope' });
  assert.equal(isError, true);
  assert.match(text, /Valid ids: xss, sqli/);
});

test('get_report returns archive metadata without the network', async () => {
  const { text, isError } = await call('get_report', { id: 'https://hackerone.com/reports/1628209', include_full_text: false });
  assert.equal(isError, false);
  assert.match(text, /^# \[1628209\] /);
  assert.match(text, /Severity: /);
  assert.match(text, /URL: https:\/\/hackerone\.com\/reports\/1628209/);
});

test('find_similar stays on topic', async () => {
  const { text } = await call('find_similar', { id: 1628209, limit: 5 });
  assert.match(text, /Reports similar to \[1628209\]/);
  assert.match(text.toLowerCase(), /ssrf|request forgery|pdf/);
  assert.doesNotMatch(text, /^\d+\. \[1628209\]/m);
});

test('list_categories and get_category_guide', async () => {
  const list = await call('list_categories');
  assert.match(list.text, /- xss — Cross-Site Scripting/);
  const guide = await call('get_category_guide', { category: 'SSRF', examples: 2 });
  assert.match(guide.text, /^# .* \[ssrf\]/);
  assert.match(guide.text, /## How to test/);
  assert.match(guide.text, /## Most upvoted examples/);
});

test('get_program and archive_stats', async () => {
  const program = await call('get_program', { program: 'shopify', examples: 2 });
  assert.match(program.text, /^# Shopify \(shopify\) on HackerOne/);
  const stats = await call('archive_stats');
  assert.match(stats.text, /publicly disclosed bug bounty reports \(HackerOne [\d,]+ · Bugcrowd [\d,]+\)/);
  assert.match(stats.text, /bundled snapshot/);
});

test('search_reports covers Bugcrowd and filters by platform', async () => {
  const { text } = await call('search_reports', { platform: 'bugcrowd', limit: 5 });
  assert.match(text, /reports for Bugcrowd/);
  const ids = [...text.matchAll(/^\d+\. \[([^\]]+)\]/gm)].map((m) => m[1]);
  assert.equal(ids.length, 5);
  for (const id of ids) assert.match(id, /^bc-[0-9a-f]{10}$/);
  assert.doesNotMatch(text, /hackerone\.com/);
  assert.match(text, /https:\/\/bugcrowd\.com\/disclosures\//);
});

test('search_reports mixes both platforms and links each to its own site', async () => {
  const { text } = await call('search_reports', { query: 'ssrf', limit: 50 });
  assert.match(text, /\(HackerOne [\d,]+ · Bugcrowd [\d,]+\)/);
  for (const block of text.split('\n\n').filter((b) => /^\d+\. \[/.test(b))) {
    if (/^\d+\. \[bc-/.test(block)) assert.match(block, /bugcrowd\.com\/disclosures\//);
    else assert.match(block, /hackerone\.com\/reports\//);
  }
});

test('get_report reads a Bugcrowd report by id or URL without the network', async () => {
  const byId = await call('get_report', { id: 'bc-495cc609bd', include_full_text: false });
  assert.equal(byId.isError, false);
  assert.match(byId.text, /^# \[bc-495cc609bd\] /);
  assert.match(byId.text, /Platform: Bugcrowd/);
  assert.match(byId.text, /Bugcrowd P\d/);
  assert.match(byId.text, /URL: https:\/\/bugcrowd\.com\/disclosures\/495cc609-bd77/);
  assert.doesNotMatch(byId.text, /hackerone\.com/);
  const byUrl = await call('get_report', { id: 'https://bugcrowd.com/disclosures/495cc609-bd77-4f03-a750-f6dbf730673f/1-click-remote-code-execution-via-link-embed', include_full_text: false });
  assert.match(byUrl.text, /^# \[bc-495cc609bd\] /);
  const missing = await call('get_report', { id: 'bc-0000000000' });
  assert.equal(missing.isError, true);
});

test('find_similar and get_program work for Bugcrowd', async () => {
  const similar = await call('find_similar', { id: 'bc-495cc609bd', limit: 3 });
  assert.match(similar.text, /Reports similar to \[bc-495cc609bd\]/);
  const program = await call('get_program', { program: 'asana', platform: 'bugcrowd', examples: 2 });
  assert.match(program.text, /^# Asana \(asana\) on Bugcrowd/);
  assert.match(program.text, /https:\/\/bugcrowd\.com\/engagements\/asana/);
  assert.match(program.text, /## Highest bounties/);
});

test('get_report reads the full write-up from HackerOne', { skip: process.env.VULNS_TEST_NETWORK !== '1' && 'set VULNS_TEST_NETWORK=1' }, async () => {
  const { text, isError } = await call('get_report', { id: 1628209, max_chars: 2000 });
  assert.equal(isError, false);
  assert.match(text, /<<<WRITEUP/);
  assert.match(text, /WRITEUP>>>/);
});

test('get_report reads the full disclosure summary from Bugcrowd', { skip: process.env.VULNS_TEST_NETWORK !== '1' && 'set VULNS_TEST_NETWORK=1' }, async () => {
  const { text, isError } = await call('get_report', { id: 'bc-495cc609bd', max_chars: 1000 });
  assert.equal(isError, false);
  assert.match(text, /## Disclosure summary by /);
  assert.match(text, /<<<WRITEUP\n[\s\S]+\nWRITEUP>>>/);
  assert.match(text, /offset=1000/);
});
