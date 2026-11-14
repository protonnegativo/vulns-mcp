// Loads the Vulns archive: a compact index of every publicly disclosed HackerOne report
// (reports.json + per-year summaries), the Bugcrowd disclosures (bugcrowd.json), the category
// taxonomy and the technique tags (playbook/<file>.json: techniques, what the write-up contains,
// payload snippets and the bypass sentence, detected in each report's write-up).
//
// Sources, in order of preference:
//   1. VULNS_DATA_DIR / --data-dir   a local folder with reports.json, taxonomy.json, summaries/,
//                                    bugcrowd.json
//   2. the on-disk cache            refreshed from VULNS_DATA_URL (default https://vulns.today/data)
//   3. the snapshot bundled in this package (./data)
//
// The server starts from the freshest copy it already has, then refreshes from the network in
// the background, so a slow or unreachable network never delays the first answer.

import { readFile, writeFile, mkdir, rename, rm } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import os from 'node:os';
import path from 'node:path';

const BUNDLED_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'data');
const DEFAULT_URL = 'https://vulns.today/data';
const REFRESH_AFTER_MS = 6 * 60 * 60 * 1000;
const FETCH_TIMEOUT_MS = 20_000;

const log = (...args) => console.error('[vulns-mcp]', ...args);

export function cacheDir() {
  if (process.env.VULNS_CACHE_DIR) return process.env.VULNS_CACHE_DIR;
  const base = process.env.XDG_CACHE_HOME || (process.platform === 'win32' ? process.env.LOCALAPPDATA : null) || path.join(os.homedir(), '.cache');
  return path.join(base || os.tmpdir(), 'vulns-mcp');
}

async function readJson(file) {
  return JSON.parse(await readFile(file, 'utf8'));
}

// Reads one complete copy of the archive from a folder.
async function readFolder(dir) {
  const index = await readJson(path.join(dir, 'reports.json'));
  const taxonomyFile = path.join(dir, 'taxonomy.json');
  const taxonomy = existsSync(taxonomyFile) ? await readJson(taxonomyFile) : await readJson(path.join(BUNDLED_DIR, 'taxonomy.json'));
  const summaries = {};
  for (const year of index.meta.summaryYears || []) {
    const file = path.join(dir, 'summaries', `${year}.json`);
    if (existsSync(file)) Object.assign(summaries, await readJson(file));
  }
  // Bugcrowd disclosures live in their own file (optional: older site builds don't have it).
  const bugcrowdFile = path.join(dir, 'bugcrowd.json');
  const bugcrowd = existsSync(bugcrowdFile) ? await readJson(bugcrowdFile) : null;
  // The playbook is optional too: older site builds don't have it.
  const playbook = {};
  for (const name of index.meta.playbookFiles || []) {
    const file = path.join(dir, 'playbook', `${name}.json`);
    if (existsSync(file)) Object.assign(playbook, await readJson(file));
  }
  return { index, taxonomy, summaries, bugcrowd, playbook };
}

// How fresh a copy is: the newest of its HackerOne fetch and its Bugcrowd build.
export function freshness(raw) {
  const stamps = [raw.index.meta.fetchedAt, raw.bugcrowd?.meta?.generatedAt].filter(Boolean).map(String);
  return stamps.sort().at(-1) || '';
}

async function fetchJson(url) {
  const res = await fetch(url, {
    headers: { Accept: 'application/json', 'User-Agent': 'vulns-mcp' },
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
  return res.json();
}

// Downloads a fresh copy into the cache folder. Returns null when the remote copy is not newer.
async function download(baseUrl, knownFreshness) {
  const index = await fetchJson(`${baseUrl}/reports.json`);
  let bugcrowd = null;
  try { bugcrowd = await fetchJson(`${baseUrl}/bugcrowd.json`); } catch { /* site without Bugcrowd data */ }
  if (knownFreshness && freshness({ index, bugcrowd }) <= knownFreshness) return null;
  let taxonomy = null;
  try { taxonomy = await fetchJson(`${baseUrl}/taxonomy.json`); } catch { /* older site build: use the bundled taxonomy */ }
  const files = { 'reports.json': index };
  if (taxonomy) files['taxonomy.json'] = taxonomy;
  if (bugcrowd) files['bugcrowd.json'] = bugcrowd;
  else await rm(path.join(cacheDir(), 'bugcrowd.json'), { force: true });
  for (const year of index.meta.summaryYears || []) {
    files[`summaries/${year}.json`] = await fetchJson(`${baseUrl}/summaries/${year}.json`);
  }
  for (const name of index.meta.playbookFiles || []) {
    files[`playbook/${name}.json`] = await fetchJson(`${baseUrl}/playbook/${name}.json`);
  }
  const dir = cacheDir();
  await mkdir(path.join(dir, 'summaries'), { recursive: true });
  await mkdir(path.join(dir, 'playbook'), { recursive: true });
  // reports.json is written last, so a half-finished download never looks complete.
  const order = Object.keys(files).sort((a, b) => (a === 'reports.json') - (b === 'reports.json'));
  for (const name of order) {
    const target = path.join(dir, name);
    await writeFile(`${target}.tmp`, JSON.stringify(files[name]));
    await rename(`${target}.tmp`, target);
  }
  await writeFile(path.join(dir, 'checked-at'), new Date().toISOString());
  return readFolder(dir);
}

async function lastChecked() {
  try { return Date.parse(await readFile(path.join(cacheDir(), 'checked-at'), 'utf8')) || 0; } catch { return 0; }
}

// Returns { initial, refresh } — `initial` is the best local copy; `refresh()` resolves to a
// newer copy from the network, or null.
export async function loadArchive({ dataDir, offline } = {}) {
  dataDir = dataDir || process.env.VULNS_DATA_DIR;
  if (dataDir) {
    const raw = await readFolder(path.resolve(dataDir));
    return { raw, source: `local folder ${path.resolve(dataDir)}`, refresh: async () => null };
  }

  const candidates = [];
  if (existsSync(path.join(cacheDir(), 'reports.json'))) {
    try { candidates.push({ raw: await readFolder(cacheDir()), source: `cache ${cacheDir()}` }); } catch (err) { log('ignoring unreadable cache:', err.message); }
  }
  candidates.push({ raw: await readFolder(BUNDLED_DIR), source: 'bundled snapshot' });
  candidates.sort((a, b) => freshness(b.raw).localeCompare(freshness(a.raw)));
  const best = candidates[0];

  offline = offline || process.env.VULNS_OFFLINE === '1';
  const baseUrl = (process.env.VULNS_DATA_URL || DEFAULT_URL).replace(/\/+$/, '');
  const refresh = async () => {
    if (offline) return null;
    if (Date.now() - (await lastChecked()) < REFRESH_AFTER_MS) return null;
    try {
      const raw = await download(baseUrl, freshness(best.raw));
      if (!raw) {
        await mkdir(cacheDir(), { recursive: true });
        await writeFile(path.join(cacheDir(), 'checked-at'), new Date().toISOString());
        return null;
      }
      return { raw, source: `${baseUrl} (cached in ${cacheDir()})` };
    } catch (err) {
      log(`could not refresh from ${baseUrl}: ${err.message} — using ${best.source}`);
      return null;
    }
  };
  return { raw: best.raw, source: best.source, refresh };
}

// ───────── Decoding ─────────

const dateStr = (int) => {
  if (!int) return null;
  const s = String(int);
  return `${s.slice(0, 4)}-${s.slice(4, 6)}-${s.slice(6, 8)}`;
};

export const PLATFORMS = { hackerone: 'HackerOne', bugcrowd: 'Bugcrowd' };

// Turns the compact index into report objects and lookup tables.
export function decodeArchive({ index, taxonomy, summaries, bugcrowd, playbook = {} }) {
  const col = Object.fromEntries(index.columns.map((name, i) => [name, i]));
  const categories = taxonomy.categories.map((c) => ({ ...c, reports: [] }));
  const topics = taxonomy.topics.map((t) => ({ ...t, reports: [] }));
  const programs = index.programs.map(([handle, name, industry]) => ({
    platform: 'hackerone', handle, name: name || handle, industry: industry || null, url: `https://hackerone.com/${handle}`, reports: [],
  }));
  const weaknesses = index.weaknesses.map(([name, cwe]) => ({ name, cwe: cwe || null }));
  const link = (report) => {
    report.program?.reports.push(report);
    report.category.reports.push(report);
    for (const t of report.topics) t.reports.push(report);
    return report;
  };

  const reports = index.rows.map((row) => {
    const program = programs[row[col.program]] || null;
    const category = categories[row[col.category]] || categories.at(-1);
    const reportTopics = (row[col.topics] || []).map((i) => topics[i]).filter(Boolean);
    const disclosed = row[col.disclosed];
    return link({
      platform: 'hackerone',
      id: row[col.id],
      url: `https://hackerone.com/reports/${row[col.id]}`,
      title: row[col.title],
      program,
      weakness: weaknesses[row[col.weakness]] || null,
      category,
      severity: taxonomy.severities[row[col.severity]] || 'unrated',
      cvss: row[col.cvss] || null,
      bounty: row[col.bounty] || 0,
      votes: row[col.votes] || 0,
      disclosed: dateStr(disclosed),
      disclosedInt: disclosed || 0,
      submitted: dateStr(row[col.submitted]),
      reporter: index.reporters[row[col.reporter]] || null,
      state: taxonomy.states[row[col.state]] || 'other',
      cves: row[col.cves] || [],
      topics: reportTopics,
      summary: summaries[row[col.id]] || null,
      playbook: playbook[String(row[col.id])] || null,
    });
  });

  // Bugcrowd: no weakness, CWE, CVE, CVSS or votes are published; the category comes from the
  // title, the severity from the P1–P5 priority, and `summary` is the start of the researcher's
  // summary (the whole text is on the disclosure page).
  const platformCounts = { hackerone: reports.length, bugcrowd: 0 };
  if (bugcrowd?.rows?.length) {
    const bc = Object.fromEntries(bugcrowd.columns.map((name, i) => [name, i]));
    const bcPrograms = (bugcrowd.programs || []).map(([code, name]) => ({
      platform: 'bugcrowd', handle: code, name: name || code, industry: null, url: `https://bugcrowd.com/engagements/${code}`, reports: [],
    }));
    programs.push(...bcPrograms);
    for (const row of bugcrowd.rows) {
      const disclosed = row[bc.disclosed];
      reports.push(link({
        platform: 'bugcrowd',
        id: String(row[bc.id]).toLowerCase(),
        url: row[bc.url],
        title: row[bc.title],
        program: bcPrograms[row[bc.program]] || null,
        weakness: null,
        category: categories[row[bc.category]] || categories.at(-1),
        severity: taxonomy.severities[row[bc.severity]] || 'unrated',
        cvss: null,
        bounty: row[bc.bounty] || 0,
        votes: 0,
        disclosed: dateStr(disclosed),
        disclosedInt: disclosed || 0,
        submitted: dateStr(row[bc.submitted]),
        reporter: bugcrowd.reporters?.[row[bc.reporter]] || null,
        state: taxonomy.states[row[bc.state]] || 'other',
        cves: [],
        topics: (row[bc.topics] || []).map((i) => topics[i]).filter(Boolean),
        summary: row[bc.summary] || null,
        playbook: playbook[String(row[bc.id]).toLowerCase()] || null,
      }));
      platformCounts.bugcrowd++;
    }
    reports.sort((a, b) => b.disclosedInt - a.disclosedInt || String(b.id).localeCompare(String(a.id)));
  }

  const byId = new Map(reports.map((r) => [r.id, r]));
  const meta = {
    ...index.meta,
    count: reports.length,
    platforms: {
      hackerone: { count: platformCounts.hackerone, updated: index.meta.fetchedAt },
      ...(platformCounts.bugcrowd ? { bugcrowd: { count: platformCounts.bugcrowd, updated: bugcrowd.meta?.generatedAt || null } } : {}),
    },
  };
  return {
    meta, reports, byId, categories, topics, programs, severities: taxonomy.severities, states: taxonomy.states,
    techniques: taxonomy.techniques || [], techniqueKinds: taxonomy.techniqueKinds || {},
  };
}
