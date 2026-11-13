// Loads the Vulns archive: a compact index of every publicly disclosed HackerOne report,
// plus per-year summaries and the category taxonomy.
//
// Sources, in order of preference:
//   1. VULNS_DATA_DIR / --data-dir   a local folder with reports.json, taxonomy.json, summaries/
//   2. the on-disk cache            refreshed from VULNS_DATA_URL (default https://vulns.today/data)
//   3. the snapshot bundled in this package (./data)
//
// The server starts from the freshest copy it already has, then refreshes from the network in
// the background, so a slow or unreachable network never delays the first answer.

import { readFile, writeFile, mkdir, rename } from 'node:fs/promises';
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
  return { index, taxonomy, summaries };
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
async function download(baseUrl, knownFetchedAt) {
  const index = await fetchJson(`${baseUrl}/reports.json`);
  if (knownFetchedAt && index.meta.fetchedAt <= knownFetchedAt) return null;
  let taxonomy = null;
  try { taxonomy = await fetchJson(`${baseUrl}/taxonomy.json`); } catch { /* older site build: use the bundled taxonomy */ }
  const files = { 'reports.json': index };
  if (taxonomy) files['taxonomy.json'] = taxonomy;
  for (const year of index.meta.summaryYears || []) {
    files[`summaries/${year}.json`] = await fetchJson(`${baseUrl}/summaries/${year}.json`);
  }
  const dir = cacheDir();
  await mkdir(path.join(dir, 'summaries'), { recursive: true });
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
  candidates.sort((a, b) => String(b.raw.index.meta.fetchedAt).localeCompare(String(a.raw.index.meta.fetchedAt)));
  const best = candidates[0];

  offline = offline || process.env.VULNS_OFFLINE === '1';
  const baseUrl = (process.env.VULNS_DATA_URL || DEFAULT_URL).replace(/\/+$/, '');
  const refresh = async () => {
    if (offline) return null;
    if (Date.now() - (await lastChecked()) < REFRESH_AFTER_MS) return null;
    try {
      const raw = await download(baseUrl, best.raw.index.meta.fetchedAt);
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

// Turns the compact index into report objects and lookup tables.
export function decodeArchive({ index, taxonomy, summaries }) {
  const col = Object.fromEntries(index.columns.map((name, i) => [name, i]));
  const categories = taxonomy.categories.map((c) => ({ ...c, reports: [] }));
  const topics = taxonomy.topics.map((t) => ({ ...t, reports: [] }));
  const programs = index.programs.map(([handle, name, industry]) => ({ handle, name: name || handle, industry: industry || null, reports: [] }));
  const weaknesses = index.weaknesses.map(([name, cwe]) => ({ name, cwe: cwe || null }));

  const reports = index.rows.map((row) => {
    const program = programs[row[col.program]] || null;
    const category = categories[row[col.category]] || categories.at(-1);
    const reportTopics = (row[col.topics] || []).map((i) => topics[i]).filter(Boolean);
    const disclosed = row[col.disclosed];
    const report = {
      id: row[col.id],
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
    };
    program?.reports.push(report);
    category.reports.push(report);
    for (const t of reportTopics) t.reports.push(report);
    return report;
  });

  const byId = new Map(reports.map((r) => [r.id, r]));
  return { meta: index.meta, reports, byId, categories, topics, programs, severities: taxonomy.severities, states: taxonomy.states };
}
