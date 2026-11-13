// Reads the full public write-up of a disclosed report from HackerOne, on demand.
//
// The archive only stores the index (title, program, weakness, severity, summary). The full
// text — steps to reproduce, payloads, impact — stays on hackerone.com and is fetched from the
// report's public JSON (https://hackerone.com/reports/<id>.json) when an agent asks for it.

const TIMEOUT_MS = 20_000;
const CACHE_SIZE = 100;
const cache = new Map();

export class FetchError extends Error {}

export function enabled() {
  return process.env.VULNS_FULL_TEXT !== '0';
}

export async function fetchReport(id) {
  if (cache.has(id)) {
    const hit = cache.get(id);
    cache.delete(id);
    cache.set(id, hit);
    return hit;
  }
  let res;
  try {
    res = await fetch(`https://hackerone.com/reports/${id}.json`, {
      headers: { Accept: 'application/json', 'User-Agent': 'vulns-mcp' },
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  } catch (err) {
    throw new FetchError(err.name === 'TimeoutError' ? 'timed out' : err.message);
  }
  if (!res.ok) throw new FetchError(`HTTP ${res.status}`);
  let json;
  try { json = await res.json(); } catch { throw new FetchError('response was not JSON (the report may not be public)'); }
  if (!json || typeof json !== 'object' || !json.id) throw new FetchError('unexpected response');

  const report = {
    id: json.id,
    url: json.url || `https://hackerone.com/reports/${id}`,
    title: json.title || null,
    state: json.readable_substate || json.substate || null,
    severity: json.severity?.rating || json.severity_rating || null,
    cvss: json.severity?.score ?? null,
    cvssMetrics: json.severity?.metrics || null,
    weakness: json.weakness?.name || null,
    asset: json.structured_scope ? { type: json.structured_scope.asset_type, identifier: json.structured_scope.asset_identifier } : null,
    cves: json.cve_ids || [],
    program: json.team ? { handle: json.team.handle, name: json.team.profile?.name || json.team.handle } : null,
    reporter: json.reporter?.username || null,
    submittedAt: json.submitted_at || null,
    disclosedAt: json.disclosed_at || null,
    bounty: json.formatted_bounty || null,
    votes: json.vote_count ?? null,
    writeup: (json.vulnerability_information || '').trim(),
    summaries: (json.summaries || [])
      .filter((s) => s.content && String(s.content).trim())
      .map((s) => ({ by: s.category === 'team' ? 'program' : s.category || 'unknown', text: String(s.content).trim() })),
    attachments: (json.attachments || []).map((a) => a.file_name).filter(Boolean),
  };
  cache.set(id, report);
  if (cache.size > CACHE_SIZE) cache.delete(cache.keys().next().value);
  return report;
}
