// Full-text search over the archive with BM25 (field-weighted), plus a tiny bit of
// security-specific query expansion so "sqli" finds "SQL injection" and vice versa.

const K1 = 1.2;
const B = 0.75;

// How much each field counts. Titles carry most of the signal; summaries add context.
const FIELDS = {
  title: 3,
  cve: 3,
  weakness: 2,
  category: 2,
  topics: 1.5,
  program: 1.5,
  playbook: 1.5,
  summary: 1,
};

const STOPWORDS = new Set(`a an and are as at be by can could for from has have how in into is it its of on or that the
their this to via was were which while with without when where who will would allows allow allowed using use used
leads lead leading due possible able any all also an being been but do does if may more most not only other our out
over same some such than then there these they through under up your you we`.split(/\s+/));

// Acronyms people type, and the words reports use.
const SYNONYMS = {
  xss: 'cross site scripting',
  sqli: 'sql injection',
  rce: 'remote code execution',
  ssrf: 'server side request forgery',
  csrf: 'cross site request forgery',
  xsrf: 'cross site request forgery',
  idor: 'insecure direct object reference',
  bola: 'insecure direct object reference authorization',
  lfi: 'local file inclusion',
  rfi: 'remote file inclusion',
  xxe: 'xml external entity',
  ssti: 'server side template injection',
  ato: 'account takeover',
  dos: 'denial service',
  ddos: 'denial service',
  redos: 'regular expression denial service',
  mfa: '2fa two factor',
  '2fa': 'two factor mfa',
  otp: 'one time password 2fa',
  jwt: 'json web token',
  cors: 'cross origin resource sharing',
  csp: 'content security policy',
  sso: 'single sign saml',
  lpe: 'local privilege escalation',
  privesc: 'privilege escalation',
  ssi: 'server side includes',
  crlf: 'crlf injection header',
  hpp: 'http parameter pollution',
  smuggling: 'request smuggling desync',
  llm: 'prompt injection ai',
};

const fold = (s) => s.normalize('NFKD').replace(/[̀-ͯ]/g, '').toLowerCase();

function stem(t) {
  if (t.length <= 3 || /\d/.test(t)) return t;
  if (t.endsWith('ies') && t.length > 4) return t.slice(0, -3) + 'y';
  if (t.endsWith('sses')) return t.slice(0, -2);
  if (t.endsWith('s') && !/(ss|us|is)$/.test(t)) return t.slice(0, -1);
  return t;
}

// Splits text into search terms. CVE and CWE ids are kept whole.
export function tokenize(text) {
  if (!text) return [];
  const s = fold(String(text));
  const out = [];
  for (const m of s.matchAll(/\b(?:cve-\d{4}-\d{3,}|cwe-\d+)\b/g)) out.push(m[0]);
  for (const raw of s.split(/[^a-z0-9]+/)) {
    if (raw.length < 2 || STOPWORDS.has(raw)) continue;
    out.push(stem(raw));
  }
  return out;
}

export class SearchIndex {
  constructor(reports) {
    this.reports = reports;
    this.N = reports.length;
    this.postings = new Map(); // term → { docs: Int32Array-ish arrays, tf }
    this.docLen = new Float32Array(this.N);
    this.docTerms = new Array(this.N); // term → weighted tf, kept for "more like this"
    const tmp = new Map();
    let total = 0;
    reports.forEach((r, i) => {
      const fields = {
        title: r.title,
        cve: r.cves.join(' '),
        weakness: r.weakness ? `${r.weakness.name} ${r.weakness.cwe || ''}` : '',
        category: `${r.category.id} ${r.category.short} ${r.category.name}`,
        topics: r.topics.map((t) => `${t.id} ${t.name}`).join(' '),
        program: `${r.platform} ${r.program ? `${r.program.handle} ${r.program.name}` : ''}`,
        summary: r.summary || '',
        // The techniques detected in the write-up and the sentence that explains a bypass, so
        // "dns rebinding" or "waf bypass" find the reports that did it.
        playbook: r.playbook ? [...(r.playbook.tags || []).map((t) => t.replace(/-/g, ' ')), r.playbook.bypass || ''].join(' ') : '',
      };
      const tf = new Map();
      let len = 0;
      for (const [field, weight] of Object.entries(FIELDS)) {
        for (const term of tokenize(fields[field])) {
          tf.set(term, (tf.get(term) || 0) + weight);
          len += weight;
        }
      }
      this.docLen[i] = len;
      this.docTerms[i] = tf;
      total += len;
      for (const [term, f] of tf) {
        let p = tmp.get(term);
        if (!p) tmp.set(term, (p = { docs: [], tf: [] }));
        p.docs.push(i);
        p.tf.push(f);
      }
    });
    for (const [term, p] of tmp) this.postings.set(term, { docs: Int32Array.from(p.docs), tf: Float32Array.from(p.tf) });
    this.avgLen = total / Math.max(1, this.N);
    this.position = new Map(reports.map((r, i) => [r, i]));
  }

  idf(term) {
    const df = this.postings.get(term)?.docs.length || 0;
    return Math.log(1 + (this.N - df + 0.5) / (df + 0.5));
  }

  // Query terms with weights: the words typed (1.0) and their expansions (0.4).
  parseQuery(query) {
    const weights = new Map();
    const add = (term, w) => weights.set(term, Math.max(weights.get(term) || 0, w));
    const typed = tokenize(query);
    for (const t of typed) add(t, 1);
    for (const raw of fold(query).split(/[^a-z0-9]+/)) {
      const syn = SYNONYMS[raw];
      if (syn) for (const t of tokenize(syn)) add(t, 0.4);
    }
    return { weights, typed: new Set(typed) };
  }

  // Scores every document. Returns Float32Array of scores (0 = no match).
  score({ weights, typed }, phrase) {
    const scores = new Float32Array(this.N);
    const hits = new Uint8Array(this.N);
    for (const [term, qw] of weights) {
      const p = this.postings.get(term);
      if (!p) continue;
      const idf = this.idf(term);
      const isTyped = typed.has(term);
      for (let k = 0; k < p.docs.length; k++) {
        const d = p.docs[k];
        const f = p.tf[k];
        scores[d] += qw * idf * (f * (K1 + 1)) / (f + K1 * (1 - B + B * (this.docLen[d] / this.avgLen)));
        if (isTyped) hits[d]++;
      }
    }
    const nTyped = typed.size || 1;
    const needle = phrase && phrase.length > 3 ? fold(phrase) : null;
    for (let d = 0; d < this.N; d++) {
      if (!scores[d]) continue;
      // Reward documents that contain more of the words actually typed, and exact phrases in the title.
      scores[d] *= 0.6 + 0.4 * (hits[d] / nTyped);
      if (needle && fold(this.reports[d].title).includes(needle)) scores[d] *= 1.5;
      // A gentle nudge toward reports the community found useful.
      scores[d] *= 1 + 0.03 * Math.log1p(this.reports[d].votes);
    }
    return scores;
  }

  search(query) {
    return this.score(this.parseQuery(query), query.trim());
  }

  // "More like this": the report's most distinctive terms become the query.
  similar(report, terms = 14) {
    const i = this.position.get(report);
    const ranked = [...this.docTerms[i]]
      .map(([term, f]) => [term, f * this.idf(term)])
      .sort((a, b) => b[1] - a[1])
      .slice(0, terms);
    const weights = new Map(ranked.map(([term, w], k) => [term, 1 - k / (terms * 2)]));
    const scores = this.score({ weights, typed: new Set(weights.keys()) }, null);
    scores[i] = 0;
    return scores;
  }
}
