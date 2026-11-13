// Reads the researcher's full summary of a Bugcrowd disclosure, on demand.
//
// Bugcrowd discloses a summary written by the researcher (not the original submission). The
// archive keeps the first ~700 characters; the whole text is on the public disclosure page
// (https://bugcrowd.com/disclosures/<uuid>/<slug>), inside <article><h5>Summary by …</h5>…</article>.

import { FetchError } from './hackerone.js';

const TIMEOUT_MS = 20_000;
const CACHE_SIZE = 100;
const cache = new Map();

const ENTITIES = { lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', amp: '&' };

function decodeEntities(s) {
  return s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e) => {
    if (e[0] === '#') {
      const code = e[1].toLowerCase() === 'x' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      return Number.isFinite(code) ? String.fromCodePoint(code) : m;
    }
    return ENTITIES[e.toLowerCase()] ?? m;
  });
}

// Plain text from the summary's HTML, keeping paragraphs, list items and code blocks readable.
function htmlToText(html) {
  return decodeEntities(html
    .replace(/<pre[^>]*>\s*(?:<code[^>]*>)?/gi, '\n```\n')
    .replace(/(?:<\/code>\s*)?<\/pre>/gi, '\n```\n')
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/(p|li|h\d|div|tr|blockquote)>/gi, '\n')
    .replace(/<li[^>]*>/gi, '- ')
    .replace(/<code[^>]*>/gi, '`').replace(/<\/code>/gi, '`')
    .replace(/<[^>]+>/g, ''))
    .replace(/[ \t]+\n/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

export function isDisclosureUrl(url) {
  try {
    const u = new URL(url);
    return u.protocol === 'https:' && u.hostname === 'bugcrowd.com' && u.pathname.startsWith('/disclosures/');
  } catch {
    return false;
  }
}

export async function fetchDisclosure(url) {
  if (!isDisclosureUrl(url)) throw new FetchError('not a bugcrowd.com disclosure URL');
  if (cache.has(url)) {
    const hit = cache.get(url);
    cache.delete(url);
    cache.set(url, hit);
    return hit;
  }
  let res;
  try {
    res = await fetch(url, {
      headers: { Accept: 'text/html', 'User-Agent': 'vulns-mcp' },
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  } catch (err) {
    throw new FetchError(err.name === 'TimeoutError' ? 'timed out' : err.message);
  }
  if (res.status === 406) throw new FetchError('HTTP 406: Bugcrowd\'s firewall blocks this page for automated clients');
  if (!res.ok) throw new FetchError(`HTTP ${res.status}`);
  const html = await res.text();
  const article = /<article>\s*<h5>\s*Summary by\s*([^<]*)<\/h5>([\s\S]*?)<\/article>/i.exec(html);
  const report = {
    url,
    author: article ? decodeEntities(article[1]).trim() : null,
    summary: article ? htmlToText(article[2]) : '',
    disclosedAt: /<time datetime="([^"]+)"/.exec(html)?.[1] || null,
  };
  cache.set(url, report);
  if (cache.size > CACHE_SIZE) cache.delete(cache.keys().next().value);
  return report;
}
