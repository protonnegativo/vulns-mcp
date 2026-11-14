#!/usr/bin/env node
// Replaces the bundled snapshot (./data) with a fresh build of the Vulns site data.
//
// Usage: npm run sync-data -- <path to the site's data folder>
//        e.g. npm run sync-data -- ../vulns.today/site/data
//
// The folder must contain reports.json, taxonomy.json and summaries/<year>.json, plus
// bugcrowd.json and playbook/<file>.json when the site has them, as written by the site's
// `npm run build`.

import { readFile, writeFile, mkdir, rm, copyFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const OUT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'data');
const src = process.argv[2] || process.env.VULNS_DATA_DIR;
if (!src) {
  console.error('Usage: npm run sync-data -- <path to site/data>');
  process.exit(2);
}
const from = path.resolve(src);
for (const name of ['reports.json', 'taxonomy.json']) {
  if (!existsSync(path.join(from, name))) {
    console.error(`${path.join(from, name)} not found. Run the site's \`npm run build\` first.`);
    process.exit(1);
  }
}

const index = JSON.parse(await readFile(path.join(from, 'reports.json'), 'utf8'));
await rm(path.join(OUT, 'summaries'), { recursive: true, force: true });
await mkdir(path.join(OUT, 'summaries'), { recursive: true });
for (const year of index.meta.summaryYears || []) {
  await copyFile(path.join(from, 'summaries', `${year}.json`), path.join(OUT, 'summaries', `${year}.json`));
}
await rm(path.join(OUT, 'playbook'), { recursive: true, force: true });
if ((index.meta.playbookFiles || []).length) {
  await mkdir(path.join(OUT, 'playbook'), { recursive: true });
  for (const name of index.meta.playbookFiles) {
    await copyFile(path.join(from, 'playbook', `${name}.json`), path.join(OUT, 'playbook', `${name}.json`));
  }
}
await copyFile(path.join(from, 'taxonomy.json'), path.join(OUT, 'taxonomy.json'));
if (existsSync(path.join(from, 'bugcrowd.json'))) await copyFile(path.join(from, 'bugcrowd.json'), path.join(OUT, 'bugcrowd.json'));
else await rm(path.join(OUT, 'bugcrowd.json'), { force: true });
await writeFile(path.join(OUT, 'reports.json'), JSON.stringify(index));
const bugcrowd = existsSync(path.join(OUT, 'bugcrowd.json')) ? JSON.parse(await readFile(path.join(OUT, 'bugcrowd.json'), 'utf8')) : null;
console.log(`Bundled ${index.meta.count} HackerOne reports (fetched ${index.meta.fetchedAt})${bugcrowd ? ` and ${bugcrowd.rows.length} Bugcrowd reports (built ${bugcrowd.meta.generatedAt})` : ''} into ${OUT}`);
