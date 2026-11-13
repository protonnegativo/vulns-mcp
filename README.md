# vulns-mcp

[![npm](https://img.shields.io/npm/v/vulns-mcp)](https://www.npmjs.com/package/vulns-mcp)

**Give your AI agent the bug bounty archive.** An [MCP](https://modelcontextprotocol.io) server that lets Claude, Cursor and any other MCP client search **13,636 publicly disclosed bug bounty reports from HackerOne and Bugcrowd**: real bugs, found by real researchers, in real programs, with the write-ups that explain how.

Part of [Vulns](https://vulns.today), which tracks what got hacked today, and how.

```text
you   ▸ How have people exploited SSRF through webhooks? Show me the payloads that worked.

agent ▸ search_reports(query: "ssrf webhook", sort: "votes")
        get_report(id: 2301565)
        find_similar(id: 2301565)

      ◂ Three patterns show up again and again. The HackerOne webhook bug (#2301565, $2,500)
        got around the deny-list with an IPv4-mapped IPv6 address and reached the EC2
        metadata service…
```

- **Search that knows security.** BM25 full-text search over titles, weaknesses, bug classes, programs and summaries. Acronyms are expanded, so `sqli` finds "SQL injection" and `ato` finds "account takeover". Filter by platform, class, severity, program, CWE, topic, CVE, date, bounty and CVSS.
- **The full text when you need it.** `get_report` pulls the original write-up from hackerone.com (steps to reproduce, requests, payloads and impact), or the researcher's complete disclosure summary from bugcrowd.com. Long texts come back in pages.
- **A playbook for each bug class.** Each guide covers what the bug is, where to look, how to test and how it gets fixed. It adds the archive's numbers for that class and its most upvoted real reports.
- **Fast and local.** The index ships with the package and loads in about a second. Your searches never leave your machine.

## Install

You need Node.js 18 or newer. `npx` downloads [the package from npm](https://www.npmjs.com/package/vulns-mcp), so there's nothing else to set up. The first start takes a little longer while it downloads; after that it runs from npx's cache.

### Claude Code

```bash
claude mcp add vulns -- npx -y vulns-mcp
```

Add `--scope user` to make it available in every project.

### Claude Desktop

Open **Settings → Developer → Edit Config**. Then add the server to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "vulns": {
      "command": "npx",
      "args": ["-y", "vulns-mcp"]
    }
  }
}
```

Restart Claude Desktop after saving.

### Cursor

Add this to `~/.cursor/mcp.json`, or to `.cursor/mcp.json` to use it in one project:

```json
{
  "mcpServers": {
    "vulns": {
      "command": "npx",
      "args": ["-y", "vulns-mcp"]
    }
  }
}
```

### VS Code

Add this to `.vscode/mcp.json`:

```json
{
  "servers": {
    "vulns": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "vulns-mcp"]
    }
  }
}
```

### From source

```bash
git clone https://github.com/protonnegativo/vulns-mcp.git
```

```bash
cd vulns-mcp && npm install
```

Then point your client at `node` with the absolute path to `src/index.js`. In Claude Code, for example:

```bash
claude mcp add vulns -- node /absolute/path/to/vulns-mcp/src/index.js
```

## Tools

| Tool | What it does |
| --- | --- |
| `search_reports` | Full-text search across both platforms, with filters. Filters: `platform` (`hackerone` or `bugcrowd`), `category`, `severity`, `program`, `weakness` (CWE id or name), `topic`, `cve`, `reporter`, `disclosed_after` / `disclosed_before`, `min_bounty`, `min_cvss`, `state`, `has_summary`. Sort by relevance, newest, oldest, votes, bounty or CVSS, and page through results. With no query it lists the latest disclosures. |
| `get_report` | One report, by id or URL. For HackerOne: metadata, the Hacktivity summary, the program and researcher summaries, and the full original write-up fetched live from hackerone.com. For Bugcrowd: metadata and the researcher's complete disclosure summary fetched live from bugcrowd.com (Bugcrowd doesn't publish the original submission). The text is paged with `offset`, and the size of each page is set with `max_chars`. |
| `find_similar` | Reports that resemble a given one, ranked by its most distinctive terms. Use it to find variations, fix bypasses and the same pattern in other programs. |
| `list_categories` | The bug classes, with counts, share of critical/high findings and a one-line description, plus the cross-cutting topics. |
| `get_category_guide` | A playbook for one class: what it is, its impact, where to look, how to test, how it gets fixed and references. Also gives the class's severity mix, common CWEs, programs, bounties and its most upvoted and best-paid reports. |
| `get_program` | A HackerOne or Bugcrowd program's history: number of reports, severity mix, the classes it gets hit by most, bounties, top researchers, and its most upvoted and latest disclosures. |
| `archive_stats` | Overview of the whole archive: reports per platform, how fresh the data is, reports per year, top classes, programs and researchers, and the latest disclosures. |

HackerOne reports have numeric ids (`1628209`); Bugcrowd reports have ids like `bc-495cc609bd`. Every result carries the report's own link, `https://hackerone.com/reports/<id>` or its `https://bugcrowd.com/disclosures/…` page, so answers can cite their sources. All tools are read-only.

Bugcrowd doesn't publish a weakness, CWE, CVE, CVSS score or votes for its disclosures. Filters and sorts on those fields only match HackerOne reports. Bugcrowd's class comes from the title, and its severity from the P1–P5 priority: P1 is critical, P5 is none.

### Prompts to try

- *What are the most common ways people bypassed SSRF protections? Cite the reports.*
- *I'm testing a GraphQL API. Which bugs have been found in GraphQL endpoints, and how were they found?*
- *Summarize GitLab's disclosed critical reports and what they have in common.*
- *Find request smuggling reports with a bounty over $5,000 and explain the techniques.*
- *Walk me through how OAuth `redirect_uri` bugs lead to account takeover, with real examples.*
- *What has been disclosed on Bugcrowd for NASA, and which bug classes keep coming up?*
- *What was disclosed this week?*

## How it works

```text
              ┌── reports.json ──┐  12,754 HackerOne reports: title, program, weakness,
  bundled ───▶│   summaries/     │  class, severity, CVSS, bounty, votes, dates, CVEs,
  snapshot    │   bugcrowd.json  │  topics, summary · 882 Bugcrowd disclosures ·
              │   taxonomy.json  │  bug-class guides
              └────────┬─────────┘
  vulns.today/data ────┘  refreshed in the background every 6 h, cached on disk
                       │
                       ▼
             BM25 index in memory ──▶ search_reports, find_similar, guides, stats
                                                   │
                                                   ▼ get_report, on demand
             hackerone.com/reports/<id>.json  ·  bugcrowd.com/disclosures/<id>/…
```

- **Startup.** The server loads the freshest copy it already has: the on-disk cache or the snapshot bundled in the package. It answers right away, then checks `vulns.today` for newer data in the background. If the network is slow or down, it keeps working with what it has.
- **Ranking.** BM25 with field weights: title ×3, CVE ×3, weakness and class ×2, topics and program ×1.5, summary ×1. Reports that contain more of the query's words rank higher, and so do exact title matches. Community votes give a small extra push.
- **Full text.** The archive stores the index and the summaries, not the full texts. `get_report` fetches them live: the write-up from the report's public JSON on hackerone.com, or the summary from the public disclosure page on bugcrowd.com. It keeps the last 100 of each in memory.

## Configuration

| Option | Default | Meaning |
| --- | --- | --- |
| `--data-dir <folder>` / `VULNS_DATA_DIR` | — | Read `reports.json`, `taxonomy.json`, `summaries/` and `bugcrowd.json` from a local folder, and never refresh. |
| `--offline` / `VULNS_OFFLINE=1` | off | Never check the network for archive updates. |
| `VULNS_DATA_URL` | `https://vulns.today/data` | Where to refresh the archive from. |
| `VULNS_CACHE_DIR` | `~/.cache/vulns-mcp` | Where refreshed data is stored. |
| `VULNS_FULL_TEXT=0` | on | Don't let `get_report` contact hackerone.com or bugcrowd.com. You still get the metadata and summaries. |

To pass an option in Claude Code, add it after the command: `claude mcp add vulns -- npx -y vulns-mcp --offline`. To set a variable, use `-e`: `claude mcp add vulns -e VULNS_FULL_TEXT=0 -- npx -y vulns-mcp`.

## Privacy and safety

- **Your searches stay local.** The server sends no telemetry. It makes only two kinds of request: the archive refresh from `VULNS_DATA_URL`, and a `GET` for the report's public page on hackerone.com or bugcrowd.com when an agent reads a report. Your queries and conversation are never sent anywhere.
- **Write-ups are untrusted text.** Reports are written by third parties and can contain anything, prompt injection included. `get_report` puts each write-up between `<<<WRITEUP` / `WRITEUP>>>` markers and labels it as data. The server's instructions tell the agent never to follow text found in a report.
- **Use it for good.** This is the public record of bugs that have been fixed and disclosed. Use it for authorized testing, research, learning and defense. Only test systems you have permission to test, and stay within each program's policy.

## Data and credit

The reports belong to the researchers who wrote them and to the programs that disclosed them on [HackerOne Hacktivity](https://hackerone.com/hacktivity) and [Bugcrowd's CrowdStream](https://bugcrowd.com/crowdstream). This package redistributes only the public index: titles, metadata, Hacktivity summaries and the start of each Bugcrowd summary. Full texts are read live from hackerone.com and bugcrowd.com, and every answer links back to the original report.

Data last fetched **2026-11-13**.

## Development

```bash
npm test
```

```bash
npm run test:network
```

```bash
npm run inspect
```

`npm test` starts the real server over stdio and checks every tool through the MCP client SDK. `npm run test:network` also runs the live HackerOne and Bugcrowd fetches. `npm run inspect` opens the [MCP Inspector](https://github.com/modelcontextprotocol/inspector).

To refresh the bundled snapshot from a build of the Vulns site, run:

```bash
npm run sync-data -- ../vulns.today/site/data
```

The layout:

```text
src/index.js      entry point: options, stdio transport, background refresh
src/data.js       loading, caching and decoding the archive
src/search.js     tokenizer, synonyms and the BM25 index
src/tools.js      the MCP tools and how their output reads
src/hackerone.js  on-demand full-text fetch from hackerone.com
src/bugcrowd.js   on-demand disclosure summary from bugcrowd.com
data/             bundled snapshot
test/             end-to-end tests over stdio
```

## Roadmap

- [x] Publish to npm
- [x] Bugcrowd disclosures next to HackerOne
- [ ] Remote server over Streamable HTTP, so nothing needs installing
- [ ] Semantic search with embeddings, next to BM25
- [ ] A "today" tool for the latest disclosures, plus a daily data refresh

## License

[MIT](LICENSE) for the code. The report content belongs to its authors; see [Data and credit](#data-and-credit).
