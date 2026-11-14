# vulns-mcp

[![npm](https://img.shields.io/npm/v/vulns-mcp)](https://www.npmjs.com/package/vulns-mcp)

**Give your AI agent the bug bounty archive.** An [MCP](https://modelcontextprotocol.io) server that lets Claude, Grok, Codex, OpenCode, Cursor, Gemini and any other MCP client search **13,636 publicly disclosed bug bounty reports from HackerOne and Bugcrowd**: real bugs, found by real researchers, in real programs, with the write-ups that explain how.

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

### Grok (Grok Build)

```bash
grok mcp add vulns -- npx -y vulns-mcp
```

Add `--scope project` to write it to the repo's `.grok/config.toml` instead of your user config. If the first start times out while npx downloads the package, raise the server's `startup_timeout_sec`.

### Codex

```bash
codex mcp add vulns -- npx -y vulns-mcp
```

The Codex CLI and the IDE extension share the same config (`~/.codex/config.toml`), so this covers both.

### OpenCode

Add this to `opencode.json` in your project, or to `~/.config/opencode/opencode.json` for every project:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "vulns": {
      "type": "local",
      "command": ["npx", "-y", "vulns-mcp"],
      "enabled": true
    }
  }
}
```

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

### Gemini CLI

Add this to `~/.gemini/settings.json`, or to `.gemini/settings.json` to use it in one project:

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

### Windsurf

Add the same `mcpServers` block to `~/.codeium/windsurf/mcp_config.json` (**Settings → Cascade → MCP servers → View raw config**).

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

### Other apps

Any app that runs local MCP servers over stdio (Cline, Zed, Goose…) works: the command is `npx -y vulns-mcp`, and most of them take the `mcpServers` block above.

ChatGPT and grok.com connect only to MCP servers on the internet, by URL. vulns-mcp runs on your machine, so it doesn't work there yet; a hosted version is on the roadmap. (Grok Build, xAI's terminal app, works today: see above.)

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
| `search_reports` | Full-text search across both platforms, with filters. Filters: `platform` (`hackerone` or `bugcrowd`), `category`, `severity`, `program`, `weakness` (CWE id or name), `topic`, `cve`, `reporter`, `disclosed_after` / `disclosed_before`, `min_bounty`, `min_cvss`, `state`, `has_summary`, `technique` (e.g. `["dns-rebinding"]`) and `has` (what the write-up contains, e.g. `["payload"]`). Each result shows its techniques, the sentence that explains a bypass and a payload from the write-up, when there are. Sort by relevance, newest, oldest, votes, bounty or CVSS, and page through results. With no query it lists the latest disclosures. |
| `list_techniques` | The attack techniques reports are tagged with (89, from `dns-rebinding` and `cloud-metadata` to `csp-bypass`, `waf-bypass`, `race-condition` and `prototype-pollution`), grouped by kind: defense bypassed, encoding and evasion, technique, where it happens, impact. Each with how many reports have it and how many show a payload. Narrow it to a class or a query to see what shows up there, then search with `technique` and `has: ["payload"]`. |
| `get_report` | One report, by id or URL, with its techniques, payload snippets and bypass sentence. For HackerOne: metadata, the Hacktivity summary, the program and researcher summaries, and the full original write-up fetched live from hackerone.com. For Bugcrowd: metadata and the researcher's complete disclosure summary fetched live from bugcrowd.com (Bugcrowd doesn't publish the original submission). The text is paged with `offset`, and the size of each page is set with `max_chars`. |
| `find_similar` | Reports that resemble a given one, ranked by its most distinctive terms. Use it to find variations, fix bypasses and the same pattern in other programs. |
| `list_categories` | The bug classes, with counts, share of critical/high findings and a one-line description, plus the cross-cutting topics. |
| `get_category_guide` | A playbook for one class: what it is, its impact, where to look, how to test, how it gets fixed and references. Also gives the class's severity mix, common CWEs, programs, bounties and its most upvoted and best-paid reports. |
| `get_program` | A HackerOne or Bugcrowd program's history: number of reports, severity mix, the classes it gets hit by most, bounties, top researchers, and its most upvoted and latest disclosures. |
| `archive_stats` | Overview of the whole archive: reports per platform, how fresh the data is, reports per year, top classes, programs and researchers, and the latest disclosures. |

### Techniques and what each write-up contains

Every report is tagged by rules over its title, summaries and full write-up (no AI involved), so an agent can pick the reports worth reading:

- **`technique`**: 89 tags in five kinds. *Defense bypassed*: `filter-bypass`, `waf-bypass`, `csp-bypass`, `fix-bypass`, `2fa-bypass`… *Encoding and evasion*: `double-encoding`, `unicode-tricks`, `ip-obfuscation`, `null-byte`… *Technique*: `dns-rebinding`, `cloud-metadata`, `redirect-chain`, `ssti`, `blind-sqli`, `prototype-pollution`, `race-condition`… *Where it happens*: `webhook`, `pdf-renderer`, `graphql`, `oauth`… *Impact*: `account-takeover`, `privilege-escalation`.
- **`has`**: `payload` (the write-up shows one), `http-request`, `steps`, `poc-code`, `bypass`, `video`, `writeup` (the full write-up is public).
- Up to three **payload snippets** copied from the write-up, and the **sentence that explains the bypass**.

A typical flow: `list_techniques(category: "ssrf")` → `search_reports(category: "ssrf", technique: ["dns-rebinding"], has: ["payload"])` → `get_report` on the best ones to understand each scenario and decide what applies to your target. Tags are detected automatically: confirm in the report before relying on one.

HackerOne reports have numeric ids (`1628209`); Bugcrowd reports have ids like `bc-495cc609bd`. Every result carries the report's own link, `https://hackerone.com/reports/<id>` or its `https://bugcrowd.com/disclosures/…` page, so answers can cite their sources. All tools are read-only.

Bugcrowd doesn't publish a weakness, CWE, CVE, CVSS score or votes for its disclosures. Filters and sorts on those fields only match HackerOne reports. Bugcrowd's class comes from the title, and its severity from the P1–P5 priority: P1 is critical, P5 is none.

### Prompts to try

- *What are the most common ways people bypassed SSRF protections? Cite the reports.*
- *List the SSRF techniques in the archive, then show me DNS rebinding reports that include a payload.*
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
              │   playbook/      │  techniques, payload snippets, bypass sentences ·
              │   taxonomy.json  │  bug-class guides and the technique list
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
- **Ranking.** BM25 with field weights: title ×3, CVE ×3, weakness and class ×2, topics, program and techniques ×1.5, summary ×1. Reports that contain more of the query's words rank higher, and so do exact title matches. Community votes give a small extra push.
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
- [ ] Remote server over Streamable HTTP, so ChatGPT, Grok and other web apps can connect by URL and nothing needs installing
- [ ] Semantic search with embeddings, next to BM25
- [x] Daily data refresh
- [x] Technique tags, payload snippets and bypass sentences for every report
- [ ] A "today" tool for the latest disclosures

## License

[MIT](LICENSE) for the code. The report content belongs to its authors; see [Data and credit](#data-and-credit).
