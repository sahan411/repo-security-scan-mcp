# repo-security-scan-mcp

An [MCP](https://modelcontextprotocol.io) server that lets Claude (or any MCP client) triage a **local** project for the classic security problems in AI-built web apps (Next.js, Vite, Express, Supabase, Firebase and similar).

It reads a folder you point it at. It never opens network connections and never probes live sites. Secrets in results are redacted to their first 4 characters.

## What it checks (20+ rule types)
Leaked secrets (AWS, Stripe, GitHub, OpenAI/Anthropic-style, Slack, SendGrid, private keys, database URLs with passwords, JWTs including Supabase `service_role`), secrets exposed to the browser through `NEXT_PUBLIC_`/`VITE_` variables, Supabase tables without row-level security, open Firebase rules, wildcard CORS, dangerous code patterns (`eval`, `dangerouslySetInnerHTML`, string-built SQL, shell injection), API routes that change data without a visible auth check, weak JWT secrets, weak password hashing, debug mode left on, TLS verification turned off, committed `.env` files, unpinned dependencies, missing lockfile and missing tests.

## Tools
| Tool | What it does |
|---|---|
| `scan_repo` | Scans a folder; returns counts and findings ordered by severity (`path`, `min_severity`, `limit`, `max_mb`). |
| `triage_summary` | Same scan, returned as a short plain-English go/no-go with what to fix first. |

## Install and use
Requires Node 18+ and Python 3.
```bash
git clone <this repo> && cd repo-security-scan-mcp
npm install
npm test
```
Add to Claude Desktop (`claude_desktop_config.json`) or Claude Code (`claude mcp add`):
```json
{ "mcpServers": { "repo-security-scan": { "command": "node", "args": ["/absolute/path/to/server.mjs"] } } }
```
Set `PYTHON` if your Python executable is not `python` (Windows) or `python3` (macOS/Linux).

Then ask: "Scan ./my-app and tell me what to fix before launch."

## Honest limits
This is a heuristic static scan, **not a penetration test**. It produces false positives and misses issues. Review each finding before acting, and rotate any exposed secret immediately. `npm test` runs a real MCP client against generated fixture apps (fake secrets are assembled at runtime so this repo never contains token-shaped strings): 7 checks, including "clean app has 0 HIGH findings".

## Need this on your project, or a custom MCP server for your tools?
Open an issue or message the author.

License: MIT
