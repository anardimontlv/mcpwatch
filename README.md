# mcpwatch

**Know when the tools your AI agents trust change.**

MCP servers can quietly rewrite a tool's description after you approved it (a "rug pull"), and that description is
read by your agent as instructions. mcpwatch fingerprints every tool of every server in the official MCP registry
daily, grades each server, and fails your CI when something you pinned drifts.

- **Static and read-only.** It never runs third-party server code and never calls a tool.
- **Private by default.** Your config never leaves your machine; the CLI only downloads public index files.
- **Zero dependencies.** Python 3.9+ standard library.

Live index and rug-pull radar: **https://www.mcpwatch.io**

## Quickstart

```bash
git clone https://github.com/anardimontlv/mcpwatch && cd mcpwatch

# 1. Scan a config for risky setups (leaked secrets, unpinned packages, root filesystem access, plain HTTP, ...)
python3 -m mcpwatch.scan ~/.cursor/mcp.json

# 2. Pin the exact tools your servers expose today...
python3 -m mcpwatch.watch lock .mcp.json          # writes mcpwatch.lock: commit it

# 3. ...and fail when any of them changes
python3 -m mcpwatch.watch check .mcp.json         # exit 1 on drift, 2 if the index can't be reached
```

Works with Claude Desktop, Claude Code (`.mcp.json`), Cursor and VS Code configs.

## GitHub Action

Scan on every pull request:

```yaml
- uses: actions/checkout@v4
- uses: anardimontlv/mcpwatch@main
  with: { config: .mcp.json, fail-on: high }
```

Check for drift every day (rug-pull radar for your repo):

```yaml
on: { schedule: [{ cron: "0 6 * * *" }] }
jobs:
  mcp-drift:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: anardimontlv/mcpwatch@main
        with: { mode: check, config: .mcp.json, lock: mcpwatch.lock }
```

## What `check` treats as drift

| Change | Severity |
|---|---|
| A pinned tool's description or input schema changed | high |
| Endpoint stopped requiring credentials | high |
| Server disappeared from the index, or its lookup now points elsewhere | high |
| Tool added or removed; grade changed | medium |
| Endpoint now requires credentials, or tools can no longer be verified | medium |
| Fingerprints older than `--max-stale` days (default 3): a server can't hide by blocking the indexer | medium |

## Scanner rules

| Rule | Finds |
|---|---|
| MW001 | Secrets in config: env, headers, args, URLs, connection strings |
| MW002 | Unpinned packages (`npx pkg`, `uvx pkg@latest`) |
| MW004 | Remote server over plain HTTP |
| MW005 | Remote server without auth |
| MW006 | Filesystem root or whole home directory granted |
| MW007 | Privileged containers, host mounts, Docker socket |
| MW008 | Inline shell launch, `curl \| sh` |
| MW009 | Flags that disable safety controls |
| MW101 | Tool poisoning: instructions aimed at the model in a tool description |
| MW102 | Tools that execute commands or delete data |
| MW103 | Invisible Unicode in tool text |

Grades are automated signals, not audits. Maintainers can dispute a finding from the server's page.

## Plans

The scanner, the Action and the public index are free. Paid plans add watchlist alerts (email/Slack), private-repo
drift checks and an org-wide view. See **https://www.mcpwatch.io/pricing**.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). The hosted index, radar and paid plans are a commercial service.
