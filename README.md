# mcpwatch

<!-- mcp-name: io.github.anardimontlv/mcpwatch -->

**Know when the tools your AI agents trust change.**

MCP servers can quietly rewrite a tool's description after you approved it (a "rug pull"), and that description is
read by your agent as instructions. mcpwatch checks every server in the official MCP registry daily, fingerprints
the tools of every publicly reachable remote server, grades each server, and fails your CI when something you pinned drifts.

- **Static and read-only.** It never runs third-party server code and never calls a tool.
- **Private by default.** Your config never leaves your machine; the CLI only downloads public index files.
- **Zero dependencies.** Python 3.10+ standard library.

Live index and rug-pull radar: **https://www.mcpwatch.io**

## Quickstart

```bash
pipx install mcpwatch-io      # or: pip install mcpwatch-io

# 1. Scan a config for risky setups (leaked secrets, unpinned packages, root filesystem access, plain HTTP, ...)
mcpwatch-scan ~/.cursor/mcp.json

# 2. In your project: pin the exact tools your servers expose today...
cd your-project
mcpwatch lock .mcp.json          # writes mcpwatch.lock: commit it

# 3. ...and fail when any of them changes
mcpwatch check .mcp.json         # exit 1 on drift, 2 if the index can't be reached
```

Or paste a config into the browser scanner at **https://www.mcpwatch.io/scan** (runs locally in your browser).
Tool fingerprints exist for remote servers we can reach without credentials; package-based servers are matched by
name and version, and their tools are not fingerprinted (we never run their code).

Works with Claude Desktop, Claude Code (`.mcp.json`), Cursor and VS Code configs.

## GitHub Action

Scan on every pull request:

```yaml
- uses: actions/checkout@v4
- uses: anardimontlv/mcpwatch-action@v1
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
      - uses: anardimontlv/mcpwatch-action@v1
        with: { mode: check, config: .mcp.json, lock: mcpwatch.lock }
```

## See exactly what changed, and block it at runtime

The public index stores only fingerprints. For servers you run yourself (or private ones), pin the tool text too:

```
mcpwatch lock .mcp.json --live    # launches each stdio server / calls each remote one and keeps the approved tool text
mcpwatch check .mcp.json --live   # fails on drift and prints a diff of the changed description or schema
```

Hidden characters are shown as `\u200b`-style escapes, so invisible instructions become visible in the diff.

`mcpwatch guard` sits in front of a stdio server and only lets your agent see the tools you approved. Changed or new
tools are removed from `tools/list`, and calls to them are refused before they reach the server:

```json
{ "mcpServers": { "github": {
    "command": "mcpwatch",
    "args": ["guard", "--name", "github", "--lock", "/path/to/mcpwatch.lock", "--", "npx", "-y", "@modelcontextprotocol/server-github"] } } }
```

Without an approved entry for `--name` the guard refuses to start. Re-run `mcpwatch lock --live` after you review a change.

## Lookup API

Is an MCP server in the index, and how does it grade? For registries, agent platforms and IDEs:

```
curl 'https://www.mcpwatch.io/api/v1/lookup?url=https://mcp.example.com/mcp'
curl 'https://www.mcpwatch.io/api/v1/lookup?package=npm:@scope/server'   # also pypi:name, oci:image, or ?id=<server id>
```

Returns the id, grade, score, auth status, last verified date and findings as rule codes, never third-party text, so
it is safe to hand to a model. 60 lookups/hour per IP; a Team report key (`Authorization: Bearer ...`) allows 5,000/hour.

## What `check` treats as drift

| Change | Severity |
|---|---|
| A pinned tool's description or input schema changed | high |
| Endpoint stopped requiring credentials | high |
| Server disappeared from the index, or its lookup now points elsewhere | high |
| Tool added or removed; grade changed | medium |
| Endpoint now requires credentials, or tools can no longer be verified | medium |
| Fingerprints older than `--max-stale` days (default 3): a server can't hide by blocking the indexer | medium |
| Server in the config but not in the lock file (`not_locked`) | medium |
| Package version changed; server newly indexed; server removed from config | low (reported, does not fail) |

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

Full rule reference: [docs/rules.md](docs/rules.md). Methodology: [docs/how-it-works.md](docs/how-it-works.md). MCP server for agents: [docs/mcp-server.md](docs/mcp-server.md).

Grades are automated signals, not audits. Maintainers can dispute a finding from the server's page.

## Plans

The scanner, the Action and the public index are free. Paid plans add email and Slack watchlist alerts (Pro) and, for
Team, shared seats, an org view of every repo with policy rules that fail CI (`mcpwatch report`), and audit export. See **https://www.mcpwatch.io/pricing**.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). The hosted index, radar and paid plans are a commercial service.
