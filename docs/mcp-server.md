# mcpwatch MCP server

Lets your coding agent ask mcpwatch "is this MCP server safe, and has it changed?" before it connects.
Python 3.9+ standard library only. Transport: stdio. Protocol version 2025-06-18.

## Tools

| Tool | Input | Returns |
|------|-------|---------|
| `check_server` | `package` + `registry` (`npm`, `pypi`, `oci`), or `url` | grade, score, findings, auth status, last verified date, page URL; or `not_indexed` / `ambiguous` |
| `scan_config` | `config`: a client config as a JSON string | grade, score, findings from the local static scan |
| `check_drift` | `config` and `lock` (an `mcpwatch.lock`) as JSON strings, optional `max_stale_days` (default 3) | `drift` true/false, drift items, servers that cannot be verified |

Privacy: `scan_config` runs entirely locally. `check_server` and `check_drift` only download public index
shards (`/m/<2 hex>.json`, `/d/<2 hex>.json`), so the package name, URL, config and lock are never sent.
Fail closed: if the index cannot be reached, `check_server` and `check_drift` return an error
(`isError: true`), never "not indexed" or "no drift".

## Install

Run these from a checkout of this repository (or anywhere `mcpwatch` is importable).

### Claude Code

```sh
claude mcp add --transport stdio mcpwatch -- python3 -m mcpwatch.mcp_server
```

Add `--scope user` to use it in every project, or `--scope project` to share it via `.mcp.json`.
If you run Claude Code outside the checkout, put the checkout on `PYTHONPATH`:

```sh
claude mcp add --transport stdio --env PYTHONPATH=/path/to/checkout mcpwatch -- python3 -m mcpwatch.mcp_server
```

### Cursor (`~/.cursor/mcp.json` or `.cursor/mcp.json`) and Claude Desktop (`claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "mcpwatch": {
      "command": "python3",
      "args": ["-m", "mcpwatch.mcp_server"],
      "env": { "PYTHONPATH": "/path/to/checkout" }
    }
  }
}
```

Set `MCPWATCH_URL` in `env` to point at a mirror of the index (default `https://www.mcpwatch.io`).

## Drift checks

Create the lock once with the CLI, then let the agent run `check_drift` with the contents of your config
and `mcpwatch.lock`:

```sh
python3 -m mcpwatch.watch lock .mcp.json --lock mcpwatch.lock
```

## Try it by hand

```sh
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | python3 -m mcpwatch.mcp_server
```
