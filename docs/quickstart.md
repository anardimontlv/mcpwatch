# Quickstart: scan, lock, check

Three steps, about two minutes:

1. **scan** your MCP config for risky setups. Runs offline.
2. **lock** the tool fingerprints your servers expose today into `mcpwatch.lock`.
3. **check** later. It fails when any pinned tool changes.

Requirements: Python 3.10 or later. No packages to install. `lock` and `check` need HTTPS access to the public index.

## 1. Get the code

macOS / Linux:

```bash
git clone https://github.com/anardimontlv/mcpwatch ~/mcpwatch
export PYTHONPATH=~/mcpwatch
```

Windows (PowerShell):

```powershell
git clone https://github.com/anardimontlv/mcpwatch $HOME\mcpwatch
$env:PYTHONPATH = "$HOME\mcpwatch"
```

With `PYTHONPATH` set you can run the commands from your own project folder. That matters for `lock`: it
writes `mcpwatch.lock` to the current directory unless you pass `--lock PATH`.

On Windows, use `python` or `py` where this page says `python3`.

## 2. Find your config

| Client | macOS / Linux | Windows (PowerShell) |
|---|---|---|
| Claude Code (project) | `.mcp.json` in the project root | `.mcp.json` in the project root |
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) | `$env:APPDATA\Claude\claude_desktop_config.json` |
| Cursor (global) | `~/.cursor/mcp.json` | `$env:USERPROFILE\.cursor\mcp.json` |
| Cursor (project) | `.cursor/mcp.json` | `.cursor\mcp.json` |
| VS Code (workspace) | `.vscode/mcp.json` | `.vscode\mcp.json` |

mcpwatch reads servers from the first of these keys it finds: `mcpServers`, `servers`, `mcp.servers`.

The file must be strict JSON. Comments or trailing commas (allowed in some VS Code files) make mcpwatch exit with
code 2: `mcpwatch: cannot read input: Expecting property name enclosed in double quotes ...`.

## 3. Scan

The examples below use this sample config, saved as `mcp.json`:

```json
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": { "GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789" }
    },
    "files": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem@2025.8.21", "/"]
    },
    "deepwiki": { "url": "https://mcp.deepwiki.com/mcp" }
  }
}
```

```bash
python3 -m mcpwatch.scan mcp.json
```

```powershell
python -m mcpwatch.scan "$env:APPDATA\Claude\claude_desktop_config.json"
```

Captured output:

```
mcpwatch grade D (49/100) across 3 server(s), 4 finding(s)
  [HIGH    ] MW001 github: Plaintext secret in env GITHUB_PERSONAL_ACCESS_TOKEN (ghp_…[40 chars]). Use an env reference or a secret store.
  [HIGH    ] MW006 files: Server is granted the filesystem root or a whole home directory. Scope it to a project folder.
  [MEDIUM  ] MW002 github: Unpinned package '@modelcontextprotocol/server-github' via npx: every launch runs whatever the registry serves. Pin a version.
  [LOW     ] MW005 deepwiki: Remote server configured without auth headers. Fine if it uses OAuth; otherwise anyone with the URL can call it.
```

Secrets are redacted in output: only the first 4 characters and the length are printed.

By default `scan` exits 0 even when it finds problems. To fail a script or CI job, add `--fail-on`:

```bash
python3 -m mcpwatch.scan mcp.json --fail-on high; echo "exit=$?"
# ... same findings ...
# exit=1
```

Other options:

| Option | Effect |
|---|---|
| `--format text\|json\|md` | Output format. Default `text`. `md` is a Markdown table (used by the GitHub Action). |
| `--fail-on low\|medium\|high\|critical` | Exit 1 if any finding is at or above this severity. |
| `--tools TOOLS.json` | Also scan a saved `tools/list` result (`{"tools": [...]}` or a bare list) for rules MW101 to MW103. |
| `--badge out.svg` | Write an SVG grade badge. |

What each finding means and how to fix it: [rules.md](rules.md).

## 4. Lock

```bash
python3 -m mcpwatch.watch lock mcp.json
```

`lock` looks each server up in the public index and writes its tool fingerprints, auth status, grade and
package versions to `mcpwatch.lock`. Commit that file.

Output below was captured against a local test copy of the index (see the note at the end of this page),
in which `deepwiki` is a remote server with two fingerprinted tools and `github` is a package server:

```
mcpwatch: locked 3 server(s) to mcpwatch.lock; 1 with tool fingerprints
  not pinned: files: not in the public index (private or local server)
```

What the result tells you:

- **with tool fingerprints**: remote servers whose `tools/list` the indexer could read without credentials.
  These are the servers `check` can protect against tool changes.
- **locked without fingerprints**: servers found in the index but whose tools are not public (package servers,
  servers that require auth). `check` still watches their grade, auth status and identity.
- **not pinned**: servers the index has no entry for, or whose lookup key is claimed by more than one registry
  entry. `check` skips them. See [faq.md](faq.md#what-about-private-or-internal-servers).

A lock entry looks like this:

```json
"deepwiki": {
  "a": "open",
  "g": "A",
  "h": { "ask_question": "ea6472274849", "read_wiki_structure": "b171c1beb87b" },
  "name": "example.deepwiki/mcp",
  "p": {},
  "slug": "example-deepwiki-mcp-d5de452c",
  "vd": "2026-11-22"
}
```

`h` is one fingerprint per tool, `a` the auth status, `g` the grade, `p` package versions and `vd` the last date
the tools were observed live.

## 5. Check

```bash
python3 -m mcpwatch.watch check mcp.json; echo "exit=$?"
```

No change:

```
mcpwatch: no drift across 3 server(s)
exit=0
```

After the `ask_question` tool's description changed in the index:

```
  [HIGH    ] deepwiki: tool_changed ask_question
  [MEDIUM  ] deepwiki: grade_changed A -> F
mcpwatch: DRIFT DETECTED across 3 server(s)
exit=1
```

If the index cannot be reached, `check` fails closed:

```
mcpwatch: cannot reach the index at https://www.mcpwatch.io: <urlopen error [Errno 8] nodename nor servname provided, or not known>
exit=2
```

Exit codes for `lock` and `check`: `0` no drift, `1` drift, `2` bad input or index unreachable. The full list of
drift kinds is in [how-it-works.md](how-it-works.md#what-check-reports).

Options:

| Option | Default | Effect |
|---|---|---|
| `--lock PATH` | `mcpwatch.lock` | Lock file to write (`lock`) or compare against (`check`). |
| `--max-stale N` | `3` | `check` only. Report drift if a pinned server's tools were last verified more than N days ago. |
| `MCPWATCH_URL` env var | `https://www.mcpwatch.io` | Index base URL. Use it to point at a mirror. |

## Next

- Run it on every PR and every day: [github-action.md](github-action.md)
- How fingerprints and grades are produced: [how-it-works.md](how-it-works.md)

---

**Note on the captured `lock`/`check` output.** When this page was written, `https://www.mcpwatch.io` did not
resolve from the test machine, and the fallback deployment (`https://agentguard-pi.vercel.app`) served an older
index without the lookup shards `lock` needs, so every server came back `not pinned`. The `scan` output and the
"index unreachable" output above are from the real tools against the real network. The `lock` and `check` outputs
are from the real CLI run against a local HTTP copy of the index with two hand-built records (`MCPWATCH_URL` set
to that copy). The server names, slugs and hashes in them are test data, not live index data.
