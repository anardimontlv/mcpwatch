# FAQ

### Does mcpwatch upload my config?

No. `scan` makes no network requests at all. `lock` and `check` only download public index files (`m/XX.json` and
`d/XX.json`, where `XX` is a 2-character shard ID). Your config, lock file, server names, URLs and environment
variables are never sent. The index host does see your IP address and which shards you requested. Details:
[how-it-works.md](how-it-works.md#privacy-of-lookups).

### Does it run MCP servers?

No. The CLI never launches a command from your config and never connects to a configured URL.

The public indexer contacts remote servers from the official registry, and only with three read-only messages:
`initialize`, `notifications/initialized`, `tools/list`. It never calls a tool, never sends credentials, and never
installs or runs package-based servers.

### How is this different from scanners that execute servers?

Scanners that install and start a server can see every tool it exposes, including package-based servers. They
also run third-party code on your machine or CI to do it.

mcpwatch does not run third-party code. The trade-off: for package-based servers it has no tool list, so no
fingerprints and no tool-change detection. It covers remote servers that publish their tools without auth, plus
static config checks for everything. See
[how-it-works.md](how-it-works.md#what-we-cannot-see).

If you already have a `tools/list` result from a server you trust to start, you can scan it with
`python3 -m mcpwatch.scan --tools tools.json`.

### Which servers can `check` protect?

Servers that were fingerprinted when you ran `lock`: the `lock` output says "N with tool fingerprints". Others
are still checked for grade, auth and identity changes if they are in the index, or skipped if they are
`not pinned`.

### What about private or internal servers?

They are not in the public index, so `lock` reports them as `not pinned` and `check` skips them silently. `scan`
works on them like on any other server, since it only reads your config.

For tool-level checks on a private server, save its `tools/list` result yourself and scan it with `--tools`.
There is no drift detection for private servers in the open-source CLI.

### What if a grade is wrong?

Every server page on the index has a "dispute any finding" link. It opens a GitHub issue in this repository with
the `dispute` label and the server's name in the title. Include the rule ID and why the finding does not apply.
Each rule's known false positives are listed in [rules.md](rules.md). Grades are recalculated every day, so a
fixed server gets a new grade on the next run.

### Why does `scan` exit 0 when it found high-severity problems?

The CLI fails only when you pass `--fail-on`. The GitHub Action passes `--fail-on high` by default.

### Are there rate limits?

The CLI does not use an API key and has no quota. It downloads static files, at most two per distinct shard per
run, and caches them for the run. The hosting provider may throttle abusive traffic. The index changes once a
day, so running `check` more often does not give newer data.

### Can I use it offline or in an air-gapped network?

- `scan`: yes, fully offline.
- `lock` and `check`: need the index. Mirror the static `d/` and `m/` directories to an internal HTTP server and
  set `MCPWATCH_URL` to it. If the index cannot be reached, `check` exits 2. It never passes without data.

### Why did `check` fail with `stale` when nothing changed?

A pinned server's tools were last verified more than `--max-stale` days ago (default 3). This happens when the
server is down, blocks the indexer, or the index itself was not updated. It is deliberate: a server that hides
from the indexer must not keep passing on old fingerprints. Raise the threshold with `--max-stale N` if you accept
the risk. The GitHub Action uses the default of 3.

### How do I accept a change after reviewing it?

Run `lock` again and commit the new `mcpwatch.lock`, ideally through a pull request so the change is reviewed.
A workflow for this is in [github-action.md](github-action.md#recipe-3-refresh-the-lock-file-on-purpose).

### Does it work on Windows?

The CLI is plain Python and reads Windows config paths (`$env:APPDATA\Claude\claude_desktop_config.json`,
`$env:USERPROFILE\.cursor\mcp.json`). Two caveats:

- Servers started as `cmd /c npx ...` are reported by MW008 and cannot be matched to the index by `lock`.
- The GitHub Action is tested on `ubuntu-latest`.

### Which config formats are supported?

Strict JSON files with servers under `mcpServers` (Claude Desktop, Claude Code, Cursor), `servers` (VS Code
`mcp.json`) or `mcp.servers` (VS Code settings). Files with comments or trailing commas are rejected with exit
code 2.

### What does the tool fingerprint cover?

The tool's description and full input schema. It does not cover title, annotations, output schema, server
instructions, prompts or resources. See [how-it-works.md](how-it-works.md#3-fingerprints).

### Is a grade A server safe?

Not necessarily. A grade summarizes automated checks on configuration, metadata and published tool text. Code is
not reviewed, and package-based servers' tools are not seen at all. Treat the grade as one input, not an
approval.
