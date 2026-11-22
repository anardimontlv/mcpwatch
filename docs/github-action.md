# GitHub Action

The action `anardimontlv/mcpwatch` has two modes:

- `scan`: static checks on your MCP config. Use it on pull requests.
- `check`: compares the config against `mcpwatch.lock` using the public index. Use it on a schedule.

It is a composite action. It runs `python3` from the runner, so use `ubuntu-latest` (or any runner with
Python 3.10+ and bash). It installs nothing.

## Inputs

| Input | Default | Used in | Meaning |
|---|---|---|---|
| `config` | `.mcp.json` | both | Path to the MCP config, relative to the workspace. |
| `mode` | `scan` | both | `scan` or `check`. Any other value fails the step with exit 2. |
| `lock` | `mcpwatch.lock` | `check` | Lock file to compare against. |
| `fail-on` | `high` | `scan` | Fail at this severity or above: `low`, `medium`, `high`, `critical`. |

`check` mode does not expose `--max-stale`; it uses the CLI default of 3 days.

The examples below use `@main`, as the README does. For a security control, pin the action to a full commit SHA
instead, so a change to this repository cannot change what runs in your CI.

## Recipe 1: scan on every pull request

`.github/workflows/mcpwatch-scan.yml`:

```yaml
name: mcpwatch scan
on:
  pull_request:
    paths: [".mcp.json"]
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: anardimontlv/mcpwatch@main
        with:
          config: .mcp.json
          fail-on: high
```

This needs no network access beyond checkout. The config is read on the runner; nothing is sent anywhere.

Remove the `paths` filter if you also want the scan to run when other files change.

## Recipe 2: daily drift check

Requires a committed `mcpwatch.lock` (see [quickstart.md](quickstart.md#4-lock) or Recipe 3).

`.github/workflows/mcpwatch-drift.yml`:

```yaml
name: mcpwatch drift
on:
  schedule: [{ cron: "0 6 * * *" }]
  workflow_dispatch:
permissions:
  contents: read
jobs:
  drift:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: anardimontlv/mcpwatch@main
        with:
          mode: check
          config: .mcp.json
          lock: mcpwatch.lock
```

The public index is rebuilt once a day (cron `17 4 * * *`, UTC). Running `check` more than once a day does not
give fresher data.

A failed scheduled run notifies the user who last edited the workflow's cron, through GitHub's normal
notification settings. Route it elsewhere (Slack, email) with your own step after this one, guarded by
`if: failure()`.

## Recipe 3: refresh the lock file on purpose

When a drift is expected (you upgraded a server, or you reviewed a tool change and accept it), refresh the lock
through a pull request, so the new fingerprints get a human review.

The action has no `lock` mode, so this workflow checks out mcpwatch and runs the CLI directly. It runs it with
`python3 -I` and an explicit path, like the action does, so a `mcpwatch/` folder in your repository cannot replace
the real code.

`.github/workflows/mcpwatch-relock.yml`:

```yaml
name: mcpwatch relock
on:
  workflow_dispatch:
permissions:
  contents: write
  pull-requests: write
jobs:
  relock:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/checkout@v4
        with:
          repository: anardimontlv/mcpwatch
          ref: main            # pin to a commit SHA in production
          path: .mcpwatch
      - name: Refresh mcpwatch.lock
        run: |
          python3 -I -c 'import sys; sys.path.insert(0, sys.argv[1]); from mcpwatch.watch import main; sys.exit(main(sys.argv[2:]))' \
            .mcpwatch lock .mcp.json --lock mcpwatch.lock | tee -a "$GITHUB_STEP_SUMMARY"
          rm -rf .mcpwatch
      - uses: peter-evans/create-pull-request@v7
        with:
          add-paths: mcpwatch.lock
          branch: mcpwatch/relock
          commit-message: "Refresh mcpwatch.lock"
          title: "Refresh mcpwatch.lock"
          body: |
            Refreshed tool fingerprints from the public mcpwatch index.
            Review every changed hash under "h" before merging: each one is a tool whose description or input schema changed.
```

Notes:

- The repository setting **Settings > Actions > General > Allow GitHub Actions to create and approve pull requests**
  must be on, or the last step fails.
- Pull requests opened with the default `GITHUB_TOKEN` do not trigger other workflows. If you want the scan in
  Recipe 1 to run on this PR, use a GitHub App token or a fine-grained PAT for `create-pull-request`.
- `lock` exits 0 even when some servers are `not pinned`. Read the step summary to see which ones.
- `lock` exits 2 if the index is unreachable. No PR is opened in that case.

## Exit codes

| Mode | 0 | 1 | 2 |
|---|---|---|---|
| `scan` | No finding at or above `fail-on` | At least one finding at or above `fail-on` | Config unreadable, not JSON, or no servers found |
| `check` | No drift | Drift (see below) | Config or lock file unreadable, no servers, or index unreachable |

The step uses bash with `pipefail`, so piping output to the step summary does not hide the exit code.

What counts as drift in `check` (any of these fails the step):

| Output tag | Kind | Severity |
|---|---|---|
| `[HIGH    ]` | `tool_changed` (description or input schema), `auth_dropped`, server `gone` from the index, `reassigned` to a different registry entry | high |
| `[MEDIUM  ]` | `tool_added`, `tool_removed`, `grade_changed`, `auth_added`, `fingerprints_lost`, `stale` | medium |
| `[NEW     ]` | A server in the config that is not in the lock file | counts as drift |
| `[LOW     ]` | `package_changed` (registry package version changed) | printed, **does not fail** |

A server removed from the config is not reported. Servers that were `not pinned` at lock time are skipped.

## Step summary

Both modes append their output to the job's step summary (`$GITHUB_STEP_SUMMARY`) as well as the log.

- `scan` writes a Markdown table: a heading with the grade and score, then one row per finding
  (Severity, Rule, Server, Finding). Server names and messages come from your config, so Markdown and HTML
  characters in them are escaped.
- `check` writes the plain-text CLI output, indented by four spaces so it renders as a code block. Server names
  from the config cannot inject Markdown this way.

Example `scan` summary for the sample config in [quickstart.md](quickstart.md):

```markdown
## mcpwatch: grade D (49/100), 3 server(s)

| Severity | Rule | Server | Finding |
|---|---|---|---|
| high | MW001 | github | Plaintext secret in env GITHUB\_PERSONAL\_ACCESS\_TOKEN (ghp\_…\[40 chars\]). Use an env reference or a secret store. |
| high | MW006 | files | Server is granted the filesystem root or a whole home directory. Scope it to a project folder. |
| medium | MW002 | github | Unpinned package '@modelcontextprotocol/server-github' via npx: every launch runs whatever the registry serves. Pin a version. |
| low | MW005 | deepwiki | Remote server configured without auth headers. Fine if it uses OAuth; otherwise anyone with the URL can call it. |
```

## Permissions

| Recipe | Permissions | Network |
|---|---|---|
| Scan on PR | `contents: read` | None beyond checkout |
| Daily drift check | `contents: read` | HTTPS GET to the index (`https://www.mcpwatch.io` by default) |
| Relock PR | `contents: write`, `pull-requests: write` | Index, plus GitHub to open the PR |

The action never needs secrets. It does not send your config, the lock file or repository data anywhere. In
`check` mode it downloads public index shards only (see [how-it-works.md](how-it-works.md#privacy-of-lookups)).

## Using a mirror of the index

`check` reads the index base URL from the `MCPWATCH_URL` environment variable. Set it at job level to use a
mirror (for example, an internal copy of the static `d/` and `m/` files):

```yaml
jobs:
  drift:
    runs-on: ubuntu-latest
    env:
      MCPWATCH_URL: https://mcpwatch-mirror.internal.example
```
