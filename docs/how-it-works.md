# How it works

This page describes what the public index does, what the CLI does, and what neither can see. It is written from
the code in this repository (`mcpwatch/index.py`, `mcpwatch/watch.py`, `mcpwatch/scan.py`). If this page and the
code disagree, the code is right and this page has a bug.

## Components

| Component | Runs where | Network |
|---|---|---|
| `mcpwatch.scan` (scanner) | Your machine or CI | None |
| `mcpwatch.watch lock` / `check` | Your machine or CI | HTTPS GET of public static index files |
| `mcpwatch.index` (indexer) | GitHub Actions in this repository, daily | Registry API, plus read-only probes of remote MCP endpoints |
| Public index | Static files on Vercel | Serves JSON shards and HTML pages |

## 1. Registry ingestion

- Source: the official MCP registry, `https://registry.modelcontextprotocol.io/v0/servers?limit=100&version=latest`,
  read page by page with the registry's cursor.
- Kept: entries whose registry status is `active` and that are marked as latest. One record per server name.
- Retries: up to 4 attempts per page on timeouts and connection errors, with exponential backoff.
- Schedule: once a day at 04:17 UTC (`.github/workflows/index.yml`), plus on pushes to `main` that touch the
  indexer, tests or site code. The test suite runs before every build.
- Publication guard: if a run produces 1,000 servers or fewer, it is not published. A broken registry fetch cannot
  wipe the public index.

Registry data is treated as untrusted input: non-list fields, non-dict items and missing values are skipped, not
trusted.

## 2. Probing remote servers

For each server, the indexer looks at up to 3 `remotes` from its registry entry. A remote is probed only if its URL
starts with `http` and contains no `{` (templated URLs are skipped).

### What is sent

Exactly three JSON-RPC messages, in order, over Streamable HTTP (POST):

1. `initialize` with protocol version `2025-06-18`, empty capabilities, client name `mcpwatch`.
2. `notifications/initialized`.
3. `tools/list`.

No tool is ever called. No credentials are sent. The `Mcp-Session-Id` returned by the server is echoed back, as
the protocol requires. The User-Agent is `mcpwatch-index/0.1 (+https://github.com/anardimontlv/mcpwatch)`.

### Result

| Outcome | Recorded auth status |
|---|---|
| HTTP 401 or 403 | `auth` |
| `initialize` and `tools/list` answer | `open` |
| Any other error, timeout, or refused address | `down` |

When a server has several remotes, the first `open` or `auth` result wins.

### SSRF and resource protections

Registry entries are written by anyone who can publish to the registry, so the probe assumes a URL may point at
something it should not reach.

- **Pre-check:** the hostname is resolved, and the probe is skipped unless every resolved address is a public
  (globally routable) address. Loopback, private, link-local (including cloud metadata at `169.254.169.254`),
  and other reserved ranges are refused.
- **Connect-time check:** after the TCP connection opens and before any request byte is sent, the actual peer
  address of the socket is checked again. This defeats DNS rebinding between the pre-check and the connection.
- **No redirects:** HTTP redirects are not followed.
- **No proxies:** proxy environment variables are ignored, so the checked peer is the real peer.
- **Limits:** 8 seconds per socket operation, 20 seconds for the whole handshake regardless of how slowly bytes
  arrive, and 1 MB per response.
- **Parallelism:** 48 servers are assessed at a time.

### Static checks on registry metadata

- Remote URLs and declared headers go through the same config rules as your local scan (MW001, MW004). A header
  the registry marks as required or secret counts as auth for the static check.
- MW005 in the index is decided by the probe, not by the config: it is reported only when an endpoint returns a
  tool list without credentials.
- Packages: MW002 if the registry entry has no version or uses `latest` or `*`. MW001 if an environment variable
  marked secret ships with a default that looks like a real credential.
- Tools from an `open` endpoint go through MW101, MW102 and MW103.

Rule details: [rules.md](rules.md).

## 3. Fingerprints

One fingerprint per tool:

```
sha256( JSON({"d": description, "s": inputSchema}, keys sorted, non-ASCII kept) ), first 12 hex characters
```

- Covered: the tool's `description` and its full `inputSchema`, including nested property descriptions.
- The tool `name` is the key. A rename shows up as one tool removed and one added.
- 12 hex characters is 48 bits. That is enough to detect accidental and deliberate changes to a given tool; it is
  not meant to resist an attacker who searches for a colliding description.

**Not covered by the fingerprint:** tool `title`, `annotations` (for example `readOnlyHint`, `destructiveHint`),
`outputSchema`, the server's `instructions` from `initialize`, prompts and resources. A change limited to those
fields is not detected.

Fingerprints are recorded only for servers whose status is `open`.

## 4. Grading

Each finding subtracts from 100: critical 40, high 20, medium 8, low 3. Duplicate findings (same rule and same
message) count once. A at 90 or more, B at 75, C at 60, D at 40, F below 40.

The grade is an automated signal from the checks above. It is not an audit, a code review or a guarantee. A
package-only server can get an A because its code was never examined.

## 5. Change detection

Each daily run compares every server with the previous day's published record.

- Tool fingerprints are compared only when the server is `open` today. A server that now requires auth, or that
  is down, is not reported as "all tools removed".
- If a server is `down` today, or has no probeable remote, yesterday's fingerprints are carried forward together
  with yesterday's **verified date** (`vd`). The date is not refreshed, so the record ages.
- Changes are written to a `history` branch, one file per day, and the last 14 days are shown on the public
  "rug-pull radar" page.

The first run with no previous data only sets the baseline.

## What `check` reports

`check` compares your lock file with today's index record for each server in your config.

| Kind | Severity | Condition |
|---|---|---|
| `tool_changed` | high | A pinned tool's fingerprint differs (server is `open` today) |
| `auth_dropped` | high | Was `auth`, now `open` |
| `gone` | high | Was in the index, now not found, or now ambiguous |
| `reassigned` | high | The config's lookup key now resolves to a different registry entry |
| `tool_added`, `tool_removed` | medium | Tool set changed (server is `open` today) |
| `grade_changed` | medium | Grade differs |
| `auth_added` | medium | Was `open`, now `auth`. Auth can hide later tool changes |
| `fingerprints_lost` | medium | Was fingerprinted, now no fingerprints |
| `stale` | medium | Server had fingerprints at lock time, and today's verified date is missing, unparseable, in the future, or older than `--max-stale` days (default 3) |
| `package_changed` | low | Registry package version changed. Printed; does not fail |
| `[NEW]` | fails | Server in config but not in the lock file |

Exit 1 if any high or medium item, or any `[NEW]` server, is present.

### Fail-closed behavior

- If any index file cannot be fetched (DNS failure, timeout, HTTP error other than 404 on a lookup shard),
  `check` exits 2. It never reports "no drift" without data.
- A 404 on a lookup shard means "no server with this key". For a server that was pinned, that is reported as
  `gone` (high).
- A server that blocks the indexer keeps its old fingerprints, but its verified date stops moving. After
  `--max-stale` days, `check` fails with `stale`. A server cannot hide a change by going dark.
- If a lookup key is claimed by more than one registry entry (for example, two entries list the same npm
  package), `lock` refuses to pick one and does not pin the server. If it happens after locking, `check`
  reports `gone`.

### Known gaps in `check`

- Servers reported `not pinned` at lock time (not in the index, or ambiguous) are skipped by `check` with no
  output.
- A server removed from your config is not reported.
- The staleness check applies only to servers that had fingerprints at lock time.

## Matching your config to the index

`lock` and `check` derive a lookup key from each config entry. No server is contacted.

| Config entry | Key |
|---|---|
| `url` or `serverUrl` | `url:` + lowercase scheme and host + path without trailing slash. Port, query and fragment are dropped. |
| `npx`, `bunx`, `pnpx` | `npm:` + first non-flag argument, version removed, lowercased |
| `uvx`, `pipx` (including `pipx run`) | `pypi:` + package name, version and extras removed, lowercased, `_` to `-` |
| `docker`, `podman` | `oci:` + the last argument containing `/` or `:`, tag and digest removed |
| Anything else (`node`, `python`, `cmd /c ...`) | No key. Reported as `not pinned`. |

The Docker rule assumes `docker run [flags] image` with nothing after the image. Arguments after the image can be
mistaken for it.

## Privacy of lookups

The CLI downloads two kinds of public files:

- `m/XX.json`: lookup shard. `XX` is the first 2 hex characters of the SHA-256 of the lookup key.
- `d/XX.json`: data shard. `XX` comes from the matched server's slug.

There are 256 shards of each kind. Each request reveals to the host (and its logs) your IP address and which
shards you fetched. That narrows your servers down to about 1/256 of the index per server. It does not send server
names, URLs, packages, environment variables, the config or the lock file. The User-Agent is `mcpwatch-cli/0.1`.

To avoid even that, mirror the static `d/` and `m/` files and set `MCPWATCH_URL` to the mirror.

## What we cannot see

- **Package-based servers' tools.** Servers distributed as npm, PyPI or OCI packages are never installed or run.
  Their tools are unknown to the index, so they have no fingerprints and `check` cannot detect tool changes in
  them. For those servers the index records only static metadata checks, the grade and package versions. This is
  most of the registry.
- **Servers that require auth.** The probe sends no credentials, so a server that returns 401 or 403 has no public
  tool list. Its tools may differ per user anyway.
- **More than the first page of tools.** The probe reads one `tools/list` response and does not follow
  `nextCursor`.
- **Per-client or per-user behavior.** A server can serve different tools to different clients, IP ranges or
  accounts. The index sees what it is served from GitHub Actions runners.
- **Runtime behavior.** What a tool does when called is never observed. A tool can keep the same description and
  schema and change what it does.
- **Servers outside the official registry,** including private and internal servers.
- **Tool output.** Prompt injection in tool results is out of scope.

## Limits of the scanner

- Rules are pattern matches on configuration and tool text. They have known false positives and false negatives,
  listed per rule in [rules.md](rules.md).
- The scanner never launches or connects to the servers it scans. It cannot tell whether a configured remote
  actually requires auth, or whether a package version is malicious.
