"""Fetch a server's tools straight from the server, as your MCP client would (for `lock --live`, `check --live`, `guard`).

Unlike the public index probe, this runs on your machine against your own config: it launches stdio servers with
their configured command and env, and calls remote servers with their configured headers (${VAR} expanded from
your environment). Nothing is sent to mcpwatch.
"""
import json, os, queue, re, subprocess, threading, time, unicodedata, urllib.error, urllib.request
from mcpwatch.index import sse_response
from mcpwatch.watch import tool_hash

PROTOCOL = "2025-06-18"
INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": PROTOCOL, "capabilities": {}, "clientInfo": {"name": "mcpwatch", "version": "0.3"}}}
MAX_PAGES = 20


def expand(v):
    """${VAR} from the environment, as MCP clients do; unknown variables stay as written."""
    return re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", lambda m: os.environ.get(m.group(1), m.group(0)), str(v))


def full_hash(tool):
    """Hash of the whole tool object (title, annotations, outputSchema, ... included): what the guard approves.
    `h` (description + inputSchema) stays comparable with the public index fingerprints."""
    import hashlib
    return hashlib.sha256(json.dumps(tool, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:16]


def snapshot_tools(tools):
    """{name: {"h", "f", "d", "s", "x"}}: index hash, full hash, description, inputSchema and every other field, so a
    later check can show exactly what changed."""
    out = {}
    for t in tools:
        if isinstance(t, dict) and isinstance(t.get("name"), str):
            out[t["name"]] = {"h": tool_hash(t), "f": full_hash(t), "d": str(t.get("description", "")), "s": t.get("inputSchema", {}),
                              "x": {k: v for k, v in t.items() if k not in ("name", "description", "inputSchema")}}
    return out


def _pages(call):
    tools, cursor = [], None
    for i in range(MAX_PAGES):
        res = call({"jsonrpc": "2.0", "id": 2 + i, "method": "tools/list", **({"params": {"cursor": cursor}} if cursor else {})})
        if not res or "error" in res:
            raise RuntimeError(f"tools/list failed: {(res or {}).get('error', 'no response')}")
        r = res.get("result") or {}
        tools += [t for t in r.get("tools", []) if isinstance(t, dict)]
        cursor = r.get("nextCursor")
        if not cursor:
            return tools
    raise RuntimeError("tools/list: too many pages")


def list_tools_http(cfg, timeout=30):
    url = expand(cfg["url"])
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream", "User-Agent": "mcpwatch-cli/0.3",
               **{str(k): expand(v) for k, v in (cfg.get("headers") or {}).items()}}
    sid = [None]

    def call(body):
        h = {**headers, **({"Mcp-Session-Id": sid[0]} if sid[0] else {})}
        if body.get("id") != 1:
            h["MCP-Protocol-Version"] = PROTOCOL
        with urllib.request.urlopen(urllib.request.Request(url, data=json.dumps(body).encode(), headers=h, method="POST"), timeout=timeout) as r:
            sid[0] = r.headers.get("Mcp-Session-Id") or sid[0]
            raw = r.read(20_000_000).decode("utf-8", "replace")
        if not raw.strip():
            return None
        return json.loads(raw) if raw.lstrip().startswith("{") else sse_response(raw)

    init = call(INIT)
    if not init or "error" in init:
        raise RuntimeError("initialize failed")
    try:
        call({"jsonrpc": "2.0", "method": "notifications/initialized"})
    except urllib.error.HTTPError:
        pass  # many servers answer 202/4xx to notifications
    return _pages(call), _instructions(init)


def list_tools_stdio(cfg, timeout=30):
    cmd = [expand(cfg["command"])] + [expand(a) for a in cfg.get("args") or []]
    env = {**os.environ, **{str(k): expand(v) for k, v in (cfg.get("env") or {}).items()}}
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env, cwd=cfg.get("cwd"))
    lines = queue.Queue()

    def pump():
        for l in p.stdout:
            lines.put(l)
        lines.put(None)
    threading.Thread(target=pump, daemon=True).start()
    deadline = time.monotonic() + timeout

    def call(body):
        p.stdin.write(json.dumps(body).encode() + b"\n")
        p.stdin.flush()
        if "id" not in body:
            return None
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError("server did not answer in time")
            line = lines.get(timeout=left)
            if line is None:
                raise RuntimeError("server exited")
            try:
                msg = json.loads(line)
            except ValueError:
                continue  # servers sometimes log to stdout
            if isinstance(msg, dict) and msg.get("id") == body["id"]:
                return msg

    try:
        init = call(INIT)
        if "error" in init:
            raise RuntimeError("initialize failed")
        call({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return _pages(call), _instructions(init)
    finally:
        p.kill()
        p.wait(timeout=5)


def _instructions(init):
    """The server's `instructions` from the initialize result (sent to the client as guidance), or None."""
    v = ((init or {}).get("result") or {}).get("instructions")
    return v if isinstance(v, str) else None


def read_server(cfg, timeout=30):
    """(tools, instructions) straight from the server."""
    if isinstance(cfg.get("url"), str):
        return list_tools_http(cfg, timeout)
    if isinstance(cfg.get("command"), str):
        return list_tools_stdio(cfg, timeout)
    raise ValueError("server has neither a command nor a url")


def list_tools(cfg, timeout=30):
    return read_server(cfg, timeout)[0]


def instructions_diff(approved, cur):
    """[] when unchanged, else diff lines (hidden characters made visible)."""
    import difflib
    if approved == cur:
        return []
    a, b = visible(approved or "").splitlines(), visible(cur or "").splitlines()
    return list(difflib.unified_diff(a, b, "approved instructions", "instructions now", lineterm="", n=1)) or ["(whitespace-only change)"]


def live_diff(locked, cur):
    """Drift between two snapshot_tools() results: [(sev, kind, tool, diff_lines)]. New tools are high: a rug pull
    usually adds capability."""
    import difflib
    out = []
    for name in sorted(set(locked) | set(cur)):
        a, b = locked.get(name), cur.get(name)
        if a and not b:
            out.append(("medium", "tool_removed", name, []))
        elif b and not a:
            out.append(("high", "tool_added", name, ["+ " + l for l in visible(b["d"]).splitlines()]))
        elif a.get("f", a["h"]) != b.get("f", b["h"]):
            lines = list(difflib.unified_diff(visible(a["d"]).splitlines(), visible(b["d"]).splitlines(), "approved", "now", lineterm="", n=1))
            for key, label in (("s", "schema"), ("x", "other fields")):
                sa, sb = (json.dumps(x.get(key, {}), indent=1, sort_keys=True, ensure_ascii=False) for x in (a, b))
                if sa != sb:
                    lines += list(difflib.unified_diff(visible(sa).splitlines(), visible(sb).splitlines(), f"approved {label}", f"{label} now", lineterm="", n=1))
            out.append(("high", "tool_changed", name, lines))
    return out


def visible(s):
    """Third-party text made safe for a terminal: control and invisible/format characters shown as \\uXXXX (which also
    exposes hidden-instruction tricks)."""
    return "".join(c if c in "\n\t" or (c.isprintable() and unicodedata.category(c) != "Cf") else f"\\u{ord(c):04x}" for c in str(s))
