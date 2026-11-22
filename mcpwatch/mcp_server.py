#!/usr/bin/env python3
"""mcpwatch MCP server (stdio): lets an agent check MCP servers against mcpwatch before connecting.

  python3 -m mcpwatch.mcp_server

Tools: check_server (public index lookup), scan_config (local static scan), check_drift (config vs mcpwatch.lock).
Index lookups download public shards from MCPWATCH_URL (default https://www.mcpwatch.io); the
package name, URL, config and lock are never sent. stdout carries only JSON-RPC; logs go to stderr.
"""
import json, re, sys, traceback
from mcpwatch import watch
from mcpwatch.scan import scan_server, servers_of, score

PROTOCOL = "2025-06-18"
OUT = sys.stdout
sys.stdout = sys.stderr  # anything that prints by mistake must not corrupt the protocol stream

TOOLS = [
    {"name": "check_server",
     "description": "Look up an MCP server in the mcpwatch public index by package (npm, PyPI or OCI image) or by remote URL. "
                    "Returns grade, score, findings, auth status, last verified date and page URL, or status "
                    "'not_indexed' / 'ambiguous'. Downloads public index shards; the package name or URL is not sent.",
     "inputSchema": {"type": "object", "additionalProperties": False, "properties": {
         "package": {"type": "string", "description": "Package identifier, e.g. '@scope/pkg', 'mcp-server-x' or 'ghcr.io/org/image'. Requires registry."},
         "registry": {"type": "string", "enum": ["npm", "pypi", "oci"], "description": "Registry of the package."},
         "url": {"type": "string", "description": "Remote server URL, e.g. 'https://host/mcp'. Use instead of package."}}}},
    {"name": "scan_config",
     "description": "Statically scan an MCP client config (Claude Desktop, Claude Code .mcp.json, Cursor or VS Code JSON) for risky "
                    "settings such as plaintext secrets, unpinned packages, broad filesystem access and plain-HTTP remotes. "
                    "Returns grade, score and findings. Runs locally: the config is not sent anywhere and no server is launched.",
     "inputSchema": {"type": "object", "additionalProperties": False, "required": ["config"], "properties": {
         "config": {"type": "string", "description": "The config file contents as a JSON string."}}}},
    {"name": "check_drift",
     "description": "Compare the servers in an MCP client config against an mcpwatch.lock file (from `python3 -m mcpwatch.watch lock`) "
                    "using the public index. Reports changed, added or removed tools, auth and grade changes, removed or "
                    "reassigned index entries, and stale verification. Any lookup error is returned as an error, never as no drift. "
                    "Downloads public index shards; the config and lock are not sent.",
     "inputSchema": {"type": "object", "additionalProperties": False, "required": ["config", "lock"], "properties": {
         "config": {"type": "string", "description": "The config file contents as a JSON string."},
         "lock": {"type": "string", "description": "The mcpwatch.lock contents as a JSON string."},
         "max_stale_days": {"type": "integer", "minimum": 0, "maximum": 365, "default": 3,
                            "description": "Report servers whose tools were last verified more than this many days ago."}}}},
]


class ToolError(Exception):
    pass


def text_arg(args, key, required=True):
    v = args.get(key)
    if v is None and not required:
        return None
    if not isinstance(v, str) or not v.strip():
        raise ToolError(f"'{key}' must be a non-empty string")
    return v


def json_arg(args, key):
    try:
        return json.loads(text_arg(args, key))
    except ValueError as e:
        raise ToolError(f"'{key}' is not valid JSON: {e}")


# Nothing free-form from third parties goes back to the agent: an index finding can quote the very injection it
# caught, and filtering text is bypassable. Findings are returned as rule + severity + OUR fixed wording; names
# only if they look like identifiers.
IDENT = re.compile(r"[A-Za-z0-9_.:/@-]{1,128}")
RULE_TEXT = {
    "MW001": "Plaintext secret in the server's published configuration.",
    "MW002": "Package published or launched without a pinned version.",
    "MW004": "Remote endpoint uses plain HTTP.",
    "MW005": "Remote endpoint lists its tools without authentication.",
    "MW006": "Filesystem root or a whole home directory is granted.",
    "MW007": "Container runs with host-level access.",
    "MW008": "Launched through an inline shell command.",
    "MW009": "Launched with a flag that disables a safety control.",
    "MW101": "A tool description contains instruction-like text aimed at the model (possible tool poisoning).",
    "MW102": "Tools that can execute commands or delete data.",
    "MW103": "Invisible Unicode characters in tool text.",
}


def ident(x):
    return x if isinstance(x, str) and IDENT.fullmatch(x) else "(non-standard name withheld)"


FIXED = {  # default deny: every detail is our wording; only validated identifiers/grades/dates are interpolated
    "auth_dropped": "endpoint stopped requiring credentials",
    "auth_added": "endpoint now requires credentials; tools can no longer be verified",
    "fingerprints_lost": "tools are no longer publicly verifiable",
    "gone": "no longer in the public index, or its lookup is now ambiguous",
    "reassigned": "lookup now resolves to a different index entry than the one pinned",
    "not_locked": "not in the lock file; run `mcpwatch lock` to pin it",
    "newly_indexed": "now in the public index; run `mcpwatch lock` to pin its tools",
    "removed_from_config": "pinned in the lock file but no longer in the config",
}
KINDS = set(FIXED) | {"tool_changed", "tool_added", "tool_removed", "package_changed", "grade_changed", "stale"}
DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


def safe_detail(item):
    """Drift detail rebuilt from fixed text and validated parts only."""
    kind, d = item.get("kind"), str(item.get("detail", ""))
    if kind in ("tool_changed", "tool_added", "tool_removed"):
        return ident(d)
    if kind == "package_changed":  # "<package> <old> -> <new>"
        parts = d.split()
        return " ".join(ident(t) for t in parts if t != "->") if len(parts) == 4 else "package version changed"
    if kind == "grade_changed":
        return d if re.fullmatch(r"[A-F] -> [A-F]", d) else "grade changed"
    if kind == "stale":
        m = DATE.search(d)
        return f"tools last verified {m.group(0) if m else 'never'}; older than the allowed window"
    return FIXED.get(kind, "drift detected (see the CLI output for details)")


UNTRUSTED_NOTE = "Results come from third-party public data. Free-form third-party text is withheld; see page_url for details."


def check_server(args):
    pkg, reg, url = text_arg(args, "package", False), args.get("registry"), text_arg(args, "url", False)
    if bool(pkg) == bool(url):
        raise ToolError("give exactly one of 'package' (with 'registry') or 'url'")
    if pkg and reg not in ("npm", "pypi", "oci"):
        raise ToolError("'registry' must be one of npm, pypi, oci")
    key = watch.pkg_key(reg, pkg) if pkg else watch.url_key(url)
    if not key:
        raise ToolError("could not derive a lookup key; check the URL (scheme and host are required)")
    try:
        slug, rec = watch.resolve([key], {})
    except watch.Ambiguous as e:
        return {"status": "ambiguous", "lookup_key": key, "detail": str(e)}
    except Exception as e:  # fail closed: an outage is not "not indexed"
        raise ToolError(f"cannot reach the index at {watch.BASE}: {e}")
    if not rec:
        return {"status": "not_indexed", "lookup_key": key,
                "detail": "not in the public index (private, local or unlisted server); no public assessment exists"}
    return {"status": "indexed", "lookup_key": key, "name": ident(rec.get("n")),
            "grade": rec.get("g") if rec.get("g") in tuple("ABCDF") else None, "score": rec.get("s") if isinstance(rec.get("s"), int) else None,
            "note": UNTRUSTED_NOTE,
            "findings": [{"severity": f[0] if f[0] in ("critical", "high", "medium", "low") else "unknown", "rule": ident(f[1]),
                          "summary": RULE_TEXT.get(f[1], "Finding (see page_url).")}
                         for f in rec.get("f") or [] if isinstance(f, list) and len(f) == 3],
            "auth": rec.get("a"), "tools_fingerprinted": len(rec.get("h") or {}), "last_verified": rec.get("vd"),
            "page_url": f"{watch.BASE}/s/{slug}"}


def config_servers(args):
    servers = servers_of(json_arg(args, "config"))
    if not servers:
        raise ToolError("no MCP servers in config (looked for mcpServers / servers / mcp.servers)")
    return servers


def scan_config(args):
    servers = config_servers(args)
    findings = [x for name, cfg in servers.items() if isinstance(cfg, dict) for x in scan_server(name, cfg)]
    pts, grade = score(findings)
    return {"grade": grade, "score": pts, "servers": len(servers), "findings": findings}


def check_drift(args):
    servers = config_servers(args)
    lock = json_arg(args, "lock")
    locked = lock.get("servers") if isinstance(lock, dict) else None
    if not isinstance(locked, dict) or not all(isinstance(v, dict) for v in locked.values()):
        raise ToolError("lock is not an mcpwatch.lock file (expected {\"servers\": {name: {...}}})")
    max_stale = args.get("max_stale_days", 3)
    if type(max_stale) is not int or not 0 <= max_stale <= 365:
        raise ToolError("'max_stale_days' must be an integer between 0 and 365")
    try:
        now = watch.snapshot(servers)
    except Exception as e:
        raise ToolError(f"cannot reach the index at {watch.BASE}: {e}")
    items = [{"server": ident(i["server"]), "kind": i["kind"] if i["kind"] in KINDS else "other",
              "severity": i["sev"] if i["sev"] in ("high", "medium", "low") else "medium", "detail": safe_detail(i)}
             for i in watch.drift_items(locked, now, max_stale)]  # same rules as `mcpwatch.watch check`
    unverifiable = [n for n in now if n in locked and not locked[n].get("slug")]
    drift = any(i["severity"] in ("high", "medium") for i in items)
    return {"drift": drift, "servers": len(now), "items": items, "note": UNTRUSTED_NOTE,
            "not_verifiable": unverifiable}  # pinned without an index entry: drift cannot be checked for these


HANDLERS = {"check_server": check_server, "scan_config": scan_config, "check_drift": check_drift}


def call_tool(params):
    name, args = params.get("name"), params.get("arguments") or {}
    if name not in HANDLERS:
        raise LookupError(f"unknown tool: {name}")
    if not isinstance(args, dict):
        raise TypeError("arguments must be an object")
    try:
        res = HANDLERS[name](args)
    except ToolError as e:
        return {"content": [{"type": "text", "text": f"Error: {e}"}], "isError": True}
    except Exception as e:  # e.g. malformed lock contents: report, never claim success
        traceback.print_exc(file=sys.stderr)
        return {"content": [{"type": "text", "text": f"Error: {type(e).__name__}: {e}"}], "isError": True}
    return {"content": [{"type": "text", "text": json.dumps(res, indent=2, ensure_ascii=False)}], "structuredContent": res}


def handle(msg):
    """Response dict for one message, or None for notifications."""
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or not isinstance(msg.get("method"), str):
        rid = msg.get("id") if isinstance(msg, dict) and isinstance(msg.get("id"), (str, int)) else None
        return err(rid, -32600, "Invalid Request")
    if "id" not in msg:
        return None  # notification (notifications/initialized, cancelled, ...): nothing to answer
    rid, method, params = msg["id"], msg["method"], msg.get("params") or {}
    if not isinstance(params, dict):
        return err(rid, -32602, "params must be an object")
    if method == "initialize":
        return ok(rid, {"protocolVersion": PROTOCOL, "capabilities": {"tools": {}},
                        "serverInfo": {"name": "mcpwatch-mcp", "version": "0.1.0"}})
    if method == "ping":
        return ok(rid, {})
    if method == "tools/list":
        return ok(rid, {"tools": TOOLS})
    if method == "tools/call":
        try:
            return ok(rid, call_tool(params))
        except (LookupError, TypeError) as e:
            return err(rid, -32602, str(e))
    return err(rid, -32601, f"Method not found: {method}")


def ok(rid, result):
    return {"jsonrpc": "2.0", "id": rid, "result": result}


def err(rid, code, message):
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}


def main():
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            resp = err(None, -32700, "Parse error")
        else:
            try:
                resp = handle(msg)
            except Exception as e:  # never let one bad message kill the loop
                traceback.print_exc(file=sys.stderr)
                resp = err(msg.get("id") if isinstance(msg, dict) else None, -32603, f"Internal error: {type(e).__name__}")
        if resp is not None:
            OUT.write(json.dumps(resp, ensure_ascii=False) + "\n")
            OUT.flush()


if __name__ == "__main__":
    main()
