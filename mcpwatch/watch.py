#!/usr/bin/env python3
"""Rug-pull radar: pin the exact MCP tools your agents trust, then detect drift.

  python3 -m mcpwatch.watch lock  CONFIG.json [--lock mcpwatch.lock]   # pin today's tools
  python3 -m mcpwatch.watch check CONFIG.json [--lock mcpwatch.lock]   # exit 1 if anything drifted

Fingerprints come from the public daily index (one hash per tool over its description and input
schema), so nothing is executed and nothing about your config is uploaded: the CLI only downloads
public index shards. Exit codes: 0 no drift, 1 drift, 2 bad input.
"""
import argparse, hashlib, json, os, re, shlex, sys, urllib.error, urllib.request
from urllib.parse import urlsplit

BASE = os.environ.get("MCPWATCH_URL", "https://www.mcpwatch.io").rstrip("/")
DRIFT_SEV = {"tool_changed": "high", "auth_dropped": "high", "tool_added": "medium", "tool_removed": "medium",
             "grade_changed": "medium", "package_changed": "low", "auth_added": "medium",  # auth can hide later tool changes
             "fingerprints_lost": "medium", "gone": "high"}


# ---- fingerprints and lookup keys (shared with the indexer) ----

def tool_hash(tool):
    body = json.dumps({"d": str(tool.get("description", "")), "s": tool.get("inputSchema", {})}, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(body.encode()).hexdigest()[:12]


def fingerprints(tools):
    return {str(t.get("name", "?")): tool_hash(t) for t in tools if isinstance(t, dict)}


def url_key(url):
    try:
        p = urlsplit(url.strip())
        return f"url:{p.scheme.lower()}://{(p.hostname or '').lower()}{p.path.rstrip('/')}" if p.hostname else None
    except ValueError:
        return None


def pkg_key(kind, ident):
    ident = ident.strip()
    if kind == "npm":
        name = ident[1:] if ident.startswith("@") else ident
        name = name.split("@", 1)[0] if "@" in name else name
        return "npm:" + ("@" if ident.startswith("@") else "") + name.lower()
    if kind == "pypi":
        return "pypi:" + re.split(r"[=<>~!\[@]", ident, 1)[0].lower().replace("_", "-")
    if kind == "oci":
        img = ident.split("@", 1)[0]
        last = img.rsplit("/", 1)[-1]
        if ":" in last:
            img = img[: img.rfind(":")]
        return "oci:" + img.lower()
    return None


def registry_keys(server):
    """Lookup keys for a registry entry (packages and remotes)."""
    keys = []
    for r in server.get("remotes") or []:
        if isinstance(r, dict) and isinstance(r.get("url"), str) and "{" not in r["url"]:
            keys.append(url_key(r["url"]))
    kinds = {"npm": "npm", "pypi": "pypi", "oci": "oci", "docker": "oci"}
    for p in server.get("packages") or []:
        if isinstance(p, dict) and kinds.get(str(p.get("registryType", "")).lower()):
            keys.append(pkg_key(kinds[str(p["registryType"]).lower()], str(p.get("identifier", ""))))
    return [k for k in keys if k]


def config_keys(cfg):
    """Lookup keys for one server entry in a client config (.mcp.json etc.)."""
    url = cfg.get("url") or cfg.get("serverUrl")
    if isinstance(url, str):
        k = url_key(url)
        return [k] if k else []
    cmd = cfg.get("command") if isinstance(cfg.get("command"), str) else ""
    args = cfg.get("args")
    args = shlex.split(args) if isinstance(args, str) else [str(a) for a in args] if isinstance(args, list) else []
    exe = cmd.replace("\\", "/").rsplit("/", 1)[-1].removesuffix(".cmd").removesuffix(".exe")
    plain = [a for a in args if not a.startswith("-")]
    if exe in {"npx", "bunx", "pnpx"} and plain:
        return [pkg_key("npm", plain[0])]
    if exe in {"uvx", "pipx"} and plain:
        return [pkg_key("pypi", plain[-1] if exe == "pipx" and plain[0] == "run" and len(plain) > 1 else plain[0])]
    if exe in {"docker", "podman"}:
        return [pkg_key("oci", a) for a in plain[1:] if "/" in a or ":" in a][-1:]  # shortcut: last image-looking arg; ok for `docker run [flags] image`
    return []


def shard2(text):
    return hashlib.sha256(text.encode()).hexdigest()[:2]


# ---- drift detection (used daily by the indexer and on demand by `check`) ----

def diff(prev, cur):
    """Changes between two index records ({h: tool hashes|None, a: auth, g: grade, p: packages}). Unknown != changed."""
    out = []
    add = lambda kind, detail: out.append({"kind": kind, "sev": DRIFT_SEV[kind], "detail": detail})
    ph, ch = prev.get("h"), cur.get("h")
    if ph and not ch and cur.get("a") not in ("down", "none"):
        add("fingerprints_lost", "tools are no longer publicly verifiable")
    if ph and ch and cur.get("a") == "open":
        for t in sorted(set(ph) & set(ch)):
            if ph[t] != ch[t]:
                add("tool_changed", t)
        for t in sorted(set(ch) - set(ph)):
            add("tool_added", t)
        for t in sorted(set(ph) - set(ch)):
            add("tool_removed", t)
    pa, ca = prev.get("a"), cur.get("a")
    if pa == "auth" and ca == "open":
        add("auth_dropped", "endpoint stopped requiring credentials")
    elif pa == "open" and ca == "auth":
        add("auth_added", "endpoint now requires credentials")
    if prev.get("g") and cur.get("g") and prev["g"] != cur["g"]:
        add("grade_changed", f"{prev['g']} -> {cur['g']}")
    for k in sorted(set(prev.get("p") or {}) & set(cur.get("p") or {})):
        if prev["p"][k] != cur["p"][k]:
            add("package_changed", f"{k} {prev['p'][k]} -> {cur['p'][k]}")
    return out


# ---- CLI ----

def fetch(path):
    req = urllib.request.Request(f"{BASE}/{path}", headers={"User-Agent": "mcpwatch-cli/0.1"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read(20_000_000))


class Ambiguous(Exception):
    pass


def resolve(keys, cache):
    """(slug, record) or (None, None) if not indexed. Fetch errors propagate: a security check must fail closed."""
    for k in keys:
        sh = shard2(k)
        if ("m", sh) not in cache:
            try:
                cache[("m", sh)] = fetch(f"m/{sh}.json")
            except urllib.error.HTTPError as e:
                if e.code != 404:  # 404 = no key in this shard; anything else is an outage, not "not indexed"
                    raise
                cache[("m", sh)] = {}
        sl = cache[("m", sh)].get(k)
        if isinstance(sl, list):
            raise Ambiguous(f"{k} is claimed by {len(sl)} registry entries ({', '.join(sl[:3])}); refusing to guess")
        if sl:
            if ("d", sl[-8:-6]) not in cache:
                cache[("d", sl[-8:-6])] = fetch(f"d/{sl[-8:-6]}.json")
            rec = cache[("d", sl[-8:-6])].get(sl)
            if rec:
                return sl, rec
    return None, None


def snapshot(servers):
    cache, out = {}, {}
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        try:
            sl, rec = resolve(config_keys(cfg), cache)
        except Ambiguous as e:
            out[name] = {"slug": None, "ambiguous": str(e)}
            continue
        out[name] = {"slug": sl, "name": rec.get("n"), "h": rec.get("h"), "a": rec.get("a"), "g": rec.get("g"), "p": rec.get("p")} if rec else {"slug": None}
    return out


def main(argv=None):
    from mcpwatch.scan import servers_of
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=["lock", "check"])
    ap.add_argument("config")
    ap.add_argument("--lock", default="mcpwatch.lock")
    a = ap.parse_args(argv)
    try:
        with open(a.config, encoding="utf-8") as fh:
            servers = servers_of(json.load(fh))
    except (OSError, ValueError) as e:
        print(f"mcpwatch: cannot read config: {e}", file=sys.stderr)
        return 2
    if not servers:
        print("mcpwatch: no MCP servers in config", file=sys.stderr)
        return 2
    try:
        now = snapshot(servers)
    except Exception as e:
        print(f"mcpwatch: cannot reach the index at {BASE}: {e}", file=sys.stderr)
        return 2
    unindexed = [n for n, r in now.items() if not r["slug"]]
    if a.cmd == "lock":
        with open(a.lock, "w", encoding="utf-8") as fh:
            json.dump({"version": 1, "servers": now}, fh, indent=2, sort_keys=True)
        pinned = sum(1 for r in now.values() if r.get("h"))
        print(f"mcpwatch: locked {len(now)} server(s) to {a.lock}; {pinned} with tool fingerprints")
        for n in unindexed:
            why = now[n].get("ambiguous") or "not in the public index (private or local server)"
            print(f"  not pinned: {n}: {why}")
        return 0
    try:
        with open(a.lock, encoding="utf-8") as fh:
            locked = json.load(fh).get("servers", {})
    except (OSError, ValueError) as e:
        print(f"mcpwatch: cannot read lock file ({e}); run `lock` first", file=sys.stderr)
        return 2
    drift = 0
    for name, cur in now.items():
        prev = locked.get(name)
        if prev is None:
            print(f"  [NEW     ] {name}: not in {a.lock}; run `lock` to pin it")
            drift += 1
            continue
        if prev.get("slug") and not cur.get("slug"):
            print(f"  [HIGH    ] {name}: gone {cur.get('ambiguous') or 'no longer in the public index'}")
            drift += 1
            continue
        for c in diff(prev, cur):
            print(f"  [{c['sev'].upper():8}] {name}: {c['kind']} {c['detail']}")
            drift += c["sev"] in ("high", "medium")
    print(f"mcpwatch: {'DRIFT DETECTED' if drift else 'no drift'} across {len(now)} server(s)")
    return 1 if drift else 0


if __name__ == "__main__":
    sys.exit(main())
