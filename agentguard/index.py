#!/usr/bin/env python3
"""Build the public agentguard index from the official MCP registry.

  python3 -m agentguard.index --out site [--limit N] [--no-probe]

Remote servers get a read-only MCP handshake + tools/list (no tool is ever called).
Package servers get static checks only: third-party code is never run.
"""
import argparse, html, json, os, re, sys, time, urllib.error, urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
from agentguard.scan import scan_server, scan_tools, score, badge, safe_url

REGISTRY = "https://registry.modelcontextprotocol.io/v0/servers"
UA = "agentguard-index/0.1 (+https://github.com/anardimontlv/agentguard)"
MAX_BYTES = 1_000_000
esc = html.escape


def get_json(url, timeout=30, tries=4):
    for i in range(tries):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": UA}), timeout=timeout) as r:
                return json.loads(r.read(MAX_BYTES * 20))
        except (TimeoutError, urllib.error.URLError) as e:
            if i == tries - 1:
                raise
            print(f"registry retry {i + 1}: {e}", file=sys.stderr)
            time.sleep(2 ** i)


def fetch_registry(limit=None):
    out, cursor, pages = {}, None, 0
    while True:
        url = REGISTRY + "?limit=100&version=latest" + (f"&cursor={urllib.request.quote(cursor)}" if cursor else "")
        d = get_json(url)
        pages += 1
        if pages % 10 == 0:
            print(f"registry: {pages} pages, {len(out)} servers", file=sys.stderr)
        for item in d.get("servers", []):
            s = item.get("server", {})
            meta = item.get("_meta", {}).get("io.modelcontextprotocol.registry/official", {})
            if meta.get("status", "active") == "active" and meta.get("isLatest", True):
                out[s["name"]] = s
        cursor = d.get("metadata", {}).get("nextCursor")
        if not cursor or (limit and len(out) >= limit):
            return list(out.values())[:limit] if limit else list(out.values())


def rpc(url, body, session=None, timeout=8):
    headers = {"User-Agent": UA, "Content-Type": "application/json", "Accept": "application/json, text/event-stream",
               "MCP-Protocol-Version": "2025-06-18"}
    if session:
        headers["Mcp-Session-Id"] = session
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read(MAX_BYTES).decode("utf-8", "replace")
        sid = r.headers.get("Mcp-Session-Id") or session
    if not raw.strip():
        return None, sid
    if raw.lstrip().startswith("{"):
        return json.loads(raw), sid
    for line in raw.splitlines():  # SSE: take the first data line that is our JSON-RPC response
        if line.startswith("data:"):
            try:
                msg = json.loads(line[5:].strip())
            except json.JSONDecodeError:
                continue
            if "result" in msg or "error" in msg:
                return msg, sid
    return None, sid


def probe(url):
    """Return (status, tools). status: 'auth' | 'open' | 'down'."""
    try:
        init, sid = rpc(url, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "agentguard", "version": "0.1"}}})
        if not init or "error" in init:
            return "down", []
        try:
            rpc(url, {"jsonrpc": "2.0", "method": "notifications/initialized"}, sid)
        except urllib.error.HTTPError:
            pass  # many servers answer 202/4xx to notifications; tools/list is what matters
        res, _ = rpc(url, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, sid)
        tools = (res or {}).get("result", {}).get("tools", [])
        return "open", tools if isinstance(tools, list) else []
    except urllib.error.HTTPError as e:
        return ("auth" if e.code in (401, 403) else "down"), []
    except Exception:
        return "down", []


def assess(s, do_probe=True):
    lst = lambda v: [x for x in v if isinstance(x, dict)] if isinstance(v, list) else []  # registry data is untrusted
    name, findings, notes, tools = str(s.get("name") or "unnamed"), [], [], []
    for r in lst(s.get("remotes")):
        url = r.get("url") if isinstance(r.get("url"), str) else ""
        hdrs = {str(h.get("name", "")): h.get("value", "") for h in lst(r.get("headers"))}
        cfg = {"url": url, "headers": hdrs}
        if any(h.get("isRequired") or h.get("isSecret") for h in lst(r.get("headers"))):
            cfg["headers"] = {**hdrs, "Authorization": "${declared}"}
        f = [x for x in scan_server(name, cfg) if x["rule"] != "AG005"]  # AG005 decided by the live probe below
        findings += f
        if do_probe and "{" not in url and url.startswith("http"):
            status, t = probe(url)
            notes.append(f"{safe_url(url)}: {'requires auth' if status == 'auth' else 'answers without auth' if status == 'open' else 'not reachable'}")
            if status == "open" and t:
                findings.append({"server": name, "rule": "AG005", "severity": "low",
                                 "message": f"Remote endpoint lists {len(t)} tool(s) to anyone, no credentials needed."})
                tools = t
                findings += scan_tools(t, name)
    for p in lst(s.get("packages")):
        ident, ver = str(p.get("identifier", "")), str(p.get("version", ""))
        if not ver or ver in {"latest", "*"}:
            findings.append({"server": name, "rule": "AG002", "severity": "medium", "message": f"Package {ident} is published without a fixed version."})
        for ev in lst(p.get("environmentVariables")):
            if ev.get("isSecret") and ev.get("default"):
                findings.append({"server": name, "rule": "AG001", "severity": "high", "message": f"Secret env {ev.get('name')} ships with a default value."})
        notes.append(f"{p.get('registryType', 'package')}: {ident}@{ver or '?'} (static checks only; code not executed)")
    # one finding per rule per message is enough for the public page
    uniq = list({(x["rule"], x["message"]): x for x in findings}.values())
    pts, grade = score(uniq)
    repo = s.get("repository") if isinstance(s.get("repository"), dict) else {}
    return {"name": name, "title": str(s.get("title") or name), "description": str(s.get("description", "")), "version": str(s.get("version", "")),
            "repo": str(repo.get("url", "")), "score": pts, "grade": grade, "findings": uniq,
            "notes": notes, "tools": [str(t.get("name", "?")) for t in lst(tools)][:100]}


def slug(name):
    # hash suffix: "a.b/c" and "a-b/c" must never share a page or badge
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:80] + "-" + hashlib.sha256(name.encode()).hexdigest()[:8]


CSS = """:root{--bg:#fff;--fg:#1a1a1a;--mut:#5f6368;--line:#e3e3e3;--card:#f7f7f8;--acc:#1b5e20}
@media (prefers-color-scheme:dark){:root{--bg:#111;--fg:#eee;--mut:#a0a0a0;--line:#2a2a2a;--card:#1a1a1a;--acc:#81c784}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.55 system-ui,-apple-system,sans-serif}
main{max-width:980px;margin:0 auto;padding:24px 16px}a{color:var(--acc)}h1{font-size:2rem;line-height:1.2;margin:.2em 0}
.mut{color:var(--mut)}.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin:16px 0}
table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:8px 6px;border-bottom:1px solid var(--line);vertical-align:top}
.g{display:inline-block;min-width:2em;text-align:center;border-radius:4px;color:#fff;font-weight:700}
.gA{background:#2e7d32}.gB{background:#558b2f}.gC{background:#f9a825;color:#111}.gD{background:#ef6c00}.gF{background:#c62828}
code,pre{font-family:ui-monospace,Menlo,monospace;font-size:.9em}pre{overflow-x:auto;background:var(--card);padding:12px;border-radius:8px;border:1px solid var(--line)}
input{width:100%;padding:10px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--fg);font-size:1rem}
.wrap{overflow-wrap:anywhere}"""


def page(title, body, desc):
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>{esc(title)}</title><meta name="description" content="{esc(desc)}"><style>{CSS}</style></head>'
            f'<body><main>{body}<p class="mut" style="margin-top:48px">agentguard: static and read-only checks. '
            f'A grade is not a guarantee of safety. <a href="/">Index</a> · <a href="https://github.com/anardimontlv/agentguard">Scanner</a></p></main></body></html>')


def g(grade):
    return f'<span class="g g{grade}">{grade}</span>'


def write_site(results, out):
    os.makedirs(f"{out}/s", exist_ok=True)
    os.makedirs(f"{out}/badge", exist_ok=True)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    for r in results:
        sl = slug(r["name"])
        with open(f"{out}/badge/{sl}.svg", "w", encoding="utf-8") as fh:
            fh.write(badge(r["grade"]))
        rows = "".join(f"<tr><td>{esc(x['severity'])}</td><td>{esc(x['rule'])}</td><td class='wrap'>{esc(x['message'])}</td></tr>"
                       for x in r["findings"]) or "<tr><td colspan=3>No issues found by current checks.</td></tr>"
        notes = "".join(f"<li class='wrap'>{esc(n)}</li>" for n in r["notes"])
        tools = ", ".join(esc(t) for t in r["tools"]) or "not listed publicly"
        md = f"[![agentguard](https://agentguard.vercel.app/badge/{sl}.svg)](https://agentguard.vercel.app/s/{sl}.html)"
        body = (f"<p><a href='/'>← All servers</a></p><h1 class='wrap'>{esc(r['title'])} {g(r['grade'])}</h1>"
                f"<p class='mut wrap'>{esc(r['name'])} · v{esc(r['version'])} · score {r['score']}/100 · checked {now}</p>"
                f"<p class='wrap'>{esc(r['description'])}</p>"
                + (f"<p class='wrap'>Source: <a rel='nofollow' href='{esc(r['repo'])}'>{esc(r['repo'])}</a></p>" if r['repo'].startswith("https://") else "")
                + f"<div class='card'><h2>Findings</h2><table><tr><th>Severity</th><th>Rule</th><th>Detail</th></tr>{rows}</table></div>"
                f"<div class='card'><h2>What was checked</h2><ul>{notes}</ul><p>Public tools: {tools}</p></div>"
                f"<div class='card'><h2>Maintainer? Add the badge</h2><pre>{esc(md)}</pre></div>")
        with open(f"{out}/s/{sl}.html", "w", encoding="utf-8") as fh:
            fh.write(page(f"Is {r['title']} MCP server safe? Grade {r['grade']}", body,
                          f"agentguard security grade {r['grade']} for the {r['title']} MCP server: findings, auth, tools."))
    results = sorted(results, key=lambda r: (r["score"], r["name"]))
    counts = {k: sum(r["grade"] == k for r in results) for k in "ABCDF"}
    open_n = sum(any(x["rule"] == "AG005" for x in r["findings"]) for r in results)
    rows = "".join(f"<tr data-n='{esc(r['name'].lower())} {esc(r['title'].lower())}'><td>{g(r['grade'])}</td>"
                   f"<td class='wrap'><a href='/s/{slug(r['name'])}.html'>{esc(r['title'])}</a><br><span class='mut'>{esc(r['name'])}</span></td>"
                   f"<td>{len(r['findings'])}</td></tr>" for r in results)
    body = (f"<h1>Is your AI agent's MCP server safe?</h1>"
            f"<p>agentguard grades every server in the official MCP registry for leaked secrets, plain-HTTP endpoints, "
            f"unauthenticated tools and poisoned tool descriptions. Updated daily. Last run {now}.</p>"
            f"<div class='card'><b>{len(results)}</b> servers · " + " · ".join(f"{g(k)} {v}" for k, v in counts.items())
            + f" · <b>{open_n}</b> expose tools without auth</div>"
            f"<div class='card'><h2>Scan your own config, free</h2><pre>git clone https://github.com/anardimontlv/agentguard &amp;&amp; cd agentguard\n"
            f"python3 -m agentguard.scan ~/.cursor/mcp.json</pre><p class='mut'>Works on Claude Desktop, Claude Code (.mcp.json), Cursor and VS Code configs. "
            f"Runs locally; nothing leaves your machine.</p></div>"
            f"<input id='q' placeholder='Search {len(results)} servers…' aria-label='Search servers'>"
            f"<table><thead><tr><th>Grade</th><th>Server</th><th>Findings</th></tr></thead><tbody id='t'>{rows}</tbody></table>"
            "<script>const q=document.getElementById('q'),rs=[...document.querySelectorAll('#t tr')];"
            "q.oninput=()=>{const v=q.value.toLowerCase();rs.forEach(r=>r.hidden=v&&!r.dataset.n.includes(v))}</script>")
    with open(f"{out}/index.html", "w", encoding="utf-8") as fh:
        fh.write(page("MCP Server Security Index: agentguard", body, "Daily security grades for every MCP server in the official registry."))
    with open(f"{out}/index.json", "w", encoding="utf-8") as fh:
        json.dump({"generated": now, "servers": results}, fh)
    urls = "".join(f"<url><loc>https://agentguard.vercel.app/s/{slug(r['name'])}.html</loc></url>" for r in results)
    with open(f"{out}/sitemap.xml", "w", encoding="utf-8") as fh:
        fh.write(f'<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                 f'<url><loc>https://agentguard.vercel.app/</loc></url>{urls}</urlset>')
    with open(f"{out}/robots.txt", "w", encoding="utf-8") as fh:
        fh.write("User-agent: *\nAllow: /\nSitemap: https://agentguard.vercel.app/sitemap.xml\n")


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="site")
    ap.add_argument("--limit", type=int)
    ap.add_argument("--no-probe", action="store_true")
    a = ap.parse_args(argv)
    servers = fetch_registry(a.limit)
    print(f"registry: {len(servers)} active servers", file=sys.stderr)
    with ThreadPoolExecutor(48) as ex:
        results = list(ex.map(lambda s: assess(s, not a.no_probe), servers))
    write_site(results, a.out)
    print(f"wrote {len(results)} pages to {a.out}/", file=sys.stderr)


if __name__ == "__main__":
    main()
