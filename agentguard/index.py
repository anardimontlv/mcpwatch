#!/usr/bin/env python3
"""Build the public agentguard index from the official MCP registry.

  python3 -m agentguard.index --out site [--limit N] [--no-probe]

Remote servers get a read-only MCP handshake + tools/list (no tool is ever called).
Package servers get static checks only: third-party code is never run.
"""
import argparse, html, json, os, re, sys, time, urllib.error, urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib, http.client, ipaddress, socket
from urllib.parse import urlsplit
from agentguard.scan import scan_server, scan_tools, score, badge, safe_url, is_secret_literal

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


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None  # a redirect could point at an internal address we never vetted


def _check_peer(sock):
    # checked on the live socket, before any request bytes are sent: defeats DNS rebinding
    if not ipaddress.ip_address(sock.getpeername()[0].split("%")[0]).is_global:
        sock.close()
        raise ConnectionRefusedError("refusing non-public address")


class _GuardedHTTP(http.client.HTTPConnection):
    def connect(self):
        super().connect()
        _check_peer(self.sock)


class _GuardedHTTPS(http.client.HTTPSConnection):
    def connect(self):
        super().connect()
        _check_peer(self.sock)


class _GuardedHTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req):
        return self.do_open(_GuardedHTTP, req)


class _GuardedHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(_GuardedHTTPS, req, context=self._context)


# ProxyHandler({}) ignores env proxies, which would otherwise hide the real peer
_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect, _GuardedHTTPHandler, _GuardedHTTPSHandler)
PROBE_DEADLINE = 20  # seconds for the whole handshake, however slowly a server drips bytes


def public_host(url):
    """True only if every address the host resolves to is public (blocks SSRF to metadata/private ranges)."""
    try:
        p = urlsplit(url)
        if p.scheme not in ("http", "https") or not p.hostname:
            return False
        infos = socket.getaddrinfo(p.hostname, p.port or (443 if p.scheme == "https" else 80), proto=socket.IPPROTO_TCP)
        # fast pre-filter only; the authoritative check is _check_peer on the connected socket
        return bool(infos) and all(ipaddress.ip_address(i[4][0].split("%")[0]).is_global for i in infos)
    except (OSError, ValueError):
        return False


def rpc(url, body, session=None, timeout=8, deadline=None):
    headers = {"User-Agent": UA, "Content-Type": "application/json", "Accept": "application/json, text/event-stream",
               "MCP-Protocol-Version": "2025-06-18"}
    if session:
        headers["Mcp-Session-Id"] = session
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers, method="POST")
    deadline = deadline or time.monotonic() + PROBE_DEADLINE
    with _opener.open(req, timeout=timeout) as r:
        buf = b""
        while len(buf) < MAX_BYTES:
            if time.monotonic() > deadline:
                raise TimeoutError("probe deadline exceeded")
            chunk = r.read1(16384) if hasattr(r, "read1") else r.read(16384)
            if not chunk:
                break
            buf += chunk
            if b"data:" in buf and sse_response(buf.decode("utf-8", "replace")):
                break  # SSE streams may stay open after answering; stop once we have the response
        raw = buf[:MAX_BYTES].decode("utf-8", "replace")
        sid = r.headers.get("Mcp-Session-Id") or session
    if not raw.strip():
        return None, sid
    if raw.lstrip().startswith("{"):
        return json.loads(raw), sid
    return sse_response(raw), sid


def sse_response(raw):
    for line in raw.splitlines():  # first complete data line that is a JSON-RPC response
        if line.startswith("data:"):
            try:
                msg = json.loads(line[5:].strip())
            except json.JSONDecodeError:
                continue
            if isinstance(msg, dict) and ("result" in msg or "error" in msg):
                return msg
    return None


def probe(url):
    """Return (status, tools). status: 'auth' | 'open' | 'down'."""
    if not public_host(url):
        return "down", []
    dl = time.monotonic() + PROBE_DEADLINE
    try:
        init, sid = rpc(url, deadline=dl, body={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "agentguard", "version": "0.1"}}})
        if not init or "error" in init:
            return "down", []
        try:
            rpc(url, {"jsonrpc": "2.0", "method": "notifications/initialized"}, sid, deadline=dl)
        except urllib.error.HTTPError:
            pass  # many servers answer 202/4xx to notifications; tools/list is what matters
        res, _ = rpc(url, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, sid, deadline=dl)
        tools = (res or {}).get("result", {}).get("tools", [])
        return "open", tools if isinstance(tools, list) else []
    except urllib.error.HTTPError as e:
        return ("auth" if e.code in (401, 403) else "down"), []
    except Exception:
        return "down", []


def assess(s, do_probe=True):
    lst = lambda v: [x for x in v if isinstance(x, dict)] if isinstance(v, list) else []  # registry data is untrusted
    name, findings, notes, tools = str(s.get("name") or "unnamed"), [], [], []
    for r in lst(s.get("remotes"))[:3]:  # cap per-server probe work
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
            if ev.get("isSecret") and is_secret_literal("SECRET", str(ev.get("default") or "")):  # "guest"/"test" defaults are not leaks
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


BASE = os.environ.get("AG_BASE_URL", "https://agentguard.vercel.app").rstrip("/")
GRADE_ORDER = "FDCBA"


def shard_of(sl):
    return sl[-8:-6]  # first 2 hex chars of the slug's hash suffix: 256 shards


def compact(r):
    """What the public page needs; keeps 69k records small enough for a static deploy."""
    return {"n": r["name"], "t": r["title"][:120], "d": r["description"][:400], "v": r["version"][:40],
            "r": r["repo"] if r["repo"].startswith("https://") else "", "s": r["score"], "g": r["grade"],
            "f": [[x["severity"], x["rule"], x["message"][:300]] for x in r["findings"][:20]],
            "o": r["notes"][:6], "k": r["tools"][:30]}


SERVER_JS = """
const $=(t,txt,cls)=>{const e=document.createElement(t);if(txt!=null)e.textContent=txt;if(cls)e.className=cls;return e};
const sl=location.pathname.split('/').filter(Boolean).pop().replace(/\\.html$/,'');
const m=document.getElementById('m');
if(!/^[a-z0-9-]{1,100}$/.test(sl)){m.replaceChildren($('p','Unknown server.'))}else{
fetch('/d/'+sl.slice(-8,-6)+'.json').then(r=>r.json()).then(d=>{const r=d[sl];if(!r){m.replaceChildren($('p','Unknown server.'));return}
document.title='Is '+r.t+' MCP server safe? Grade '+r.g;
const h=$('h1',r.t+' ');h.className='wrap';h.append($('span',r.g,'g g'+r.g));
const k=$('div',null,'card');k.append($('h2','Findings'));
if(!r.f.length)k.append($('p','No issues found by current checks.'));
r.f.forEach(f=>{const p=$('p',null,'wrap');p.append($('b',f[0]+' '+f[1]+': '),f[2]);k.append(p)});
const c=$('div',null,'card');c.append($('h2','What was checked'));r.o.forEach(o=>c.append($('p',o,'wrap')));
c.append($('p','Public tools: '+(r.k.join(', ')||'not listed publicly'),'wrap'));
const b=$('div',null,'card');b.append($('h2','Maintainer? Add the badge'),
 $('pre','[![agentguard](BASE/badge/'+sl+'.svg)](BASE/s/'+sl+')'));
m.replaceChildren($('p',r.n+' · v'+r.v+' · score '+r.s+'/100','mut wrap'),h,$('p',r.d,'wrap'),k,c,b)})
.catch(()=>m.replaceChildren($('p','Could not load data.')))}
"""

SEARCH_JS = """
const $=(t,txt,cls)=>{const e=document.createElement(t);if(txt!=null)e.textContent=txt;if(cls)e.className=cls;return e};
const q=document.getElementById('q'),out=document.getElementById('res');let L=null;
q.addEventListener('input',async()=>{const v=q.value.trim().toLowerCase();if(v.length<2){out.replaceChildren();return}
if(!L)L=await (await fetch('/list.json')).json();
const hits=L.filter(x=>x[0].includes(v)||x[1].toLowerCase().includes(v)).slice(0,50);
out.replaceChildren(...hits.map(x=>{const tr=$('tr'),a=$('a',x[1]);a.href='/s/'+x[0];
const td=$('td',null,'wrap');td.append(a);const g=$('td');g.append($('span',x[2],'g g'+x[2]));tr.append(g,td,$('td',String(x[3])));return tr}))});
"""


def write_site(results, out):
    os.makedirs(f"{out}/s", exist_ok=True)
    os.makedirs(f"{out}/d", exist_ok=True)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    shards, listing, notable = {}, [], []
    for r in results:
        sl = slug(r["name"])
        shards.setdefault(shard_of(sl), {})[sl] = compact(r)
        listing.append([sl, r["title"][:120], r["grade"], len(r["findings"])])
        if r["grade"] != "A":
            notable.append((sl, r))
    for k, v in shards.items():
        with open(f"{out}/d/{k}.json", "w", encoding="utf-8") as fh:
            json.dump(v, fh, separators=(",", ":"))
    with open(f"{out}/list.json", "w", encoding="utf-8") as fh:
        json.dump(listing, fh, separators=(",", ":"))

    # static, crawlable pages only where there is something to say (grade below A); /s/<slug> covers the rest
    for sl, r in notable:
        rows = "".join(f"<tr><td>{esc(x['severity'])}</td><td>{esc(x['rule'])}</td><td class='wrap'>{esc(x['message'])}</td></tr>"
                       for x in r["findings"])
        notes = "".join(f"<li class='wrap'>{esc(n)}</li>" for n in r["notes"])
        tools = ", ".join(esc(t) for t in r["tools"][:30]) or "not listed publicly"
        md = f"[![agentguard]({BASE}/badge/{sl}.svg)]({BASE}/s/{sl})"
        body = (f"<p><a href='/'>← All servers</a></p><h1 class='wrap'>{esc(r['title'])} {g(r['grade'])}</h1>"
                f"<p class='mut wrap'>{esc(r['name'])} · v{esc(r['version'])} · score {r['score']}/100 · checked {now}</p>"
                f"<p class='wrap'>{esc(r['description'][:600])}</p>"
                + (f"<p class='wrap'>Source: <a rel='nofollow' href='{esc(r['repo'])}'>{esc(r['repo'])}</a></p>" if r['repo'].startswith("https://") else "")
                + f"<div class='card'><h2>Findings</h2><table><tr><th>Severity</th><th>Rule</th><th>Detail</th></tr>{rows}</table></div>"
                f"<div class='card'><h2>What was checked</h2><ul>{notes}</ul><p class='wrap'>Public tools: {tools}</p></div>"
                f"<div class='card'><h2>Maintainer? Fix, then add the badge</h2><p>Grades refresh daily.</p><pre class='wrap'>{esc(md)}</pre></div>")
        with open(f"{out}/s/{sl}.html", "w", encoding="utf-8") as fh:
            fh.write(page(f"Is {r['title']} MCP server safe? Grade {r['grade']}", body,
                          f"agentguard security grade {r['grade']} for the {r['title']} MCP server: findings, auth, tools."))
    with open(f"{out}/s.html", "w", encoding="utf-8") as fh:  # client-rendered fallback for every other server
        fh.write(page("MCP server security grade: agentguard", "<p><a href='/'>← All servers</a></p><div id='m'><p>Loading…</p></div>"
                      f"<script>{SERVER_JS.replace('BASE', BASE)}</script>", "agentguard security grade for an MCP server."))

    counts = {k: sum(r["grade"] == k for r in results) for k in "ABCDF"}
    open_n = sum(any(x["rule"] == "AG005" for x in r["findings"]) for r in results)
    worst = sorted(notable, key=lambda x: (x[1]["score"], x[1]["name"]))[:100]
    rows = "".join(f"<tr><td>{g(r['grade'])}</td><td class='wrap'><a href='/s/{sl}'>{esc(r['title'])}</a>"
                   f"<br><span class='mut'>{esc(r['name'])}</span></td><td>{len(r['findings'])}</td></tr>" for sl, r in worst)
    body = (f"<h1>Is your AI agent's MCP server safe?</h1>"
            f"<p>agentguard grades every server in the official MCP registry for leaked secrets, plain-HTTP endpoints, "
            f"unauthenticated tools and poisoned tool descriptions. Updated daily. Last run {now}.</p>"
            f"<div class='card'><b>{len(results):,}</b> servers · " + " · ".join(f"{g(k)} {v:,}" for k, v in counts.items())
            + f" · <b>{open_n:,}</b> list tools to anyone without auth</div>"
            f"<div class='card'><h2>Scan your own config, free</h2><pre>git clone https://github.com/anardimontlv/agentguard &amp;&amp; cd agentguard\n"
            f"python3 -m agentguard.scan ~/.cursor/mcp.json</pre><p class='mut'>Works on Claude Desktop, Claude Code (.mcp.json), Cursor and VS Code configs. "
            f"Runs locally; nothing leaves your machine.</p></div>"
            f"<input id='q' placeholder='Search {len(results):,} servers…' aria-label='Search servers'>"
            f"<table><tbody id='res'></tbody></table>"
            f"<h2>Lowest grades today</h2><table><thead><tr><th>Grade</th><th>Server</th><th>Findings</th></tr></thead><tbody>{rows}</tbody></table>"
            f"<script>{SEARCH_JS}</script>")
    with open(f"{out}/index.html", "w", encoding="utf-8") as fh:
        fh.write(page("MCP Server Security Index: agentguard", body, "Daily security grades for every MCP server in the official registry."))
    with open(f"{out}/stats.json", "w", encoding="utf-8") as fh:
        json.dump({"generated": now, "servers": len(results), "grades": counts, "open": open_n,
                   "rules": {k: sum(x["rule"] == k for r in results for x in r["findings"]) for k in
                             sorted({x["rule"] for r in results for x in r["findings"]})}}, fh)
    urls = "".join(f"<url><loc>{BASE}/s/{sl}</loc></url>" for sl, _ in notable[:49000])
    with open(f"{out}/sitemap.xml", "w", encoding="utf-8") as fh:
        fh.write(f'<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                 f'<url><loc>{BASE}/</loc></url>{urls}</urlset>')
    with open(f"{out}/robots.txt", "w", encoding="utf-8") as fh:
        fh.write(f"User-agent: *\nAllow: /\nSitemap: {BASE}/sitemap.xml\n")


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
    print(f"indexed {len(results)} servers into {a.out}/", file=sys.stderr)


if __name__ == "__main__":
    main()
