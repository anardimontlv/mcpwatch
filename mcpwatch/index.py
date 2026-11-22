#!/usr/bin/env python3
"""Build the public mcpwatch index from the official MCP registry.

  python3 -m mcpwatch.index --out site [--limit N] [--no-probe]

Remote servers get a read-only MCP handshake + tools/list (no tool is ever called).
Package servers get static checks only: third-party code is never run.
"""
import argparse, html, json, os, re, sys, time, urllib.error, urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib, http.client, ipaddress, socket, threading
from urllib.parse import urlsplit
from mcpwatch.scan import scan_server, scan_tools, score, badge, safe_url, is_secret_literal, RULES_VERSION
from mcpwatch.watch import fingerprints, registry_keys, shard2, diff
from mcpwatch.webscan import write_scan_assets

REGISTRY = "https://registry.modelcontextprotocol.io/v0/servers"
UA = "mcpwatch-index/0.2 (+https://www.mcpwatch.io/probe)"
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


_host_slots, _host_lock = {}, threading.Lock()
PER_HOST = 2  # never more than 2 concurrent probes to one hostname (shared hosting has many servers)


def probe(url):
    """Return (status, tools). status: 'auth' | 'open' | 'down'."""
    if not public_host(url):
        return "down", []
    host = (urlsplit(url).hostname or "").lower()
    with _host_lock:
        slot = _host_slots.setdefault(host, threading.Semaphore(PER_HOST))
    with slot:
        return _probe(url)


def _close(url, sid):
    """End the MCP session (DELETE per the streamable-HTTP transport spec) so servers don't keep it open."""
    if not sid:
        return
    try:
        req = urllib.request.Request(url, method="DELETE", headers={"User-Agent": UA, "Mcp-Session-Id": sid})
        _opener.open(req, timeout=5).close()
    except Exception:
        pass  # best effort: many servers don't support DELETE


def _probe(url):
    dl = time.monotonic() + PROBE_DEADLINE
    sid = None
    try:
        init, sid = rpc(url, deadline=dl, body={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "mcpwatch", "version": "0.1"}}})
        if not init or "error" in init:
            return "down", []
        try:
            rpc(url, {"jsonrpc": "2.0", "method": "notifications/initialized"}, sid, deadline=dl)
        except urllib.error.HTTPError:
            pass  # many servers answer 202/4xx to notifications; tools/list is what matters
        res, _ = rpc(url, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, sid, deadline=dl)
        tools = (res or {}).get("result", {}).get("tools", [])
        _close(url, sid)
        return "open", tools if isinstance(tools, list) else []
    except urllib.error.HTTPError as e:
        # only 401 means "auth required" (MCP spec); 403 is usually a firewall/rate limit: unknown, not auth
        return ("auth" if e.code == 401 else "down"), []
    except Exception:
        return "down", []


def load_optout():
    """Server names or hostnames whose owners asked us not to probe (one per line, # comments)."""
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "optout.txt")
    try:
        with open(path, encoding="utf-8") as fh:
            return {l.split("#", 1)[0].strip().lower() for l in fh} - {""}
    except OSError:
        return set()


OPTOUT = load_optout()


def opted_out(name, url):
    host = (urlsplit(url).hostname or "").lower() if url else ""
    return name.lower() in OPTOUT or (host and host in OPTOUT)


def assess(s, do_probe=True):
    lst = lambda v: [x for x in v if isinstance(x, dict)] if isinstance(v, list) else []  # registry data is untrusted
    name, findings, notes, tools = str(s.get("name") or "unnamed"), [], [], []
    auth = "none"  # none: no probeable remote; open/auth/down: first definitive probe result wins
    # sorted: registry order can change between runs and must not change which endpoints/tools we fingerprint
    for r in sorted(lst(s.get("remotes")), key=lambda r: str(r.get("url", "")))[:3]:  # cap per-server probe work
        url = r.get("url") if isinstance(r.get("url"), str) else ""
        hdrs = {str(h.get("name", "")): h.get("value", "") for h in lst(r.get("headers"))}
        cfg = {"url": url, "headers": hdrs}
        if any(h.get("isRequired") or h.get("isSecret") for h in lst(r.get("headers"))):
            cfg["headers"] = {**hdrs, "Authorization": "${declared}"}
        f = [x for x in scan_server(name, cfg) if x["rule"] != "MW005"]  # MW005 decided by the live probe below
        findings += f
        if do_probe and opted_out(name, url):
            notes.append(f"{safe_url(url)}: not probed (owner opt-out)")
        elif do_probe and "{" not in url and url.startswith("http"):
            status, t = probe(url)
            # order-independent: any open endpoint makes the server open; otherwise auth beats down
            auth = max(auth, status, key=["none", "down", "auth", "open"].index)
            notes.append(f"{safe_url(url)}: {'requires auth' if status == 'auth' else 'answers without auth' if status == 'open' else 'not reachable'}")
            if status == "open" and t:
                findings.append({"server": name, "rule": "MW005", "severity": "low",
                                 "message": f"Remote endpoint lists {len(t)} tool(s) to anyone, no credentials needed."})
                if not tools:  # first open endpoint (in sorted order) defines the fingerprints
                    tools = t
                    findings += scan_tools(t, name)
    pk = {}
    for p in lst(s.get("packages")):
        ident, ver = str(p.get("identifier", "")), str(p.get("version", ""))
        pk[ident[:100]] = ver[:40]
        if not ver or ver in {"latest", "*"}:
            findings.append({"server": name, "rule": "MW002", "severity": "medium", "message": f"Package {ident} is published without a fixed version."})
        for ev in lst(p.get("environmentVariables")):
            if ev.get("isSecret") and is_secret_literal("SECRET", str(ev.get("default") or "")):  # "guest"/"test" defaults are not leaks
                findings.append({"server": name, "rule": "MW001", "severity": "high", "message": f"Secret env {ev.get('name')} ships with a default value."})
        notes.append(f"{p.get('registryType', 'package')}: {ident}@{ver or '?'} (static checks only; code not executed)")
    # one finding per rule per message is enough for the public page
    uniq = list({(x["rule"], x["message"]): x for x in findings}.values())
    pts, grade = score(uniq)
    repo = s.get("repository") if isinstance(s.get("repository"), dict) else {}
    return {"name": name, "title": str(s.get("title") or name), "description": str(s.get("description", "")), "version": str(s.get("version", "")),
            "repo": str(repo.get("url", "")), "score": pts, "grade": grade, "findings": uniq,
            "notes": notes, "tools": [str(t.get("name", "?")) for t in lst(tools)][:100],
            "auth": auth, "fp": fingerprints(lst(tools)) if auth == "open" else None, "pk": pk,
            "verified": datetime.now(timezone.utc).strftime("%Y-%m-%d") if auth == "open" else None,
            "keys": registry_keys(s), "tool_text": {str(t.get("name", "?")): str(t.get("description", ""))[:4000] for t in lst(tools)}}


def slug(name):
    # hash suffix: "a.b/c" and "a-b/c" must never share a page or badge
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:80] + "-" + hashlib.sha256(name.encode()).hexdigest()[:8]


# Design tokens: docs/brand.md has the hex values and contrast ratios. Grade chip colours are theme-independent.
CSS = """:root{color-scheme:light dark;--bg:#fff;--sf:#f6f8f9;--fg:#0e1417;--mut:#55616b;--line:#e1e6ea;--acc:#0f766e;--on:#fff;--soft:#e6f4f2;--r:10px;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
@media (prefers-color-scheme:dark){:root{--bg:#0b0f12;--sf:#12191d;--fg:#e6edf0;--mut:#9aa7b0;--line:#243038;--acc:#2dd4bf;--on:#042f2b;--soft:#0f2a28}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.6 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;-webkit-font-smoothing:antialiased}
a{color:var(--acc);text-underline-offset:2px}a:hover{text-decoration-thickness:2px}
:focus-visible{outline:2px solid var(--acc);outline-offset:2px;border-radius:4px}
.in,main{max-width:1040px;margin:0 auto;padding:0 16px}main{padding-top:40px;padding-bottom:24px}
.skip{position:absolute;left:-999px}.skip:focus{left:16px;top:8px;z-index:9;background:var(--bg);padding:8px 12px}
.top{border-bottom:1px solid var(--line)}.top .in{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:4px 24px;min-height:60px}
.brand{display:inline-flex;align-items:center;gap:10px;color:var(--fg);font-weight:650;font-size:1.0625rem;letter-spacing:-.01em;text-decoration:none}
.logo rect{fill:var(--acc)}.logo .k{stroke:var(--on)}.logo circle{fill:var(--on)}
nav{display:flex;flex-wrap:wrap;gap:0 20px;font-size:.9375rem}nav a{color:var(--mut);text-decoration:none;padding:8px 0}nav a:hover{color:var(--fg)}
footer{border-top:1px solid var(--line);margin-top:64px;font-size:.875rem;color:var(--mut)}footer .in{display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:0 24px;padding:16px}footer p{margin:8px 0}footer nav{gap:0 16px;font-size:inherit}
h1,h2,h3{line-height:1.2;letter-spacing:-.02em;margin:0 0 .5em}h1{font-size:clamp(1.875rem,4.6vw,2.75rem)}
h2{font-size:1.375rem;margin-top:2.4em}h3{font-size:1rem;margin:0 0 .25em}p{margin:0 0 1em}ul{padding-left:1.2em}li{margin:.3em 0}
.mut{color:var(--mut)}.sm{font-size:.875rem}.wrap{overflow-wrap:anywhere}.min0{min-width:0}.crumb{font-size:.875rem;margin-bottom:20px}
.vh{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
.card{background:var(--sf);border:1px solid var(--line);border-radius:var(--r);padding:20px;margin:16px 0}.card h2{font-size:1.0625rem;margin-top:0}
.hero{max-width:780px;padding-bottom:8px}.lede{font-size:1.125rem;color:var(--mut)}
.eye{display:inline-block;font:500 .8125rem/1 var(--mono);color:var(--acc);background:var(--soft);padding:6px 10px;border-radius:99px;margin-bottom:16px}
.cta{display:flex;flex-wrap:wrap;gap:12px;margin:28px 0 20px}
.btn{display:inline-flex;align-items:center;min-height:44px;padding:0 18px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--fg);font-weight:600;text-decoration:none;transition:border-color .15s,box-shadow .15s}
.btn:hover{border-color:var(--mut)}.btn.pri{background:var(--acc);border-color:var(--acc);color:var(--on)}
button.btn{font:inherit;font-weight:600;cursor:pointer}
textarea{width:100%;min-height:220px;padding:12px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--fg);font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;resize:vertical}
textarea:focus{outline:2px solid var(--acc);outline-offset:1px}.btn.pri:hover{box-shadow:inset 0 0 0 99px rgb(0 0 0/.14)}
.trust{list-style:none;padding:0;margin:0;display:flex;flex-wrap:wrap;gap:4px 20px;font-size:.875rem;color:var(--mut)}.trust li::before{content:"\\2713\\00a0";color:var(--acc);font-weight:700}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:40px 0 12px}
.stat{border:1px solid var(--line);border-radius:var(--r);padding:14px 16px}.stat b{display:block;font-size:clamp(1.25rem,5vw,1.625rem);letter-spacing:-.02em;font-variant-numeric:tabular-nums}.stat span{font-size:.8125rem;color:var(--mut)}
.dist{display:flex;height:8px;border-radius:4px;overflow:hidden;background:var(--line);margin:20px 0 10px}
.legend{list-style:none;padding:0;margin:0;display:flex;flex-wrap:wrap;gap:4px 18px;font-size:.875rem;font-variant-numeric:tabular-nums}
.steps{list-style:none;padding:0;display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px;counter-reset:s}
.steps li{margin:0;border:1px solid var(--line);border-radius:var(--r);padding:16px;background:var(--sf);min-width:0}
.steps h3::before{counter-increment:s;content:counter(s);display:inline-grid;place-items:center;width:22px;height:22px;margin-right:8px;border-radius:50%;background:var(--acc);color:var(--on);font-size:.75rem}
code,pre{font-family:var(--mono);font-size:.875em}pre{margin:0;padding:12px 14px;background:var(--bg);border:1px solid var(--line);border-radius:8px;white-space:pre-wrap;overflow-wrap:anywhere;font-size:.8125rem;line-height:1.6}
.card pre,.steps pre{margin-top:8px}
input[type=search]{width:100%;min-height:48px;padding:0 16px;border:1px solid var(--line);border-radius:var(--r);background:var(--bg);color:var(--fg);font:inherit}input[type=search]:focus-visible{outline-offset:0;border-color:var(--acc)}
table{width:100%;border-collapse:separate;border-spacing:0;border:1px solid var(--line);border-radius:var(--r);overflow:hidden;font-size:.9375rem;background:var(--bg);margin:12px 0}
td,th{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top}tr:last-child td{border-bottom:0}
th{font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;color:var(--mut);background:var(--sf)}.n{text-align:right;font-variant-numeric:tabular-nums}
.g{display:inline-grid;place-items:center;min-width:1.75rem;height:1.5rem;padding:0 6px;border-radius:6px;color:#fff;font-weight:700;font-size:.875rem;line-height:1}
.g.lg{min-width:3.25rem;height:3.25rem;font-size:1.75rem;border-radius:12px;flex:none}
.gA{background:#1a7f37}.gB{background:#4d7c0f}.gC{background:#8a5a00}.gD{background:#bc4c00}.gF{background:#c4222e}
.sh{display:flex;gap:16px;align-items:center;margin-bottom:16px}.sh h1{margin:0}.sh p{margin:4px 0 0}
.sev{display:inline-block;padding:0 6px;border:1px solid var(--line);border-radius:4px;font-size:.8125rem;font-weight:600;white-space:nowrap}
.feed{list-style:none;padding:0}.feed li{padding:12px 0;border-top:1px solid var(--line)}.chg{display:flex;flex-wrap:wrap;gap:6px;margin-top:6px}
.tag{font:.8125rem/1.5 var(--mono);padding:2px 8px;border-radius:6px;background:var(--sf);border:1px solid var(--line);overflow-wrap:anywhere;min-width:0}
.tiers{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:16px;margin:32px 0}
.tier{display:flex;flex-direction:column;border:1px solid var(--line);border-radius:var(--r);padding:24px}.tier h2{margin:0;font-size:1.0625rem}.tier ul{flex:1;margin:16px 0}
.price{font-size:2.25rem;font-weight:700;letter-spacing:-.03em;margin:8px 0 0}.price small{font-size:.875rem;font-weight:400;color:var(--mut);letter-spacing:0}
.soon{margin:0;padding:10px;border:1px dashed var(--line);border-radius:8px;text-align:center;color:var(--mut);font-size:.875rem}
.prose{max-width:720px}.prose h2{font-size:1.125rem;margin-top:2em}
@media (max-width:600px){.card{padding:16px}td,th{padding:8px}}
@media (prefers-reduced-motion:reduce){*{transition:none!important}}"""

_MARK = ('<rect width="24" height="24" rx="6"{f}/><g fill="none" stroke-width="2" stroke-linecap="round">'
         '<path class="k"{s} d="M12 5.5a6.5 6.5 0 1 0 6.5 6.5"/><path class="k"{s} d="M12 12l4.6-4.6"/></g><circle cx="12" cy="12" r="1.8"{c}/>')
# radar ring with a gap: the sweep points at the part that changed
LOGO = f'<svg class="logo" width="24" height="24" viewBox="0 0 24 24" aria-hidden="true">{_MARK.format(f="", s="", c="")}</svg>'
_FAV = _MARK.format(f=' fill="#0f766e"', s=' stroke="#fff"', c=' fill="#fff"')
FAVICON = "data:image/svg+xml," + urllib.request.quote('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">' + _FAV + '</svg>', safe="")
GH = "https://github.com/anardimontlv/mcpwatch"
HOW = GH + "/blob/main/docs/how-it-works.md"


def page(title, body, desc, noindex=False):
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            + ('<meta name="robots" content="noindex">' if noindex else '') +
            f'<title>{esc(title)}</title><meta name="description" content="{esc(desc)}"><link rel="icon" href="{FAVICON}"><style>{CSS}</style></head>'
            f'<body><a class="skip" href="#main">Skip to content</a><header class="top"><div class="in"><a class="brand" href="/">{LOGO}mcpwatch</a>'
            f'<nav aria-label="Main"><a href="/scan">Scan</a><a href="/changes">Radar</a><a href="/pricing">Pricing</a><a href="{GH}#quickstart">Docs</a><a href="{GH}">GitHub</a></nav></div></header>'
            f'<main id="main">{body}</main><footer><div class="in"><p>Automated, read-only checks. A grade is not a guarantee of safety. Servers listed here are third-party projects from the public MCP registry; mcpwatch does not sell, operate or endorse them. mcpwatch sells one product: developer security monitoring (<a href="/pricing">pricing</a>).</p>'
            f'<nav aria-label="Footer"><a href="/">Index</a><a href="/changes">Radar</a><a href="/pricing">Pricing</a><a href="{GH}">GitHub</a>'
            f'<a href="/terms">Terms</a><a href="/privacy">Privacy</a><a href="/refunds">Refunds</a></nav></div></footer></body></html>')


def g(grade, cls=""):
    return f'<span class="g g{grade}{cls}"><span class="vh">Grade </span>{grade}</span>'


def sev(s):
    return f"<span class='sev'>{esc(str(s).capitalize())}</span>"


BASE = os.environ.get("MCPWATCH_URL", "https://www.mcpwatch.io").rstrip("/")
DISPUTE = "https://github.com/anardimontlv/mcpwatch/issues/new?labels=dispute&title=Dispute%3A+"
GRADE_ORDER = "FDCBA"


def shard_of(sl):
    return sl[-8:-6]  # first 2 hex chars of the slug's hash suffix: 256 shards


def compact(r):
    """What the public page needs; keeps 69k records small enough for a static deploy."""
    return {"n": r["name"], "t": r["title"][:120], "d": r["description"][:400], "v": r["version"][:40],
            "r": r["repo"] if r["repo"].startswith("https://") else "", "s": r["score"], "g": r["grade"],
            "f": [[x["severity"], x["rule"], x["message"][:300]] for x in r["findings"][:20]],
            "o": r["notes"][:6], "k": r["tools"][:30], "h": r.get("fp"), "a": r.get("auth"), "p": r.get("pk") or {},
            "vd": r.get("verified"),  # last day the fingerprints were observed live ("v" is the version)
            "rv": RULES_VERSION}


SERVER_JS = """
const $=(t,txt,cls)=>{const e=document.createElement(t);if(txt!=null)e.textContent=txt;if(cls)e.className=cls;return e};
const card=t=>{const k=$('section',null,'card');k.append($('h2',t));return k};
const sl=location.pathname.split('/').filter(Boolean).pop().replace(/\\.html$/,'');
const m=document.getElementById('m');
if(!/^[a-z0-9-]{1,100}$/.test(sl)){m.replaceChildren($('p','Unknown server.'))}else{
fetch('/d/'+sl.slice(-8,-6)+'.json').then(r=>r.json()).then(d=>{const r=d[sl];if(!r){m.replaceChildren($('p','Unknown server.'));return}
document.title=r.t+' MCP server: security check (grade '+r.g+')';
const gr=$('span',null,'g lg g'+r.g);gr.append($('span','Grade ','vh'),r.g);
const tx=$('div',null,'min0');tx.append($('h1',r.t,'wrap'),$('p',r.n+' · v'+r.v+' · score '+r.s+'/100'+(r.vd?' · tools verified '+r.vd:''),'mut sm wrap'));
const hd=$('div',null,'sh');hd.append(gr,tx);const dl=$('a','dispute any finding');dl.href='DISPUTE'+encodeURIComponent(r.n);dl.rel='nofollow';
const hw=$('a','How grading works');hw.href='HOWURL';const nt=$('p','Automated, read-only signal from public data, not an audit or an accusation. Maintainers can ','mut sm');nt.append(dl,'. ',hw);
const top=[hd,nt,$('p',r.d,'wrap')];
const wp=$('p'),wa=$('a','Watch this server','btn');wa.href='/watch?add='+sl;wp.append(wa);top.push(wp);
if(/^https:\\/\\//.test(r.r)){const p=$('p','Source: ','wrap'),a=$('a',r.r);a.href=r.r;a.rel='nofollow';p.append(a);top.push(p)}
const k=card('Findings');
if(!r.f.length)k.append($('p','No issues found by current checks.','mut'));else{
const t=$('table'),hr=$('tr'),th=$('thead'),tb=$('tbody');['Severity','Rule','Detail'].forEach(x=>hr.append($('th',x)));th.append(hr);
r.f.forEach(f=>{const tr=$('tr'),s=$('td');s.append($('span',String(f[0]).charAt(0).toUpperCase()+String(f[0]).slice(1),'sev'));tr.append(s,$('td',f[1]),$('td',f[2],'wrap'));tb.append(tr)});
t.append(th,tb);k.append(t)}
const c=card('What was checked'),ul=$('ul');r.o.forEach(o=>ul.append($('li',o,'wrap')));
c.append(ul,$('p','Public tools: '+(r.k.join(', ')||'not listed publicly'),'wrap'));
const b=card('Maintainer? Add the badge');const d2=$('a','Dispute this grade');d2.href=dl.href;d2.rel='nofollow';
const dp=$('p','Think a finding is wrong? ');dp.append(d2,'.');b.append(dp,$('pre','[![mcpwatch](BASE/badge/'+sl+'.svg)](BASE/s/'+sl+')'));
m.replaceChildren(...top,k,c,b)})
.catch(()=>m.replaceChildren($('p','Could not load data.')))}
"""

CHANGES_JS = """
const $=(t,txt,cls)=>{const e=document.createElement(t);if(txt!=null)e.textContent=txt;if(cls)e.className=cls;return e};
const box=document.getElementById('c');
const row=it=>{const li=$('li'),a=$('a',it.name,'wrap'),cs=$('div',null,'chg');a.href='/s/'+it.slug;
const nb=it.notable||[];nb.forEach(w=>cs.append($('span',w,'tag')));
const covered=k=>(k==='auth_dropped'&&nb.some(w=>w.includes('credentials')))||(k==='grade_changed'&&nb.some(w=>w.startsWith('grade dropped')));
it.changes.filter(c=>!covered(c.kind)).forEach(c=>cs.append($('span',c.kind.replace(/_/g,' ')+' '+c.detail,'tag')));li.append(a,cs);return li};
fetch('/changes.json').then(r=>r.json()).then(days=>{box.replaceChildren();
if(!days.length){box.append($('p','No history yet: the radar records its first baseline today. Changes appear from tomorrow.','card'));return}
days.forEach(d=>{const s=$('section'),hot=d.items.filter(i=>i.notable&&i.notable.length),rest=d.items.filter(i=>!(i.notable&&i.notable.length));
s.append($('h2',d.date));
const h=$('h3',hot.length?hot.length+' notable change'+(hot.length===1?'':'s'):'No notable changes');s.append(h);
if(hot.length){const ul=$('ul',null,'feed');hot.slice(0,200).forEach(i=>ul.append(row(i)));s.append(ul)}
else s.append($('p','Nothing matched our checks for dropped auth, falling grades or suspicious tool text.','mut'));
if(rest.length){const det=$('details'),sm=$('summary',rest.length+' routine update'+(rest.length===1?'':'s')+' (reworded descriptions, new or removed tools)');
const ul=$('ul',null,'feed');rest.slice(0,300).forEach(i=>ul.append(row(i)));det.append(sm,ul);s.append(det)}
box.append(s)})}).catch(()=>box.replaceChildren($('p','Could not load the feed.')));
"""

SEARCH_JS = """
const $=(t,txt,cls)=>{const e=document.createElement(t);if(txt!=null)e.textContent=txt;if(cls)e.className=cls;return e};
const q=document.getElementById('q'),out=document.getElementById('res'),T=document.getElementById('rt'),rc=document.getElementById('rc');let L=null;
q.addEventListener('input',async()=>{const v=q.value.trim().toLowerCase();if(v.length<2){out.replaceChildren();T.hidden=true;rc.textContent='';return}
if(!L){try{L=await (await fetch('/list.json')).json()}catch(e){rc.textContent='Could not load the index.';return}}
const all=L.filter(x=>x[0].includes(v)||x[1].toLowerCase().includes(v)),hits=all.slice(0,50);
rc.textContent=!all.length?'No servers match.':all.length>50?'Showing 50 of '+all.length.toLocaleString()+' matches.':all.length+(all.length===1?' match.':' matches.');
T.hidden=!hits.length;
out.replaceChildren(...hits.map(x=>{const tr=$('tr'),a=$('a',x[1]);a.href='/s/'+x[0];
const td=$('td',null,'wrap');td.append(a);const g=$('td'),c=$('span',null,'g g'+x[2]);c.append($('span','Grade ','vh'),x[2]);g.append(c);tr.append(g,td,$('td',String(x[3]),'n'));return tr}))});
"""


def write_site(results, out, changes=None):
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
    os.makedirs(f"{out}/m", exist_ok=True)  # package/url -> slug, for `mcpwatch lock`
    claims = {}
    for r in results:
        for k in set(r.get("keys", [])):
            claims.setdefault(k, []).append(slug(r["name"]))
    lookup = {}
    for k, sls in claims.items():  # a key claimed twice is ambiguous: never silently pick one (squatting)
        lookup.setdefault(shard2(k), {})[k] = sls[0] if len(sls) == 1 else sorted(sls)
    for k, v in lookup.items():
        with open(f"{out}/m/{k}.json", "w", encoding="utf-8") as fh:
            json.dump(v, fh, separators=(",", ":"))
    web = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web")
    entity = esc(os.environ.get("MCPWATCH_LEGAL_ENTITY", "the mcpwatch project"))
    titles = {"pricing": "Pricing", "terms": "Terms of Service", "privacy": "Privacy Policy", "refunds": "Refund Policy",
              "probe": "How the index checks servers", "scan": "Scan your MCP config", "watch": "Watch servers"}
    for name, title in titles.items():
        with open(os.path.join(web, f"{name}.html"), encoding="utf-8") as fh:
            body = fh.read().replace("{{LEGAL_ENTITY}}", entity)
        with open(f"{out}/{name}.html", "w", encoding="utf-8") as fh:
            fh.write(page(f"{title}: mcpwatch", body, f"mcpwatch {title.lower()}."))
    with open(f"{out}/404.html", "w", encoding="utf-8") as fh:  # Vercel serves this for any unknown path
        fh.write(page("Page not found: mcpwatch",
                      "<div class='hero'><h1>Page not found</h1><p class='lede'>That address doesn't exist on mcpwatch. "
                      "Looking for a server? Search the index from the home page.</p>"
                      "<div class='cta'><a class='btn pri' href='/'>Search the index</a><a class='btn' href='/scan'>Scan your config</a></div></div>",
                      "Page not found.", noindex=True))
    write_scan_assets(out)  # /scan.js for the in-browser scanner, /watch.js for the watchlist
    with open(f"{out}/changes.json", "w", encoding="utf-8") as fh:
        json.dump(changes or [], fh, separators=(",", ":"))
    with open(f"{out}/changes.html", "w", encoding="utf-8") as fh:
        fh.write(page("MCP rug-pull radar: tool changes across every public MCP server",
                      "<div class='hero'><span class='eye'>Updated daily</span><h1>Rug-pull radar</h1><p class='lede'>Every remote MCP server that lists its tools publicly is fingerprinted daily. "
                      "When a tool's description or input schema changes after you trusted it, it shows up here. Last 14 days.</p></div>"
                      "<div id='c'><p class='mut'>Loading…</p></div>" f"<script>{CHANGES_JS}</script>",
                      "Daily feed of MCP tool changes across every server in the official registry."))

    # static, crawlable pages only where there is something to say (grade below A); /s/<slug> covers the rest
    for sl, r in notable:
        rows = "".join(f"<tr><td>{sev(x['severity'])}</td><td>{esc(x['rule'])}</td><td class='wrap'>{esc(x['message'])}</td></tr>"
                       for x in r["findings"])
        notes = "".join(f"<li class='wrap'>{esc(n)}</li>" for n in r["notes"])
        tools = ", ".join(esc(t) for t in r["tools"][:30]) or "not listed publicly"
        md = f"[![mcpwatch]({BASE}/badge/{sl}.svg)]({BASE}/s/{sl})"
        body = (f"<p class='crumb'><a href='/'>← All servers</a></p><div class='sh'>{g(esc(r['grade']), ' lg')}<div class='min0'>"
                f"<h1 class='wrap'>{esc(r['title'])}</h1><p class='mut sm wrap'>{esc(r['name'])} · v{esc(r['version'])} · "
                f"score {esc(str(r['score']))}/100 · checked {now}</p></div></div>"
                f"<p class='mut sm'>Automated, read-only signal from public data, not an audit or an accusation. Maintainers can "
                f"<a rel='nofollow' href='{esc(DISPUTE + urllib.request.quote(r['name']))}'>dispute any finding</a>. <a href='{HOW}'>How grading works</a></p>"
                f"<p class='wrap'>{esc(r['description'][:600])}</p>"
                f"<p><a class='btn' href='/watch?add={esc(sl)}'>Watch this server</a></p>"
                + (f"<p class='wrap'>Source: <a rel='nofollow' href='{esc(r['repo'])}'>{esc(r['repo'])}</a></p>" if r['repo'].startswith("https://") else "")
                + f"<section class='card'><h2>Findings</h2><table><thead><tr><th>Severity</th><th>Rule</th><th>Detail</th></tr></thead><tbody>{rows}</tbody></table></section>"
                f"<section class='card'><h2>What was checked</h2><ul>{notes}</ul><p class='wrap'>Public tools: {tools}</p></section>"
                f"<section class='card'><h2>Maintainer? Add the badge</h2><p>Grades refresh daily. "
                f"Think a finding is wrong? <a rel='nofollow' href='{esc(DISPUTE + urllib.request.quote(r['name']))}'>Dispute this grade</a>.</p>"
                f"<pre>{esc(md)}</pre></section>")
        with open(f"{out}/s/{sl}.html", "w", encoding="utf-8") as fh:
            fh.write(page(f"{r['title']} MCP server: security check (grade {r['grade']})", body,
                          f"Automated, read-only security check of the {r['title']} MCP server: grade, findings, auth, tools. Updated daily."))
    with open(f"{out}/s.html", "w", encoding="utf-8") as fh:  # client-rendered fallback for every other server
        fh.write(page("MCP server security grade: mcpwatch", "<p class='crumb'><a href='/'>← All servers</a></p><div id='m'><p class='mut'>Loading…</p></div>"
                      f"<script>{SERVER_JS.replace('BASE', BASE).replace('DISPUTE', DISPUTE).replace('HOWURL', HOW)}</script>", "mcpwatch security grade for an MCP server.", noindex=True))

    counts = {k: sum(r["grade"] == k for r in results) for k in "ABCDF"}
    open_n = sum(any(x["rule"] == "MW005" for x in r["findings"]) for r in results)
    total = max(len(results), 1)
    dist = "".join(f"<span class='g{k}' style='width:{v * 100 / total:.3f}%'></span>" for k, v in counts.items() if v)
    latest = (changes or [{}])[0]
    radar = f"{len(latest['items']):,}" if latest.get("items") is not None else "–"
    radar_lbl = f"servers changed on {esc(latest['date'])}" if latest.get("date") else "servers changed (baseline pending)"
    steps = [("Scan", "Flag leaked secrets, unpinned packages, plain HTTP and root filesystem access.", "mcpwatch-scan ~/.cursor/mcp.json"),
             ("Lock", "Pin the exact tools your servers expose today. Commit mcpwatch.lock.", "mcpwatch lock .mcp.json"),
             ("Check", "Fail CI when any pinned tool changes: exit 1 on drift.", "mcpwatch check .mcp.json")]
    body = (f"<section class='hero'><span class='eye'>Rug-pull radar for MCP</span><h1>Know when the tools your AI agents trust change.</h1>"
            f"<p class='lede'>MCP servers can rewrite a tool's instructions after you approve it: a rug pull. mcpwatch checks every server in the "
            f"official MCP registry daily, fingerprints the tools of every remote server it can reach, grades them for leaked secrets, "
            f"plain-HTTP endpoints, unauthenticated access and poisoned descriptions, and fails your CI when a tool you pinned changes.</p>"
            f"<div class='cta'><a class='btn pri' href='/scan'>Scan your config</a><a class='btn' href='/changes'>See today's radar →</a></div>"
            f"<ul class='trust'><li>Read-only checks</li><li>Never runs third-party code</li><li>Nothing leaves your machine</li>"
            f"<li>No cookies or trackers</li></ul></section>"
            f"<section aria-label='Index statistics'><div class='stats'>"
            f"<div class='stat'><b>{len(results):,}</b><span>servers graded daily</span></div>"
            f"<div class='stat'><b>{open_n:,}</b><span>list tools to anyone, no auth</span></div>"
            f"<div class='stat'><b>{radar}</b><span>{radar_lbl}</span></div>"
            f"<div class='stat'><b>{now}</b><span>last run (UTC)</span></div></div>"
            f"<div class='dist' aria-hidden='true'>{dist}</div><ul class='legend'>"
            + "".join(f"<li>{g(k)} {v:,}</li>" for k, v in counts.items()) + "</ul></section>"
            f"<h2>Quickstart</h2><p class='mut'>Zero dependencies, Python 3.10+. Works with Claude Desktop, Claude Code (.mcp.json), Cursor and VS Code configs.</p>"
            f"<pre>pipx install mcpwatch-io</pre><ol class='steps'>"
            + "".join(f"<li><h3>{t}</h3><p class='mut sm'>{d}</p><pre>{esc(c)}</pre></li>" for t, d, c in steps) + "</ol>"
            f"<p class='sm'><a href='{GH}#github-action'>Run it as a GitHub Action →</a></p>"
            f"<h2><label for='q'>Look up a server</label></h2>"
            f"<input id='q' type='search' autocomplete='off' spellcheck='false' placeholder='Search {len(results):,} servers by name…'>"
            f"<p id='rc' class='mut sm' aria-live='polite'></p>"
            f"<table id='rt' hidden><thead><tr><th>Grade</th><th>Server</th><th class='n'>Findings</th></tr></thead><tbody id='res'></tbody></table>"
            f"<h2>Recent tool changes across the ecosystem</h2><p class='mut'>Every day mcpwatch compares each server's tools with the day before: "
            f"changed tool descriptions, added or removed tools, auth and grade changes.</p><p><a class='btn' href='/changes'>Open the radar →</a></p>"
            f"<script>{SEARCH_JS}</script>")
    with open(f"{out}/index.html", "w", encoding="utf-8") as fh:
        fh.write(page("MCP Server Security Index: mcpwatch", body, "Daily security grades for every MCP server in the official registry."))
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


def load_prev(d):
    prev = {}
    for f in os.listdir(d) if os.path.isdir(d) else []:
        if f.endswith(".json"):
            try:
                with open(os.path.join(d, f), encoding="utf-8") as fh:
                    prev.update(json.load(fh))
            except (OSError, ValueError):
                pass  # a corrupt shard only loses change detection for its servers
    return prev


def track_changes(results, prev, today=None):
    """Diff each server against yesterday; servers unreachable today keep yesterday's fingerprints (and their
    old verified date, so clients can fail on staleness)."""
    today = today or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    items = []
    for r in results:
        old = prev.get(slug(r["name"])) or {}
        if not old:
            continue
        if r["fp"] is None and old.get("h") and r["auth"] in ("down", "none"):
            r["fp"] = old["h"]  # unknown is not "all tools removed"
            vd = old.get("vd")  # only a real, non-future date may be carried forward
            r["verified"] = vd if isinstance(vd, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", vd) and vd <= today else None
        cur = {"h": r["fp"], "a": r["auth"] if r["auth"] != "down" else old.get("a"), "g": r["grade"], "p": r["pk"], "rv": RULES_VERSION}
        ch = diff(old, cur)
        if ch:
            full = {c["detail"]: r["tool_text"].get(c["detail"], "") for c in ch if c["kind"] in ("tool_changed", "tool_added")}
            why = notable_reasons(ch, full)
            items.append({"slug": slug(r["name"]), "name": r["name"], "changes": ch, "notable": why,
                          "new_text": {k: v[:300] for k, v in full.items()}})
    items.sort(key=lambda x: (not x["notable"], -sum(c["sev"] == "high" for c in x["changes"])))
    return items


def notable_reasons(changes, new_text):
    """Why a change matters beyond a routine update. Empty list = routine (rewording, new features)."""
    why = []
    if any(c["kind"] == "auth_dropped" for c in changes):
        why.append("endpoint stopped requiring credentials")
    for c in changes:
        if c["kind"] == "grade_changed" and re.fullmatch(r"[A-F] -> [A-F]", c["detail"]) and c["detail"][-1] > c["detail"][0]:
            why.append(f"grade dropped ({c['detail']})")
    added = {c["detail"] for c in changes if c["kind"] == "tool_added"}
    for f in scan_tools([{"name": n, "description": t} for n, t in new_text.items()], "radar"):
        if f["rule"] in ("MW101", "MW103"):
            why.append("new tool text matches a tool-poisoning pattern" if f["rule"] == "MW101" else "new tool text contains invisible characters")
        elif f["rule"] == "MW102" and any(n in f["message"] for n in added):
            why.append("a newly added tool can execute commands or delete data")
    return sorted(set(why))


def results_from_site(d):
    """Rebuild render inputs from a published site's d/ shards (render-only mode: no registry fetch, no probes)."""
    out = []
    for name, rec in sorted(load_prev(os.path.join(d, "d")).items()):
        out.append({"name": rec.get("n", name), "title": rec.get("t", ""), "description": rec.get("d", ""), "version": rec.get("v", ""),
                    "repo": rec.get("r", ""), "score": rec.get("s", 100), "grade": rec.get("g", "A"),
                    "findings": [{"server": rec.get("n", name), "severity": f[0], "rule": f[1], "message": f[2]} for f in rec.get("f", [])],
                    "notes": rec.get("o", []), "tools": rec.get("k", []), "fp": rec.get("h"), "auth": rec.get("a"), "pk": rec.get("p", {}),
                    "verified": rec.get("vd"), "keys": [], "tool_text": {}})
    return out


def render_only(src, out):
    import shutil
    results = results_from_site(src)
    if len(results) < 1000:  # a missing/broken source must not wipe the public site
        sys.exit(f"render-only: only {len(results)} records in {src}; refusing to publish")
    try:
        with open(os.path.join(src, "changes.json"), encoding="utf-8") as fh:
            changes = json.load(fh)
    except (OSError, ValueError):
        changes = []
    for day in changes:  # items recorded before notability / the grade-only rule existed
        day["items"] = [it for it in day.get("items", []) if any(c.get("kind") != "grade_changed" for c in it.get("changes", []))]
        for it in day["items"]:
            if "notable" not in it:
                it["notable"] = notable_reasons(it.get("changes", []), it.get("new_text", {}))
    write_site(results, out, changes)
    shutil.rmtree(os.path.join(out, "m"), ignore_errors=True)  # lookup keys aren't in d/: keep the published ones
    shutil.copytree(os.path.join(src, "m"), os.path.join(out, "m"))
    print(f"rendered {len(results)} servers from {src} into {out}/", file=sys.stderr)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="site")
    ap.add_argument("--limit", type=int)
    ap.add_argument("--no-probe", action="store_true")
    ap.add_argument("--prev", help="previous site's d/ shard dir, for change detection")
    ap.add_argument("--history", help="dir of daily change files (the history branch checkout)")
    ap.add_argument("--render-from", help="re-render pages from a published site dir (no registry fetch, no probes)")
    a = ap.parse_args(argv)
    if a.render_from:
        return render_only(a.render_from, a.out)
    servers = fetch_registry(a.limit)
    print(f"registry: {len(servers)} active servers", file=sys.stderr)
    with ThreadPoolExecutor(48) as ex:
        results = list(ex.map(lambda s: assess(s, not a.no_probe), servers))
    prev = load_prev(a.prev) if a.prev else {}
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    items = track_changes(results, prev, today)
    changes = []
    if a.history:
        os.makedirs(a.history, exist_ok=True)
        if prev:  # first run only sets the baseline
            with open(f"{a.history}/{today}.json", "w", encoding="utf-8") as fh:
                json.dump(items, fh, separators=(",", ":"))
        days = sorted(f for f in os.listdir(a.history) if re.fullmatch(r"\d{4}-\d{2}-\d{2}\.json", f))[-14:]
        for f in reversed(days):
            with open(f"{a.history}/{f}", encoding="utf-8") as fh:
                changes.append({"date": f[:10], "items": json.load(fh)})
    print(f"changes: {len(items)} server(s) changed since last run", file=sys.stderr)
    write_site(results, a.out, changes)
    print(f"indexed {len(results)} servers into {a.out}/", file=sys.stderr)


if __name__ == "__main__":
    main()
