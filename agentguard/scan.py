#!/usr/bin/env python3
"""agentguard: static security scanner for MCP client configs and MCP tool manifests.

Usage:
  python3 -m agentguard.scan CONFIG.json [--tools TOOLS.json] [--format text|json|md] [--badge out.svg] [--fail-on high]

CONFIG.json: any MCP client config with an "mcpServers" (or "servers") object
(Claude Desktop, Claude Code .mcp.json, Cursor, VS Code).
TOOLS.json: the result of an MCP `tools/list` call ({"tools": [...]}).
Static only: never launches or connects to the servers it scans.
Exit codes: 0 ok, 1 findings at/above --fail-on, 2 unreadable or unusable input.
"""
import argparse, json, re, shlex, sys, unicodedata
from urllib.parse import urlsplit, parse_qsl

SEV_WEIGHT = {"critical": 40, "high": 20, "medium": 8, "low": 3}
SEV_ORDER = ["low", "medium", "high", "critical"]

SECRET_PATTERNS = [
    re.compile(p) for p in (
        r"sk-[A-Za-z0-9_\-]{20,}", r"sk-ant-[A-Za-z0-9_\-]{20,}", r"gh[pousr]_[A-Za-z0-9]{30,}",
        r"github_pat_[A-Za-z0-9_]{30,}", r"AKIA[0-9A-Z]{16}", r"xox[abpr]-[A-Za-z0-9\-]{10,}",
        r"AIza[0-9A-Za-z_\-]{35}", r"glpat-[A-Za-z0-9_\-]{20}", r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    )
]
SECRET_KEY_NAME = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD|PASSWD|PWD|CREDENTIAL|AUTH)", re.I)
# names that mention a secret but hold a pointer, a mode or a number, not the secret itself
NOT_SECRET_NAME = re.compile(r"(_FILE|_PATH|_DIR|_MODE|_TYPE|_METHOD|_URL|_ENDPOINT|_HEADER|_NAME|_ID|_REGION|^MAX_|_LIMIT|_TOKENS)$", re.I)
SECRET_PARAM = re.compile(r"(key|token|secret|password|passwd|pwd|auth|signature|sig|access_token|apikey)", re.I)
ENV_REF = re.compile(r"\$\{?[A-Za-z_][A-Za-z0-9_:\-]*\}?|\$\{input:[^}]*\}|\{\{[^}]*\}\}")
RUNNERS = {"npx", "bunx", "pnpx", "uvx", "pipx", "dlx"}
BROAD_PATH = re.compile(r"^(/|~|~/|\$HOME|\$\{HOME\}|%USERPROFILE%|[A-Za-z]:[\\/]?|/Users/[^/]+|/home/[^/]+|/root|[A-Za-z]:[\\/]Users[\\/][^\\/]+)[\\/]?$")
UNSAFE_FLAGS = re.compile(r"^--?(allow-all|allow-all-tools|dangerously-skip-permissions|no-sandbox|disable-sandbox|unsafe|yolo|trust-all)(=.*)?$", re.I)
INJECTION = re.compile(
    r"(ignore|disregard|forget)\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|rules)"
    r"|do\s+not\s+(tell|inform|mention|reveal)[^.]{0,40}user|<\s*important\s*>|before\s+using\s+any\s+other\s+tool"
    r"|instead\s+of\s+the\s+user|send\s+(it|them|the\s+[a-z ]+)\s+to\s+https?://|\.ssh/|id_(rsa|ed25519|ecdsa)|exfiltrat",
    re.I,
)
DANGEROUS_TOKENS = {"exec", "execute", "shell", "bash", "sh", "zsh", "powershell", "sudo", "eval", "delete", "remove", "rm", "drop", "kill"}
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


def redact(s):
    return s[:4] + "…" + f"[{len(s)} chars]" if len(s) > 8 else "…"


def safe_url(url):
    """URL with credentials and query values removed: safe to print."""
    try:
        p = urlsplit(url)
        host = p.hostname or ""
        port = f":{p.port}" if p.port else ""
    except ValueError:
        return "(unparseable url)"
    q = "?" + "&".join(f"{k}=…" for k, _ in parse_qsl(p.query, keep_blank_values=True)) if p.query else ""
    return f"{p.scheme}://{host}{port}{p.path}{q}"


def looks_like_value(v):
    """Literal that could plausibly be a credential (not a path, number, word or env reference)."""
    v = v.strip()
    if any(p.search(v) for p in SECRET_PATTERNS):
        return True
    if not v or ENV_REF.fullmatch(v) or v.isdigit() or v.lower() in {"true", "false", "none", "null"}:
        return False
    if v[0] in "/~." or re.match(r"^[A-Za-z]:[\\/]", v) or re.fullmatch(r"[a-z]+([_\-][a-z]+)*", v):
        return False
    return len(v) >= 12 and " " not in v


def is_secret_literal(key, val):
    if not isinstance(val, str) or not val or ENV_REF.fullmatch(val.strip()):
        return False
    if any(p.search(val) for p in SECRET_PATTERNS):
        return True
    if re.match(r"^[a-z][a-z0-9+.\-]*://[^/@\s:]+:[^/@\s]+@", val, re.I) and not ENV_REF.search(val.split("@")[0]):
        return True  # credentials embedded in a connection string
    scheme = re.match(r"^(bearer|basic|token)\s+(.+)$", val, re.I)
    if scheme:
        return looks_like_value(scheme.group(2))
    return bool(key and SECRET_KEY_NAME.search(key) and not NOT_SECRET_NAME.search(key)) and looks_like_value(val)


def url_secrets(url):
    try:
        p = urlsplit(url)
        if p.password and not ENV_REF.search(p.password):
            return True
        return any(SECRET_PARAM.search(k) and looks_like_value(v) for k, v in parse_qsl(p.query))
    except ValueError:
        return False


def pkg_pinned(pkg):
    if pkg.startswith("-") or "==" in pkg:
        return True
    name = pkg[1:] if pkg.startswith("@") else pkg  # scoped npm: @scope/name@1.2.3
    if "@" not in name:
        return False
    version = name.rsplit("@", 1)[1]
    return bool(version) and version not in {"latest", "next", "*"}


def first_package(args):
    return next((a for a in args if not a.startswith("-")), None)


def as_dict(v):
    return v if isinstance(v, dict) else {}


def as_args(v):
    if isinstance(v, str):
        try:
            return shlex.split(v)
        except ValueError:
            return v.split()
    return [str(a) for a in v] if isinstance(v, list) else []


def is_local(url):
    try:
        return (urlsplit(url).hostname or "") in LOCAL_HOSTS
    except ValueError:
        return False


def scan_server(name, cfg):
    f = []
    add = lambda rule, sev, msg: f.append({"server": str(name), "rule": rule, "severity": sev, "message": msg})
    cmd = cfg.get("command") if isinstance(cfg.get("command"), str) else ""
    args = as_args(cfg.get("args"))
    exe = cmd.replace("\\", "/").rsplit("/", 1)[-1].removesuffix(".cmd").removesuffix(".exe")

    for where, items in (("env", as_dict(cfg.get("env"))), ("header", as_dict(cfg.get("headers")))):
        for k, v in items.items():
            if is_secret_literal(str(k), v):
                add("AG001", "high", f"Plaintext secret in {where} {k} ({redact(v)}). Use an env reference or a secret store.")
    for a in args:
        flag_val = re.match(r"^--?[\w\-]*(key|token|secret|password|auth)[\w\-]*=(.+)$", a, re.I)
        if any(p.search(a) for p in SECRET_PATTERNS) or (flag_val and looks_like_value(flag_val.group(2))):
            add("AG001", "high", f"Plaintext secret in command args ({redact(a)}). Visible in process lists.")
        if UNSAFE_FLAGS.match(a):
            add("AG009", "high", f"Launched with '{a.split('=')[0]}', which turns off a safety control.")

    if exe in RUNNERS:
        pkg = first_package(args)
        if pkg and not pkg_pinned(pkg):
            add("AG002", "medium", f"Unpinned package '{pkg}' via {exe}: every launch runs whatever the registry serves. Pin a version.")
    if exe in {"bash", "sh", "zsh", "cmd", "powershell", "pwsh"} and any(a in {"-c", "/c", "-Command"} for a in args):
        add("AG008", "high", "Server launched through an inline shell command. Hard to audit; prefer a direct executable.")
    if re.search(r"(curl|wget)[^|]*\|\s*(ba|z)?sh", " ".join([cmd] + args)):
        add("AG008", "critical", "Pipes a download straight into a shell.")

    if exe in {"docker", "podman"}:
        joined = " ".join(args)
        if "--privileged" in args or re.search(r"--cap-add[ =](SYS_ADMIN|ALL)\b", joined, re.I):
            add("AG007", "critical", "Container runs privileged or with SYS_ADMIN/ALL capabilities: effectively host access.")
        if "/var/run/docker.sock" in joined or re.search(r"(-v|--volume)[ =]/:|(src|source)=/(,|\s|$)", joined):
            add("AG007", "critical", "Container mounts the host root or the Docker socket.")
        if re.search(r"--(network|net|pid|ipc)[ =]host\b", joined):
            add("AG007", "medium", "Container shares the host network, PID or IPC namespace.")
        for m in re.finditer(r"(?:-v|--volume)[ =]([^:\s]+):|(?:src|source)=([^,\s]+)", joined):
            host_path = m.group(1) or m.group(2)
            if host_path != "/" and BROAD_PATH.match(host_path):
                add("AG006", "high", f"Container mounts a whole home directory ({host_path}).")

    if any(BROAD_PATH.match(a) for a in args if exe not in {"docker", "podman"}):
        add("AG006", "high", "Server is granted the filesystem root or a whole home directory. Scope it to a project folder.")

    url = cfg.get("url") or cfg.get("serverUrl")
    if isinstance(url, str) and url:
        shown = safe_url(url)
        if url_secrets(url):
            add("AG001", "high", f"Credentials embedded in the server URL ({shown}). They end up in logs and history.")
        if url.lower().startswith("http://") and not is_local(url):
            add("AG004", "high", f"Remote server over plain HTTP ({shown}). Traffic and tokens can be intercepted.")
        headers = {str(k).lower() for k in as_dict(cfg.get("headers"))}
        if not headers & {"authorization", "x-api-key", "api-key"} and not cfg.get("oauth") and not is_local(url) and not url_secrets(url):
            add("AG005", "low", "Remote server configured without auth headers. Fine if it uses OAuth; otherwise anyone with the URL can call it.")
    return f


def hidden_chars(s):
    return [c for c in s if unicodedata.category(c) in {"Cf", "Co"} or 0xE0000 <= ord(c) <= 0xE007F]


def name_tokens(name):
    return {t.lower() for t in re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+", name)}


def scan_tools(tools, server="(tools manifest)"):
    f = []
    for t in tools if isinstance(tools, list) else []:
        if not isinstance(t, dict):
            continue
        name = str(t.get("name", "?"))
        text = " ".join([str(t.get("description", "")), json.dumps(t.get("inputSchema", {}), ensure_ascii=False)])
        add = lambda rule, sev, msg: f.append({"server": server, "rule": rule, "severity": sev, "message": f"tool '{name}': {msg}"})
        if hidden_chars(text + name):
            add("AG103", "critical", "contains invisible/tag Unicode characters, a common way to hide instructions from humans.")
        m = INJECTION.search(text)
        if m:
            add("AG101", "critical", f"description contains instruction-like text aimed at the model ('{m.group(0)[:60]}'). Possible tool poisoning.")
        toks = name_tokens(name)
        if toks & DANGEROUS_TOKENS or {"run", "command"} <= toks:
            add("AG102", "medium", "exposes command execution or deletion. Require confirmation before the agent calls it.")
    return f


def servers_of(config):
    if not isinstance(config, dict):
        return {}
    s = config.get("mcpServers") or config.get("servers") or as_dict(config.get("mcp")).get("servers") or {}
    return s if isinstance(s, dict) else {}


def score(findings):
    pts = max(0, 100 - sum(SEV_WEIGHT[x["severity"]] for x in findings))
    grade = "A" if pts >= 90 else "B" if pts >= 75 else "C" if pts >= 60 else "D" if pts >= 40 else "F"
    return pts, grade


BADGE_COLORS = {"A": "#2e7d32", "B": "#558b2f", "C": "#f9a825", "D": "#ef6c00", "F": "#c62828"}


def badge(grade):
    c = BADGE_COLORS[grade]
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="128" height="20" role="img" aria-label="agentguard: {grade}">'
            f'<rect width="96" height="20" fill="#555"/><rect x="96" width="32" height="20" fill="{c}"/>'
            f'<g fill="#fff" font-family="Verdana,sans-serif" font-size="11" text-anchor="middle">'
            f'<text x="48" y="14">agentguard</text><text x="112" y="14">{grade}</text></g></svg>')


def md_cell(s):
    # server names and messages come from the scanned (untrusted) config: neutralise markdown/HTML
    s = re.sub(r"[\r\n]+", " ", str(s))
    return re.sub(r"([\\|`*_\[\]<>!#])", r"\\\1", s)


def render(findings, fmt, n_servers):
    pts, grade = score(findings)
    if fmt == "json":
        return json.dumps({"score": pts, "grade": grade, "servers": n_servers, "findings": findings}, indent=2)
    key = lambda x: -SEV_ORDER.index(x["severity"])
    if fmt == "md":
        rows = "\n".join(f"| {x['severity']} | {x['rule']} | {md_cell(x['server'])} | {md_cell(x['message'])} |" for x in sorted(findings, key=key))
        return f"## agentguard: grade {grade} ({pts}/100), {n_servers} server(s)\n\n| Severity | Rule | Server | Finding |\n|---|---|---|---|\n{rows}\n"
    lines = [f"agentguard grade {grade} ({pts}/100) across {n_servers} server(s), {len(findings)} finding(s)"]
    lines += [f"  [{x['severity'].upper():8}] {x['rule']} {x['server']}: {x['message']}" for x in sorted(findings, key=key)]
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("config", nargs="?")
    ap.add_argument("--tools")
    ap.add_argument("--format", choices=["text", "json", "md"], default="text")
    ap.add_argument("--badge")
    ap.add_argument("--fail-on", choices=SEV_ORDER, default=None)
    a = ap.parse_args(argv)
    if not a.config and not a.tools:
        ap.error("give a config file, --tools, or both")
    findings, servers = [], {}
    try:
        if a.config:
            with open(a.config, encoding="utf-8") as fh:
                servers = servers_of(json.load(fh))
            for name, cfg in servers.items():
                if isinstance(cfg, dict):
                    findings += scan_server(name, cfg)
        if a.tools:
            with open(a.tools, encoding="utf-8") as fh:
                data = json.load(fh)
            findings += scan_tools(data.get("tools", []) if isinstance(data, dict) else data)
    except (OSError, ValueError) as e:
        print(f"agentguard: cannot read input: {e}", file=sys.stderr)
        return 2
    if not servers and not a.tools:
        print("agentguard: no MCP servers found in config (looked for mcpServers / servers / mcp.servers)", file=sys.stderr)
        return 2
    print(render(findings, a.format, len(servers)))
    if a.badge:
        with open(a.badge, "w", encoding="utf-8") as fh:
            fh.write(badge(score(findings)[1]))
    if a.fail_on and any(SEV_ORDER.index(x["severity"]) >= SEV_ORDER.index(a.fail_on) for x in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
