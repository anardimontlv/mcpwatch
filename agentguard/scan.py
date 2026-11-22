#!/usr/bin/env python3
"""agentguard: static security scanner for MCP client configs and MCP tool manifests.

Usage:
  python3 -m agentguard.scan CONFIG.json [--tools TOOLS.json] [--format text|json|md] [--badge out.svg] [--fail-on high]

CONFIG.json: any MCP client config with an "mcpServers" (or "servers") object
(Claude Desktop, Claude Code .mcp.json, Cursor, VS Code).
TOOLS.json: the result of an MCP `tools/list` call ({"tools": [...]}).
Static only: never launches or connects to the servers it scans.
"""
import argparse, json, re, sys, unicodedata

SEV_WEIGHT = {"critical": 40, "high": 20, "medium": 8, "low": 3}
SEV_ORDER = ["low", "medium", "high", "critical"]

SECRET_PATTERNS = [
    re.compile(p) for p in (
        r"sk-[A-Za-z0-9_\-]{20,}", r"sk-ant-[A-Za-z0-9_\-]{20,}", r"gh[pousr]_[A-Za-z0-9]{30,}",
        r"github_pat_[A-Za-z0-9_]{30,}", r"AKIA[0-9A-Z]{16}", r"xox[abpr]-[A-Za-z0-9\-]{10,}",
        r"AIza[0-9A-Za-z_\-]{35}", r"glpat-[A-Za-z0-9_\-]{20}", r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    )
]
SECRET_KEY_NAME = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH)", re.I)
ENV_REF = re.compile(r"^\$\{?[A-Za-z_][A-Za-z0-9_:\-]*\}?$|^\$\{input:")
RUNNERS = {"npx", "bunx", "pnpx", "uvx", "pipx", "dlx"}
BROAD_PATHS = {"/", "~", "~/", "$HOME", "${HOME}", "C:\\", "C:/"}
INJECTION = re.compile(
    r"ignore (all |any )?(previous|prior|above) (instructions|prompts)|do not (tell|inform|mention)[^.]{0,40}user"
    r"|<\s*important\s*>|before using any other tool|instead of the user|send (it|them|the [a-z ]+) to (http|https)://"
    r"|~/\.ssh|id_rsa|\.env\b|exfiltrat",
    re.I,
)
DANGEROUS_TOOL = re.compile(r"(^|_)(exec|shell|run_command|eval|bash|terminal|delete_|rm_|sudo)", re.I)


def redact(s):
    return s[:4] + "…" + f"[{len(s)} chars]" if len(s) > 8 else "…"


def is_secret_literal(key, val):
    if not isinstance(val, str) or not val or ENV_REF.match(val):
        return False
    if any(p.search(val) for p in SECRET_PATTERNS):
        return True
    return bool(key and SECRET_KEY_NAME.search(key)) and len(val) >= 12 and " " not in val


def pkg_pinned(pkg):
    if pkg.startswith("-"):
        return True
    if "==" in pkg:
        return True
    name = pkg[1:] if pkg.startswith("@") else pkg  # scoped npm: @scope/name@1.2.3
    if "@" not in name:
        return False
    version = name.rsplit("@", 1)[1]
    return bool(version) and version not in {"latest", "next", "*"}


def first_package(args):
    for a in args:
        if a.startswith("-"):
            continue
        return a
    return None


def scan_server(name, cfg):
    f = []
    add = lambda rule, sev, msg: f.append({"server": name, "rule": rule, "severity": sev, "message": msg})
    cmd = str(cfg.get("command", ""))
    args = [str(a) for a in cfg.get("args", []) or []]
    exe = cmd.replace("\\", "/").rsplit("/", 1)[-1].removesuffix(".cmd").removesuffix(".exe")

    for k, v in (cfg.get("env") or {}).items():
        if is_secret_literal(k, v):
            add("AG001", "high", f"Plaintext secret in env {k} ({redact(v)}). Use an env reference or a secret store.")
    for k, v in (cfg.get("headers") or {}).items():
        if is_secret_literal(k, v):
            add("AG001", "high", f"Plaintext secret in header {k} ({redact(v)}). Use an env reference.")
    for a in args:
        if any(p.search(a) for p in SECRET_PATTERNS):
            add("AG001", "high", f"Plaintext secret in command args ({redact(a)}). Visible in process lists.")

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
        if "--privileged" in args:
            add("AG007", "critical", "Container runs --privileged: full host access.")
        if re.search(r"(-v|--volume)[ =]/:", joined) or "/var/run/docker.sock" in joined:
            add("AG007", "critical", "Container mounts the host root or the Docker socket.")
        if "--network host" in joined or "--net=host" in joined or "--network=host" in joined:
            add("AG007", "medium", "Container shares the host network.")

    if any(a.rstrip("/\\") in {p.rstrip("/\\") for p in BROAD_PATHS} or a in BROAD_PATHS for a in args):
        add("AG006", "high", "Server is granted the filesystem root or the whole home directory. Scope it to a project folder.")

    url = cfg.get("url") or cfg.get("serverUrl")
    if url:
        if url.startswith("http://") and not re.match(r"http://(localhost|127\.0\.0\.1|\[::1\])", url):
            add("AG004", "high", f"Remote server over plain HTTP ({url}). Traffic and tokens can be intercepted.")
        headers = {k.lower() for k in (cfg.get("headers") or {})}
        if not headers & {"authorization", "x-api-key", "api-key"} and not cfg.get("oauth") and "localhost" not in url:
            add("AG005", "low", "Remote server configured without auth headers. Fine if it uses OAuth; otherwise anyone with the URL can call it.")
    return f


def hidden_chars(s):
    return [c for c in s if unicodedata.category(c) in {"Cf", "Co"} or 0xE0000 <= ord(c) <= 0xE007F]


def scan_tools(tools, server="(tools manifest)"):
    f = []
    for t in tools:
        name = str(t.get("name", "?"))
        text = " ".join([str(t.get("description", "")), json.dumps(t.get("inputSchema", {}))])
        add = lambda rule, sev, msg: f.append({"server": server, "rule": rule, "severity": sev, "message": f"tool '{name}': {msg}"})
        if hidden_chars(text):
            add("AG103", "critical", "contains invisible/tag Unicode characters, a common way to hide instructions from humans.")
        m = INJECTION.search(text)
        if m:
            add("AG101", "critical", f"description contains instruction-like text aimed at the model ('{m.group(0)[:60]}'). Possible tool poisoning.")
        if DANGEROUS_TOOL.search(name):
            add("AG102", "medium", "exposes command execution or deletion. Require confirmation before the agent calls it.")
    return f


def servers_of(config):
    s = config.get("mcpServers") or config.get("servers") or (config.get("mcp") or {}).get("servers") or {}
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


def render(findings, fmt, n_servers):
    pts, grade = score(findings)
    if fmt == "json":
        return json.dumps({"score": pts, "grade": grade, "servers": n_servers, "findings": findings}, indent=2)
    key = lambda x: -SEV_ORDER.index(x["severity"])
    if fmt == "md":
        rows = "\n".join(f"| {x['severity']} | {x['rule']} | {x['server']} | {x['message']} |" for x in sorted(findings, key=key))
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
            findings += scan_tools(data.get("tools", data) if isinstance(data, dict) else data)
    except (OSError, json.JSONDecodeError) as e:
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
