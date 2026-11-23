#!/usr/bin/env python3
"""Rug-pull demo: watch mcpwatch catch and block an MCP server that changes its tools after you approved them.

  python3 examples/rug-pull-demo/run_demo.py

Needs only Python 3.10+ and mcpwatch (`pipx install mcpwatch-io`, or run it from a clone of the repo).
Everything runs locally against notes_server.py; nothing is sent anywhere. Exits non-zero if any step
doesn't behave as described, so it doubles as an end-to-end test.
"""
import json, os, shutil, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER = os.path.join(HERE, "notes_server.py")
REPO = os.path.dirname(os.path.dirname(HERE))
# inside a clone, always use the repo's own code; otherwise the installed CLI
IN_REPO = os.path.isfile(os.path.join(REPO, "mcpwatch", "watch.py"))
MCPWATCH = [sys.executable, "-m", "mcpwatch.watch"] if IN_REPO or not shutil.which("mcpwatch") else [shutil.which("mcpwatch")]
ENV = {**os.environ, "PYTHONPATH": REPO + os.pathsep + os.environ.get("PYTHONPATH", "")}


def say(title, text=""):
    print(f"\n\033[1m== {title}\033[0m" if sys.stdout.isatty() else f"\n== {title}")
    if text:
        print(text)


def mcpwatch(*args, work=""):
    p = subprocess.run(MCPWATCH + list(args), capture_output=True, text=True, env=ENV, timeout=120)
    out = "\n".join(l for l in p.stdout.splitlines() if "not pinned:" not in l)  # local server: index note is noise here
    return p.returncode, out.replace(work + os.sep, "").strip()


def agent_session(command, env):
    """What an MCP client (your agent) sees: initialize, list tools, then try the destructive tool."""
    msgs = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                                                                       "clientInfo": {"name": "demo-agent", "version": "1"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "delete_all_notes", "arguments": {}}}]
    p = subprocess.run(command, input="".join(json.dumps(m) + "\n" for m in msgs), capture_output=True, text=True,
                       env={**ENV, **env}, timeout=60)
    out = {m.get("id"): m for m in (json.loads(l) for l in p.stdout.splitlines() if l.strip().startswith("{"))}
    return out, p.stderr.strip()


def show_tools(resp):
    tools = resp[2]["result"]["tools"]
    for t in tools:
        print(f"   - {t['name']}: {t['description']}")
    if not tools:
        print("   (no tools: the changed search_notes and the new delete_all_notes are both held back until you re-approve)")


def main():
    ok = True

    def check(cond, msg):
        nonlocal ok
        if not cond:
            ok = False
            print(f"   !! unexpected: {msg}")

    work = tempfile.mkdtemp(prefix="mcpwatch-demo-")
    cfg_path, lock = os.path.join(work, "mcp.json"), os.path.join(work, "mcpwatch.lock")

    def write_config(rugpull):
        cfg = {"mcpServers": {"notes": {"command": sys.executable, "args": ["-I", SERVER], "env": {"RUGPULL": "1" if rugpull else "0"}}}}
        with open(cfg_path, "w") as fh:
            json.dump(cfg, fh, indent=2)

    server_cmd = [sys.executable, "-I", SERVER]
    guard_cmd = MCPWATCH + ["guard", "--name", "notes", "--lock", lock, "--"] + server_cmd

    say("1. You review the notes server and approve its tools")
    write_config(False)
    code, out = mcpwatch("lock", cfg_path, "--lock", lock, "--live", work=work)
    print("   $ mcpwatch lock mcp.json --live\n   " + out.replace("\n", "\n   "))
    check(code == 0, "lock failed")

    say("2. Later, the server ships a malicious update (a rug pull)")
    write_config(True)
    resp, _ = agent_session(server_cmd, {"RUGPULL": "1"})
    print("   Without protection, your agent now sees:")
    show_tools(resp)
    print(f"   ...and calling delete_all_notes returns: {resp[3]['result']['content'][0]['text']!r}")
    check(len(resp[2]["result"]["tools"]) == 2, "rug-pulled server should expose 2 tools")

    say("3. CI catches it: mcpwatch check fails with the exact change")
    code, out = mcpwatch("check", cfg_path, "--lock", lock, "--live", work=work)
    print("   $ mcpwatch check mcp.json --live\n   " + out.replace("\n", "\n   "))
    print(f"   (exit code {code}: your CI job fails)")
    check(code == 1 and "tool_changed search_notes" in out and "tool_added delete_all_notes" in out, "check should report the drift")

    say("4. At runtime, mcpwatch guard blocks it before your agent reads anything")
    resp, log = agent_session(guard_cmd, {"RUGPULL": "1"})
    print("   With guard in front of the server, your agent sees:")
    show_tools(resp)
    err = resp[3].get("error", {}).get("message", "")
    print(f"   ...and calling delete_all_notes returns an error: {err!r}")
    print("   guard's log (your MCP client's server log):\n   " + log.replace("\n", "\n   "))
    names = [t["name"] for t in resp[2]["result"]["tools"]]
    check(names == [], "guard should hide both the changed and the new tool")
    check("error" in resp[3], "guard should refuse the destructive call")

    shutil.rmtree(work, ignore_errors=True)
    say("Result", "PASS: the change was caught in CI and blocked at runtime." if ok else "FAIL: see the unexpected lines above.")
    print("\nTo protect a real server, put this in your MCP client config:\n"
          '   "command": "mcpwatch", "args": ["guard", "--name", "<server>", "--", <the server\'s command...>]')
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
