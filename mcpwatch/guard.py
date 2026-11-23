"""mcpwatch guard: a stdio proxy that only lets your agent see tools you approved.

  mcpwatch guard --name github [--lock mcpwatch.lock] [--allow-new] -- npx -y @modelcontextprotocol/server-github

Put it in front of a stdio server in your MCP client config (command "mcpwatch", args ["guard", ...]). It starts the
real server and relays every message. In tools/list answers it removes any tool whose description or input schema
differs from the approved copy in mcpwatch.lock (written by `mcpwatch lock --live`), and new tools unless --allow-new;
calls to a removed tool get an error without reaching the server. Blocked tools are reported on stderr (your MCP
client's server log). Without a live lock entry for --name it refuses to start: fail closed.
"""
import argparse, json, os, subprocess, sys, threading
from mcpwatch.watch import tool_hash

# shortcut: stdio only; remote (HTTP) servers can be wrapped with a stdio bridge such as mcp-remote until a native HTTP mode exists


class Guard:
    def __init__(self, approved, allow_new=False, log=None):
        self.approved, self.allow_new = approved, allow_new  # approved: {tool: hash}
        self.list_ids, self.blocked, self.lock = set(), set(), threading.Lock()
        self.log = log or (lambda m: print(f"mcpwatch guard: {m}", file=sys.stderr, flush=True))

    def allowed(self, tool):
        name = tool.get("name")
        if name in self.approved:
            return self.approved[name] == tool_hash(tool)
        return self.allow_new

    def from_client(self, msg):
        """(forward_to_server, reply_to_client) for one client message."""
        if not isinstance(msg, dict):
            return msg, None
        key = json.dumps(msg.get("id"))
        if msg.get("method") == "tools/list" and "id" in msg:
            with self.lock:
                self.list_ids.add(key)
        if msg.get("method") == "tools/call" and "id" in msg:
            name = (msg.get("params") or {}).get("name")
            if name in self.blocked or (name not in self.approved and not self.allow_new):
                return None, {"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32602,
                              "message": f"mcpwatch guard blocked '{name}': this tool is not the version you approved. Review it, then run `mcpwatch lock --live`."}}
        return msg, None

    def from_server(self, msg):
        """The server message with unapproved tools removed from tools/list answers."""
        if not isinstance(msg, dict) or "method" in msg:
            return msg
        key = json.dumps(msg.get("id"))
        with self.lock:
            if key not in self.list_ids:
                return msg
            self.list_ids.discard(key)
        result = msg.get("result")
        if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
            return msg
        keep = []
        for t in result["tools"]:
            if isinstance(t, dict) and self.allowed(t):
                keep.append(t)
            else:
                name = t.get("name") if isinstance(t, dict) else "?"
                if name not in self.blocked:
                    self.log(f"blocked tool '{name}': {'changed since you approved it' if name in self.approved else 'not in your approved list'}")
                self.blocked.add(name)
        return {**msg, "result": {**result, "tools": keep}}


def relay(guard, child, client_in, client_out):
    out_lock = threading.Lock()

    def write(stream, msg):
        with out_lock:
            stream.write(json.dumps(msg, ensure_ascii=False).encode() + b"\n")
            stream.flush()

    def upstream():  # client -> server
        try:
            for line in client_in:
                try:
                    msg = json.loads(line)
                except ValueError:
                    continue  # not JSON-RPC: never forwarded
                fwd, reply = guard.from_client(msg)
                if reply is not None:
                    write(client_out, reply)
                if fwd is not None:
                    child.stdin.write(json.dumps(fwd, ensure_ascii=False).encode() + b"\n")
                    child.stdin.flush()
        except (BrokenPipeError, OSError):
            pass
        finally:
            try:
                child.stdin.close()
            except OSError:
                pass

    t = threading.Thread(target=upstream, daemon=True)
    t.start()
    for line in child.stdout:  # server -> client
        try:
            msg = json.loads(line)
        except ValueError:
            continue  # servers that log to stdout would corrupt the stream anyway
        write(client_out, guard.from_server(msg))
    return child.wait()


def main(argv=None):
    ap = argparse.ArgumentParser(prog="mcpwatch guard", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--name", required=True, help="the server's name in your config / mcpwatch.lock")
    ap.add_argument("--lock", default="mcpwatch.lock")
    ap.add_argument("--allow-new", action="store_true", help="let tools that are not in the lock file through")
    ap.add_argument("command", nargs=argparse.REMAINDER, help="-- then the real server command")
    a = ap.parse_args(argv)
    cmd = a.command[1:] if a.command[:1] == ["--"] else a.command
    if not cmd:
        ap.error("give the server command after --")
    try:
        with open(a.lock, encoding="utf-8") as fh:
            live = json.load(fh)["servers"][a.name]["live"]
        approved = {n: t["h"] for n, t in live.items()}
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        print(f"mcpwatch guard: no approved tools for '{a.name}' in {a.lock}: run `mcpwatch lock --live` first", file=sys.stderr)
        return 2
    child = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=os.environ)  # stderr passes through
    return relay(Guard(approved, a.allow_new), child, sys.stdin.buffer, sys.stdout.buffer)


if __name__ == "__main__":
    sys.exit(main())
