"""A minimal stdio MCP server for tests. Tools come from the FAKE_TOOLS env var (JSON list)."""
import json, os, sys
tools = json.loads(os.environ.get("FAKE_TOOLS", "[]"))
print("starting (a log line on stdout that clients must skip)", flush=True)
for line in sys.stdin:
    msg = json.loads(line)
    if "id" not in msg:
        continue
    if msg["method"] == "initialize":
        res = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": "fake", "version": "1"}}
    elif msg["method"] == "tools/list":
        cur = (msg.get("params") or {}).get("cursor")
        res = {"tools": tools[1:]} if cur else ({"tools": tools[:1], "nextCursor": "p2"} if len(tools) > 1 else {"tools": tools})
    elif msg["method"] == "tools/call":
        res = {"content": [{"type": "text", "text": "ran " + msg["params"]["name"]}]}
    else:
        res = {}
    print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": res}), flush=True)
