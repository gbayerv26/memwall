"""Fake MCP memory backend for gateway integration tests.

Speaks just enough newline-delimited JSON-RPC to handshake and accept tool
calls. Every tools/call it receives is appended to the file given as argv[1],
so tests can assert exactly what reached the backend.
"""
import json
import sys

calls_path = sys.argv[1] if len(sys.argv) > 1 else None


def send(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        msg = json.loads(line)
    except json.JSONDecodeError:
        continue
    method, mid = msg.get("method"), msg.get("id")
    if method == "initialize":
        send({"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": msg.get("params", {}).get("protocolVersion", "2025-06-18"),
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "fake-memory", "version": "0.0.1"}}})
    elif method == "tools/list":
        send({"jsonrpc": "2.0", "id": mid, "result": {"tools": [
            {"name": "add_observations", "description": "store", "inputSchema": {"type": "object"}}]}})
    elif method == "tools/call":
        if calls_path:
            with open(calls_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(msg) + "\n")
        send({"jsonrpc": "2.0", "id": mid, "result": {"content": [{"type": "text", "text": "stored"}]}})
    elif mid is not None:
        send({"jsonrpc": "2.0", "id": mid, "result": {}})
