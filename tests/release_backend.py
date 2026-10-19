"""Counting stdio backend for release fault injection, never an agent model."""
import json
import os
from pathlib import Path
import sys
import time

root = Path(sys.argv[1])
mode = sys.argv[2]
pid = str(os.getpid())
wire = root / ("wire-" + pid + ".jsonl")


def record(direction, message, raw):
    with wire.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"direction": direction, "message": message, "raw": raw}) + "\n")


def send(message):
    raw = json.dumps(message) + "\n"
    record("response", message, raw)
    sys.stdout.write(raw)
    sys.stdout.flush()


for line in sys.stdin:
    msg = json.loads(line)
    record("request", msg, line)
    if msg.get("method") == "initialize":
        (root / ("started-" + pid)).touch()
        if mode == "gate":
            end = time.monotonic() + 15
            while not (root / "continue").exists():
                if time.monotonic() > end:
                    sys.exit(3)
                time.sleep(.01)
        send({"jsonrpc": "2.0", "id": msg["id"], "result": {
            "protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
            "serverInfo": {"name": "counting-fixture", "version": "1"}}})
    elif msg.get("method") == "tools/call":
        with (root / "effects.jsonl").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(msg) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        (root / ("applied-" + pid)).touch()
        if mode == "lost":
            sys.exit(0)
        if mode == "hold":
            while not (root / "continue").exists():
                time.sleep(.01)
        send({"jsonrpc": "2.0", "id": msg["id"], "result": {
            "content": [{"type": "text", "text": "stored"}]}})
