"""Minimal stdio MCP client - used to replay released quarantine entries."""
from __future__ import annotations

import json
import subprocess

from . import __version__

PROTOCOL_VERSION = "2025-06-18"


class MiniClient:
    def __init__(self, cmd):
        self.proc = subprocess.Popen(
            list(cmd), stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0)
        self._id = 0

    def _send(self, obj: dict) -> None:
        self.proc.stdin.write((json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8"))
        self.proc.stdin.flush()

    def request(self, method: str, params: dict = None):
        self._id += 1
        rid = self._id
        self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}})
        while True:
            line = self.proc.stdout.readline()
            if not line:
                raise RuntimeError(f"backend closed while waiting for {method}")
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(msg, dict) and msg.get("id") == rid:
                if "error" in msg:
                    raise RuntimeError(f"{method} failed: {msg['error']}")
                return msg.get("result")

    def initialize(self):
        result = self.request("initialize", {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "memwall", "version": __version__},
        })
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return result

    def call_tool(self, name: str, arguments: dict):
        return self.request("tools/call", {"name": name, "arguments": arguments})

    def close(self) -> None:
        try:
            self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.terminate()
        try:
            self.proc.stdout.close()
        except OSError:
            pass
