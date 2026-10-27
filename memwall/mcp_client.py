"""Minimal stdio MCP client - used to replay released quarantine entries."""
from __future__ import annotations

import json
import subprocess

from . import __version__
from .contracts import ContractError, strict_loads

PROTOCOL_VERSION = "2025-06-18"


def successful_tool_result(result):
    """Recognize structural MCP success, never proof of actual persisted effects."""
    if (not isinstance(result, dict) or not isinstance(result.get("content"), list)
            or ("isError" in result and type(result["isError"]) is not bool)
            or result.get("isError")
            or ("structuredContent" in result and not isinstance(result["structuredContent"], dict))
            or ("_meta" in result and not isinstance(result["_meta"], dict))):
        return False
    for block in result["content"]:
        if not isinstance(block, dict):
            return False
        kind = block.get("type")
        if kind == "text":
            required = ("text",)
        elif kind in ("image", "audio"):
            required = ("data", "mimeType")
        elif kind == "resource_link":
            required = ("uri", "name")
        elif kind == "resource":
            resource = block.get("resource")
            if (not isinstance(resource, dict) or not isinstance(resource.get("uri"), str)
                    or not any(isinstance(resource.get(key), str) for key in ("text", "blob"))
                    or ("mimeType" in resource and not isinstance(resource["mimeType"], str))):
                return False
            required = ()
        else:
            return False
        if any(not isinstance(block.get(key), str) for key in required):
            return False
        if any(key in block and not isinstance(block[key], dict) for key in ("annotations", "_meta")):
            return False
    return True


class MiniClient:
    def __init__(self, cmd):
        self.proc = subprocess.Popen(
            list(cmd), stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0)
        self._id = 0

    def _send(self, obj: dict) -> None:
        data = memoryview((json.dumps(obj, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8"))
        while data:
            written = self.proc.stdin.write(data)
            if written is None or written <= 0:
                raise RuntimeError("backend pipe did not accept complete request")
            data = data[written:]
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
                msg = strict_loads(line)
            except ContractError as exc:
                raise RuntimeError("backend returned invalid JSON") from exc
            if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
                raise RuntimeError("backend returned an invalid JSON-RPC envelope")
            if type(msg.get("id")) is int and msg["id"] == rid:
                if "method" in msg or (("result" in msg) == ("error" in msg)):
                    raise RuntimeError("backend returned an ambiguous JSON-RPC response")
                if "error" in msg:
                    raise RuntimeError(f"{method} failed: {msg['error']}")
                return msg.get("result")

    def initialize(self):
        result = self.request("initialize", {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "memwall", "version": __version__},
        })
        if (not isinstance(result, dict) or not isinstance(result.get("protocolVersion"), str)
                or not isinstance(result.get("capabilities"), dict)
                or not isinstance(result.get("serverInfo"), dict)
                or not isinstance(result["serverInfo"].get("name"), str)
                or not isinstance(result["serverInfo"].get("version"), str)):
            raise RuntimeError("backend returned an invalid initialize result")
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
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        try:
            self.proc.stdout.close()
        except OSError:
            pass
