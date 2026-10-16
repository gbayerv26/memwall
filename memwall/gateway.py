"""The memwall gateway: a transparent MCP stdio proxy with quarantine-before-commit.

The gateway spawns the real memory server as a subprocess and forwards
JSON-RPC traffic in both directions. tools/call requests whose tool name
looks like a write are scanned with the heuristic engine first; anything at
or above the block threshold for its declared origin is quarantined instead
of forwarded, and the agent receives an isError tool response telling it not
to retry.

Provenance handshake: agents may declare content origin via
params._meta.memwall.origin ("user", "web", "email", ...). The origin picks
the block threshold from the Policy and is recorded on every event and
quarantine entry; the memwall meta key is stripped before forwarding.

Judge-in-the-loop: with judge_enabled, flagged writes are classified by the
Claude judge before quarantining - clearing verdicts let the write through,
anything else (including judge unavailability) keeps the block (fail-safe).

stdout carries MCP protocol only - all gateway diagnostics go to stderr.
Without a profile, internal scan errors fail open. With a local contract
profile, unsupported requests and inspection/state failures are refused;
judging is advisory and cannot clear an enforced block.
"""
from __future__ import annotations

import copy
import json
import re
import subprocess
import sys
import threading

from .heuristics import evaluate
from .models import MemoryRecord, Severity
from .policy import Policy
from .state import StateStore
from .contracts import ContractError, MAX_REQUEST_BYTES, strict_loads, validate_depth

WRITE_TOOL = re.compile(r"create|add|store|save|write|update|remember|append|insert|set", re.I)

_CLEARING_VERDICTS = {"benign_fact", "preference", "task_context"}


def _strings(value, out=None) -> list:
    if out is None:
        out = []
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, dict):
        for item in value.values():
            _strings(item, out)
    elif isinstance(value, list):
        for item in value:
            _strings(item, out)
    return out


class Gateway:
    def __init__(self, backend_cmd, state_dir: str = ".memwall", policy: Policy = None,
                 judge_enabled: bool = False, judge_model: str = None, profile=None):
        self.backend_cmd = list(backend_cmd)
        self.policy = policy or Policy()
        self.judge_enabled = judge_enabled
        self.judge_model = judge_model
        self.profile = profile
        self.state = StateStore(state_dir)
        self._out_lock = threading.Lock()
        self.proc = None

    def run(self) -> int:
        self.proc = subprocess.Popen(
            self.backend_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0)
        print(
            f"memwall gateway: wrapping {' '.join(self.backend_cmd)} "
            f"(default-block-at={self.policy.default_block_at.name}, "
            f"judge={'on' if self.judge_enabled else 'off'}, state={self.state.root})",
            file=sys.stderr, flush=True)
        pump = threading.Thread(target=self._pump_backend, daemon=True)
        pump.start()
        try:
            while True:
                raw = sys.stdin.buffer.readline(MAX_REQUEST_BYTES + 1) if self.profile else sys.stdin.buffer.readline()
                if not raw:
                    break
                if self.profile and len(raw) > MAX_REQUEST_BYTES:
                    # Drain only this oversized frame, in bounded chunks. The
                    # next newline-delimited request must remain independent.
                    while raw and not raw.endswith(b"\n"):
                        raw = sys.stdin.buffer.readline(MAX_REQUEST_BYTES + 1)
                    self._refuse(None, "", "request exceeds 1 MiB", code=-32600)
                elif raw.strip():
                    self._handle_client(raw)
        finally:
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
            pump.join(timeout=5)
            try:
                self.proc.stdout.close()
            except OSError:
                pass
        return (self.proc.returncode or 0) if self.profile else 0

    def _pump_backend(self) -> None:
        for line in iter(self.proc.stdout.readline, b""):
            with self._out_lock:
                sys.stdout.buffer.write(line if line.endswith(b"\n") else line + b"\n")
                sys.stdout.buffer.flush()

    def _handle_client(self, raw: bytes) -> None:
        if self.profile:
            self._handle_enforced(raw)
            return
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            self._forward(raw)
            return
        if not (isinstance(msg, dict) and msg.get("method") == "tools/call"):
            self._forward(raw)
            return

        params = msg.get("params") or {}
        tool = str(params.get("name", ""))
        origin, modified = self._extract_origin(params)
        if modified:
            raw = json.dumps(msg, ensure_ascii=False).encode("utf-8")
        if not WRITE_TOOL.search(tool):
            self._forward(raw)
            return

        arguments = params.get("arguments") or {}
        try:
            reports = self._scan(tool, arguments)
        except Exception as exc:  # fail open: never take the store down
            print(f"memwall gateway: scan error on {tool}: {exc}", file=sys.stderr, flush=True)
            self._forward(raw)
            return

        findings = [f for rep in reports for f in rep.findings]
        threshold = self.policy.threshold_for(origin)
        worst = max((f.severity for f in findings), default=None)
        extra = {"origin": origin}

        if worst is not None and worst >= threshold:
            if self.judge_enabled:
                flagged = [rep for rep in reports if rep.findings]
                cleared, judge_info = self._consult_judge(flagged)
                extra["judge"] = judge_info
                findings = [f for rep in reports for f in rep.findings]  # judge may escalate
                if cleared:
                    self.state.log_event("allowed", tool, findings, payload=arguments, extra=extra)
                    self._forward(raw)
                    return
            qid = self.state.quarantine(tool, msg, findings, extra=extra)
            self.state.log_event("blocked", tool, findings, qid=qid, payload=arguments, extra=extra)
            if msg.get("id") is not None:
                self._reply_blocked(msg["id"], findings, qid, threshold)
            return

        self.state.log_event("allowed", tool, findings, payload=arguments, extra=extra)
        self._forward(raw)

    def _handle_enforced(self, raw: bytes) -> None:
        msg, tool = None, ""
        error_code = -32600
        try:
            if len(raw) > MAX_REQUEST_BYTES:
                raise ContractError("request exceeds 1 MiB")
            error_code = -32700
            msg = strict_loads(raw)
            error_code = -32600
            validate_depth(msg)
            if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
                raise ContractError("expected a JSON-RPC 2.0 object")
            if "id" in msg and msg["id"] is not None and type(msg["id"]) not in (str, int):
                raise ContractError("request id must be a string or integer")
            if "method" not in msg:
                if "id" not in msg or (("result" in msg) == ("error" in msg)):
                    raise ContractError("invalid JSON-RPC response")
                self._forward(raw)  # client response to a server-initiated call
                return
            if not isinstance(msg["method"], str) or "result" in msg or "error" in msg:
                raise ContractError("invalid JSON-RPC method")
            error_code = -32602
            if "params" in msg and not isinstance(msg["params"], dict):
                raise ContractError("MCP params must be an object")
            if msg["method"] != "tools/call":
                self._forward(raw)
                return

            if "id" not in msg or msg["id"] is None:
                raise ContractError("tools/call must be a request with an id")

            params = msg.get("params", {})
            if set(params) - {"name", "arguments", "_meta"}:
                raise ContractError("unsupported tools/call parameters")
            tool = params.get("name", "")
            if not isinstance(tool, str):
                tool = ""
                raise ContractError("tool name must be a string")
            if "_meta" in params:
                meta = params["_meta"]
                if not isinstance(meta, dict):
                    raise ContractError("tool metadata must be an object")
                if "memwall" in meta:
                    claim = meta["memwall"]
                    if (not isinstance(claim, dict) or set(claim) - {"origin"}
                            or not isinstance(claim.get("origin", "unknown"), str)):
                        raise ContractError("invalid Memwall origin metadata")
            arguments = params.get("arguments", {})
            groups = self.profile.extract(tool, arguments)
            original = copy.deepcopy(msg)
            origin, modified = self._extract_origin(params)
            if modified:
                raw = json.dumps(msg, ensure_ascii=False).encode("utf-8")
            threshold = self.policy.enforcement_threshold_for(origin)
            extra = {
                "origin": origin, "claimed_origin": origin,
                "effective_threshold": threshold.name, "policy_source": "operator-minimum",
                "profile": self.profile.name, "profile_version": self.profile.version,
                "role": self.profile.tools[tool],
                "groups": [{"id": f"{tool}#group{i}", "field_paths": group.field_paths}
                           for i, group in enumerate(groups)],
            }
            reports = [evaluate(MemoryRecord(
                id=f"{tool}#group{i}", content=group.content, store="gateway", source=tool,
                metadata={"field_paths": group.field_paths})) for i, group in enumerate(groups)]
            findings = [finding for report in reports for finding in report.findings]
            worst = max((finding.severity for finding in findings), default=None)
            if worst is not None and worst >= threshold:
                if self.judge_enabled:
                    _, info = self._consult_judge([report for report in reports if report.findings])
                    extra["judge"] = dict(info, mode="advisory")
                    findings = [finding for report in reports for finding in report.findings]
                qid = self.state.quarantine(tool, original, findings, extra=extra)
                self.state.log_event("blocked", tool, findings, qid=qid, payload=arguments, extra=extra)
                if "id" in msg:
                    self._reply_blocked(msg["id"], findings, qid, threshold)
                return
            self.state.log_event("allowed", tool, findings, payload=arguments, extra=extra)
        except ContractError as exc:
            self._refuse(msg, tool, str(exc), code=error_code)
            return
        except Exception as exc:
            # A failure to inspect or record a decision never authorizes a write.
            print(f"memwall gateway: enforcement failed: {exc}", file=sys.stderr, flush=True)
            self._refuse(msg, tool, "inspection or state unavailable", code=-32603)
            return

        if not self._forward(raw):
            self._refuse(msg, tool, "backend unavailable; write outcome unknown, do not retry automatically",
                         code=-32603)

    def _refuse(self, msg, tool: str, reason: str, code: int = -32602) -> None:
        try:
            self.state.log_event("refused", tool, [], extra={
                "profile": self.profile.name, "reason": reason})
        except Exception as exc:
            print(f"memwall gateway: cannot audit refusal: {exc}", file=sys.stderr, flush=True)
        # Valid notifications have no response. Invalid frames have no usable ID.
        if isinstance(msg, dict) and "id" not in msg and isinstance(msg.get("method"), str):
            return
        rid = msg.get("id") if isinstance(msg, dict) else None
        if type(rid) not in (str, int):
            rid = None
        self._reply({"jsonrpc": "2.0", "id": rid,
                     "error": {"code": code, "message": f"memwall refused request: {reason}"}})

    @staticmethod
    def _extract_origin(params) -> tuple:
        meta = params.get("_meta")
        if not isinstance(meta, dict):
            return "unknown", False
        mw_meta = meta.get("memwall")
        if not isinstance(mw_meta, dict):
            return "unknown", False
        origin = str(mw_meta.get("origin", "unknown")).lower()
        del meta["memwall"]
        if not meta:
            params.pop("_meta", None)
        return origin, True

    def _scan(self, tool: str, arguments) -> list:
        reports = []
        for idx, text in enumerate(_strings(arguments)):
            record = MemoryRecord(id=f"{tool}#{idx}", content=text, store="gateway", source=tool)
            reports.append(evaluate(record))
        return reports

    def _consult_judge(self, reports) -> tuple:
        try:
            from . import judge as judge_mod
            judge_mod.judge(reports, model=self.judge_model or judge_mod.DEFAULT_MODEL)
        # BaseException on purpose: judge raises SystemExit when the sdk or
        # API key is missing, and that must never kill the gateway.
        except BaseException as exc:
            print(f"memwall gateway: judge unavailable, keeping quarantine: {exc}",
                  file=sys.stderr, flush=True)
            return False, {"error": str(exc)}
        verdicts = {rep.record.id: rep.judge_verdict for rep in reports}
        cleared = bool(verdicts) and all(v in _CLEARING_VERDICTS for v in verdicts.values())
        return cleared, {"verdicts": verdicts}

    def _reply_blocked(self, msg_id, findings, qid: str, threshold: Severity) -> None:
        rules = ", ".join(sorted({
            f"{f.rule_id} {f.rule_name}" for f in findings if f.severity >= threshold}))
        text = (
            f"memwall blocked this memory write ({rules}). The content was "
            f"quarantined as {qid} for human review (memwall quarantine show {qid}). "
            f"Do not retry; continue without storing it.")
        self._reply({
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {"content": [{"type": "text", "text": text}], "isError": True},
        })

    def _forward(self, raw: bytes) -> bool:
        try:
            remaining = memoryview(raw if raw.endswith(b"\n") else raw + b"\n")
            while remaining:
                written = self.proc.stdin.write(remaining)
                if not written:
                    raise BrokenPipeError("backend pipe made no progress")
                remaining = remaining[written:]
            self.proc.stdin.flush()
            return True
        except (BrokenPipeError, OSError) as exc:
            print(f"memwall gateway: backend unavailable: {exc}", file=sys.stderr, flush=True)
            return False

    def _reply(self, obj: dict) -> None:
        data = (json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8")
        with self._out_lock:
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()
