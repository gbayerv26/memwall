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
The proxy fails open on internal scan errors so it never takes the store down.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import threading

from .heuristics import evaluate
from .models import MemoryRecord, Severity
from .policy import Policy
from .state import StateStore

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
                 judge_enabled: bool = False, judge_model: str = None):
        self.backend_cmd = list(backend_cmd)
        self.policy = policy or Policy()
        self.judge_enabled = judge_enabled
        self.judge_model = judge_model
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
        threading.Thread(target=self._pump_backend, daemon=True).start()
        try:
            for raw in iter(sys.stdin.buffer.readline, b""):
                raw = raw.strip()
                if raw:
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
                self.proc.stdout.close()
            except OSError:
                pass
        return 0

    def _pump_backend(self) -> None:
        for line in iter(self.proc.stdout.readline, b""):
            with self._out_lock:
                sys.stdout.buffer.write(line if line.endswith(b"\n") else line + b"\n")
                sys.stdout.buffer.flush()

    def _handle_client(self, raw: bytes) -> None:
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

    def _forward(self, raw: bytes) -> None:
        try:
            self.proc.stdin.write(raw + b"\n")
            self.proc.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            print(f"memwall gateway: backend unavailable: {exc}", file=sys.stderr, flush=True)

    def _reply(self, obj: dict) -> None:
        data = (json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8")
        with self._out_lock:
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()
