"""Append-only gateway state: forensic event log and quarantine store.

Both files are JSONL and append-only by design - status changes are recorded
as new lines and folded on read, so the audit trail is never rewritten.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
import uuid
from contextlib import contextmanager

from .contracts import ContractError, strict_loads


class StateError(RuntimeError):
    """State cannot safely authorize a quarantine operation."""


_QID = re.compile(r"q[A-Za-z0-9_-]{1,79}\Z")
_JOURNAL_DEPTH = 40  # Gateway request depth 32 plus the journal/evidence envelope.


def _validate_journal_depth(value):
    stack = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        if depth > _JOURNAL_DEPTH:
            raise StateError("quarantine journal nesting limit exceeded")
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)


@contextmanager
def _file_lock(path, wait=True):
    """OS-owned advisory lock, automatically released when a process dies."""
    with open(path, "a+b") as fh:
        if os.fstat(fh.fileno()).st_size == 0:
            fh.write(b"\0")
            fh.flush()
        deadline = time.monotonic() + (5 if wait else 0)
        while True:
            try:
                if os.name == "nt":
                    import msvcrt
                    fh.seek(0)
                    msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as exc:
                if time.monotonic() >= deadline:
                    raise StateError("quarantine state busy or lock unavailable") from exc
                time.sleep(.01)
        try:
            yield
        finally:
            if os.name == "nt":
                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(fh, fcntl.LOCK_UN)


class StateStore:
    def __init__(self, root: str):
        self.root = root
        os.makedirs(root, exist_ok=True)
        self.events_path = os.path.join(root, "events.jsonl")
        self.quarantine_path = os.path.join(root, "quarantine.jsonl")

    @staticmethod
    def _now() -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def _append(self, path: str, obj: dict) -> None:
        text = json.dumps(obj, ensure_ascii=False, allow_nan=False)
        if path == self.quarantine_path:
            _validate_journal_depth(strict_loads(text))
        data = (text + "\n").encode("utf-8")
        with open(path, "ab") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())

    @contextmanager
    def entry_lock(self, qid):
        if not isinstance(qid, str) or not _QID.fullmatch(qid):
            raise StateError("invalid quarantine id")
        with _file_lock(os.path.join(self.root, ".release-" + qid + ".lock"), wait=False):
            yield

    def _journal_lock(self):
        return _file_lock(os.path.join(self.root, ".quarantine.lock"))

    def _read(self, path: str):
        if not os.path.exists(path):
            return
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue

    def log_event(self, kind: str, tool: str, findings, qid: str = None, payload=None, extra: dict = None) -> None:
        obj = {
            "ts": self._now(),
            "event": kind,
            "tool": tool,
            "findings": [f"{f.rule_id}:{f.severity.name}" for f in findings],
        }
        if qid:
            obj["qid"] = qid
        if payload is not None:
            blob = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
            obj["payload_sha256"] = hashlib.sha256(blob).hexdigest()[:16]
        if extra:
            obj.update(extra)
        self._append(self.events_path, obj)

    def events(self) -> list:
        return list(self._read(self.events_path))

    def quarantine(self, tool: str, request: dict, findings, extra: dict = None) -> str:
        qid = "q" + uuid.uuid4().hex
        entry = {
            "version": 2,
            "type": "entry",
            "qid": qid,
            "ts": self._now(),
            "tool": tool,
            "request": request,
            "findings": [
                {"rule": f.rule_id, "name": f.rule_name, "severity": f.severity.name, "message": f.message}
                for f in findings
            ],
        }
        if extra:
            if set(extra) & (set(entry) | {"status", "release"}):
                raise StateError("quarantine metadata overrides a reserved field")
            entry.update(extra)
        # Validate the serialized form too, before it can poison the journal.
        _validate_journal_depth(strict_loads(json.dumps(entry, ensure_ascii=False, allow_nan=False)))
        with self._journal_lock():
            entries = self._entries()
            if qid in entries:
                raise StateError("quarantine id collision; no entry written")
            self._validate_entry(entry)
            self._append(self.quarantine_path, entry)
        return qid

    def set_status(self, qid: str, status: str, *, attempt=None, reason=None, outcome=None,
                   backend_quiesced=False) -> None:
        """Append a checked transition. Release/reconciliation callers hold entry_lock."""
        with self._journal_lock():
            entries = self._entries()
            if qid not in entries:
                raise StateError("no quarantine entry " + qid)
            row = {"version": 2, "type": "status", "qid": qid, "ts": self._now(),
                   "status": status, "previous": entries[qid]["status"]}
            if attempt is not None:
                row["attempt"] = attempt
            if reason is not None:
                row["reason"] = reason
            if outcome is not None:
                row["outcome"] = outcome
                row["backend_quiesced"] = backend_quiesced
            self._fold_status(entries[qid], row)
            self._append(self.quarantine_path, row)

    @staticmethod
    def _validate_entry(obj):
        if (not isinstance(obj.get("qid"), str) or not _QID.fullmatch(obj["qid"])
                or not isinstance(obj.get("ts"), str) or not isinstance(obj.get("tool"), str)
                or not obj["tool"] or not isinstance(obj.get("findings"), list)
                or "status" in obj or "release" in obj):
            raise StateError("invalid quarantine journal entry")
        request = obj.get("request")
        if not isinstance(request, dict):
            raise StateError("invalid quarantine journal request")
        params = request.get("params")
        if (request.get("jsonrpc") != "2.0" or request.get("method") != "tools/call"
                or not isinstance(params, dict) or params.get("name") != obj["tool"]
                or not isinstance(params.get("arguments"), dict)):
            raise StateError("invalid quarantine journal request")
        for finding in obj["findings"]:
            if not isinstance(finding, dict) or not isinstance(finding.get("rule"), str):
                raise StateError("invalid quarantine journal finding")

    @staticmethod
    def _fold_status(entry, row):
        previous, status = entry["status"], row.get("status")
        if row.get("version") is None:
            # Historical CLI records could drop a released entry, but never reopen it.
            if (entry.get("version") is not None or entry.get("release", {}).get("version") is not None
                    or status not in ("released", "dropped") or previous == "dropped"):
                raise StateError("invalid legacy quarantine journal transition")
        else:
            if set(row) - {"version", "type", "qid", "ts", "status", "previous", "attempt",
                           "reason", "outcome", "backend_quiesced"}:
                raise StateError("unsupported quarantine journal transition fields")
            if row.get("previous") != previous:
                raise StateError("quarantine journal transition does not match previous state")
            attempt = row.get("attempt")
            old_attempt = entry.get("release", {}).get("attempt")
            reconciliation = row.get("outcome")
            if reconciliation is not None:
                valid = (previous in ("releasing", "uncertain")
                         and reconciliation in ("applied", "not-applied")
                         and status == ("released" if reconciliation == "applied" else "pending")
                         and isinstance(row.get("reason"), str) and row["reason"].strip()
                         and attempt == old_attempt
                         and (reconciliation != "not-applied" or row.get("backend_quiesced") is True))
            elif previous == "pending":
                valid = (status == "dropped" or (status == "releasing"
                         and isinstance(attempt, str) and len(attempt) == 32))
            else:
                valid = (previous == "releasing" and attempt == old_attempt
                         and (status in ("released", "uncertain") or
                              (status == "pending" and row.get("reason") == "not-dispatched")))
            if not valid:
                raise StateError("invalid quarantine journal transition")
        entry["status"] = status
        entry["release"] = dict(row)

    def _entries(self):
        entries = {}
        try:
            fh = open(self.quarantine_path, "rb")
        except FileNotFoundError:
            return entries
        with fh:
            for number, raw in enumerate(fh, 1):
                try:
                    if not raw.strip():
                        continue
                    if not raw.endswith(b"\n"):
                        raise StateError("incomplete record")
                    obj = strict_loads(raw)
                    _validate_journal_depth(obj)
                    if (not isinstance(obj, dict) or obj.get("version") not in (None, 2)
                            or type(obj.get("version", 2)) is not int
                            or not isinstance(obj.get("ts"), str)):
                        raise StateError("unsupported record schema")
                    qid = obj.get("qid")
                    if not isinstance(qid, str) or not _QID.fullmatch(qid):
                        raise StateError("invalid quarantine id")
                    if obj.get("type") == "entry":
                        self._validate_entry(obj)
                        if qid in entries:
                            raise StateError("duplicate quarantine id")
                        entries[qid] = dict(obj, status="pending")
                    elif obj.get("type") == "status" and qid in entries:
                        self._fold_status(entries[qid], obj)
                    else:
                        raise StateError("unknown record or missing entry")
                except (ContractError, StateError) as exc:
                    raise StateError(f"quarantine journal invalid at line {number}: {exc}; "
                                     "preserve the journal and review it before recovery") from exc
        return entries

    def quarantine_entries(self) -> list:
        with self._journal_lock():
            return list(self._entries().values())
