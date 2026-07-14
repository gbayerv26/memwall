"""Append-only gateway state: forensic event log and quarantine store.

Both files are JSONL and append-only by design - status changes are recorded
as new lines and folded on read, so the audit trail is never rewritten.
"""
from __future__ import annotations

import hashlib
import json
import os
import time


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
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(obj, ensure_ascii=False) + "\n")

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
        blob = json.dumps(request, sort_keys=True, ensure_ascii=False)
        qid = "q" + hashlib.sha256((self._now() + blob).encode("utf-8")).hexdigest()[:8]
        entry = {
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
            entry.update(extra)
        self._append(self.quarantine_path, entry)
        return qid

    def set_status(self, qid: str, status: str) -> None:
        self._append(self.quarantine_path, {"type": "status", "qid": qid, "ts": self._now(), "status": status})

    def quarantine_entries(self) -> list:
        entries, status = {}, {}
        for obj in self._read(self.quarantine_path):
            if obj.get("type") == "entry":
                entries[obj["qid"]] = obj
            elif obj.get("type") == "status":
                status[obj["qid"]] = obj["status"]
        for qid, entry in entries.items():
            entry["status"] = status.get(qid, "pending")
        return list(entries.values())
