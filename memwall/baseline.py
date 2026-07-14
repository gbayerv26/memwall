"""Baseline files: accept known findings so CI only fails on new ones.

A fingerprint is derived from the rule id and the memory content, so a
baselined finding stays suppressed until the memory itself changes.
"""
from __future__ import annotations

import hashlib
import json


def fingerprint(record, finding) -> str:
    blob = f"{finding.rule_id}|{record.content}".encode("utf-8")
    return hashlib.sha256(blob).hexdigest()[:16]


def load_baseline(path: str) -> set:
    try:
        with open(path, encoding="utf-8-sig") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return set()
    return set(data.get("fingerprints") or [])


def save_baseline(path: str, reports) -> int:
    fingerprints = sorted({
        fingerprint(rep.record, f) for rep in reports for f in rep.findings})
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"version": 1, "fingerprints": fingerprints}, fh, indent=2)
    return len(fingerprints)
