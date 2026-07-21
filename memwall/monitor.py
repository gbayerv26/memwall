"""Continuous monitoring: re-scan a store and surface only NEW findings.

The first run over a store establishes a baseline snapshot (a set of finding
fingerprints). Every later run reports findings whose fingerprint is not in
the snapshot - i.e. poison that appeared since last time - then folds them in.
This is the engine a hosted monitor wraps: stateless scan + persistent delta.
"""
from __future__ import annotations

import json
import hashlib
import os
import time
from dataclasses import dataclass

from . import adapters
from .heuristics import scan_records


def _target_identity(path: str) -> str:
    """Canonical identity used to isolate snapshots for each monitored target."""
    return os.path.normcase(os.path.realpath(os.path.abspath(os.fspath(path))))


def _normalized_format(fmt: str) -> str:
    return str(fmt or "auto").strip().lower()


def _snapshot_path(state_dir: str, path: str | None = None, fmt: str = "auto") -> str:
    identity = _target_identity(path) if path is not None else ""
    key = hashlib.sha256(f"{identity}|{_normalized_format(fmt)}".encode("utf-8")).hexdigest()[:32]
    return os.path.join(state_dir, f"monitor-snapshot-{key}.json")


def _finding_fingerprint(record, finding) -> str:
    blob = f"{record.source}|{record.id}|{record.content}|{finding.rule_id}".encode("utf-8")
    return hashlib.sha256(blob).hexdigest()[:16]


def _load_snapshot(state_dir: str, path: str, fmt: str) -> tuple[set, bool]:
    target = _target_identity(path)
    normalized_fmt = _normalized_format(fmt)
    try:
        with open(_snapshot_path(state_dir, path, fmt), encoding="utf-8") as fh:
            data = json.load(fh)
        if (not isinstance(data, dict) or data.get("version") != 2
                or data.get("target") != target or data.get("format") != normalized_fmt
                or not isinstance(data.get("ts"), str)
                or not isinstance(data.get("fingerprints"), list)
                or any(not isinstance(fp, str) for fp in data["fingerprints"])):
            return set(), False
        return set(data["fingerprints"]), True
    except (FileNotFoundError, json.JSONDecodeError, OSError, TypeError):
        return set(), False


def load_snapshot(state_dir: str, path: str | None = None, fmt: str = "auto") -> set:
    """Load fingerprints for a target; invalid snapshots are treated as empty."""
    if path is None:
        return set()
    return _load_snapshot(state_dir, path, fmt)[0]


def save_snapshot(state_dir: str, fingerprints: set, path: str = "", fmt: str = "auto") -> None:
    os.makedirs(state_dir, exist_ok=True)
    target = _target_identity(path)
    normalized_fmt = _normalized_format(fmt)
    destination = _snapshot_path(state_dir, path, fmt)
    tmp = destination + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump({"version": 2, "target": target, "format": normalized_fmt,
                   "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                   "fingerprints": sorted(fingerprints)}, fh)
    os.replace(tmp, destination)


@dataclass
class Tick:
    is_baseline: bool
    new_items: list       # list[(MemoryRecord, list[Finding])]
    total_findings: int
    scanned: int


def run_once(path: str, state_dir: str, fmt: str = "auto") -> Tick:
    previous, had_snapshot = _load_snapshot(state_dir, path, fmt)
    reports = scan_records(adapters.load(path, fmt))

    all_fps, new_items, total = set(), [], 0
    for rep in reports:
        total += len(rep.findings)
        fresh = []
        for f in rep.findings:
            fp = _finding_fingerprint(rep.record, f)
            all_fps.add(fp)
            if had_snapshot and fp not in previous:
                fresh.append(f)
        if fresh:
            new_items.append((rep.record, fresh))

    save_snapshot(state_dir, all_fps, path, fmt)
    return Tick(is_baseline=not had_snapshot, new_items=new_items,
                total_findings=total, scanned=len(reports))


def watch(path: str, state_dir: str, interval: int, fmt: str = "auto",
          once: bool = False, on_tick=None, sleep=time.sleep) -> None:
    while True:
        tick = run_once(path, state_dir, fmt)
        if on_tick is not None:
            on_tick(tick)
        if once:
            return
        sleep(interval)
