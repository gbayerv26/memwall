"""Continuous monitoring: re-scan a store and surface only NEW findings.

The first run over a store establishes a baseline snapshot (a set of finding
fingerprints). Every later run reports findings whose fingerprint is not in
the snapshot - i.e. poison that appeared since last time - then folds them in.
This is the engine a hosted monitor wraps: stateless scan + persistent delta.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass

from . import adapters
from .baseline import fingerprint
from .heuristics import scan_records


def _snapshot_path(state_dir: str) -> str:
    return os.path.join(state_dir, "monitor-snapshot.json")


def load_snapshot(state_dir: str) -> set:
    try:
        with open(_snapshot_path(state_dir), encoding="utf-8") as fh:
            return set(json.load(fh).get("fingerprints") or [])
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return set()


def save_snapshot(state_dir: str, fingerprints: set) -> None:
    os.makedirs(state_dir, exist_ok=True)
    tmp = _snapshot_path(state_dir) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                   "fingerprints": sorted(fingerprints)}, fh)
    os.replace(tmp, _snapshot_path(state_dir))


@dataclass
class Tick:
    is_baseline: bool
    new_items: list       # list[(MemoryRecord, list[Finding])]
    total_findings: int
    scanned: int


def run_once(path: str, state_dir: str, fmt: str = "auto") -> Tick:
    had_snapshot = os.path.exists(_snapshot_path(state_dir))
    previous = load_snapshot(state_dir)
    reports = scan_records(adapters.load(path, fmt))

    all_fps, new_items, total = set(), [], 0
    for rep in reports:
        total += len(rep.findings)
        fresh = []
        for f in rep.findings:
            fp = fingerprint(rep.record, f)
            all_fps.add(fp)
            if had_snapshot and fp not in previous:
                fresh.append(f)
        if fresh:
            new_items.append((rep.record, fresh))

    save_snapshot(state_dir, all_fps)
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
