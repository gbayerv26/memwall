"""Adapter for mem0-style exports (JSON with a list of memory objects)."""
from __future__ import annotations

import json

from ..models import MemoryRecord

_META_KEYS = ("user_id", "agent_id", "run_id", "categories")


def load(path: str) -> list:
    with open(path, encoding="utf-8-sig") as fh:
        data = json.load(fh)
    if isinstance(data, dict):
        items = data.get("results") or data.get("memories") or data.get("items") or []
    else:
        items = data
    if not isinstance(items, list):
        items = [items]

    records = []
    for idx, item in enumerate(items):
        created = None
        metadata = {}
        if isinstance(item, str):
            content, rid = item, f"mem-{idx}"
        elif isinstance(item, dict):
            content = item.get("memory") or item.get("text") or item.get("content") or ""
            rid = str(item.get("id", f"mem-{idx}"))
            created = item.get("created_at")
            metadata = {k: item[k] for k in _META_KEYS if k in item}
        else:
            continue
        if content:
            records.append(MemoryRecord(
                id=rid,
                content=str(content),
                store="mem0",
                source=path,
                created_at=created,
                metadata=metadata,
            ))
    return records
