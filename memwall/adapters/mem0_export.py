"""Adapter for mem0-style exports (JSON with a list of memory objects)."""
from __future__ import annotations

import json

from ..models import MemoryRecord

_META_KEYS = ("user_id", "agent_id", "run_id", "categories")
_COLLECTIONS = ("results", "memories", "items")
_TEXT_FIELDS = ("memory", "text", "content")


def load(path: str, *, issue=None) -> list:
    with open(path, encoding="utf-8-sig") as fh:
        data = json.load(fh)
    if isinstance(data, dict):
        collections = [data[key] for key in _COLLECTIONS if key in data]
        if issue is not None and (not collections or any(not isinstance(value, list) for value in collections)):
            issue("unsupported_document")
        items = next((value for value in collections if value), [])
    else:
        items = data
        if issue is not None and not isinstance(data, list):
            issue("unsupported_document")
    if not isinstance(items, list):
        items = [items]

    records = []
    for idx, item in enumerate(items):
        created = None
        metadata = {}
        if isinstance(item, str):
            content, rid = item, f"mem-{idx}"
        elif isinstance(item, dict):
            if issue is not None:
                fields = [item[key] for key in _TEXT_FIELDS if key in item]
                if not fields or any(value is not None and not isinstance(value, str) for value in fields):
                    issue("unsupported_item", location=idx + 1)
            content = item.get("memory") or item.get("text") or item.get("content") or ""
            rid = str(item.get("id", f"mem-{idx}"))
            created = item.get("created_at")
            metadata = {k: item[k] for k in _META_KEYS if k in item}
        else:
            if issue is not None:
                issue("unsupported_item", location=idx + 1)
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
