"""Fallback adapter for generic JSON memory dumps."""
from __future__ import annotations

import json

from ..models import MemoryRecord

_CONTENT_FIELDS = ("content", "memory", "text", "observation", "value", "fact", "note")


def load(path: str) -> list:
    with open(path, encoding="utf-8-sig") as fh:
        data = json.load(fh)
    if isinstance(data, dict):
        for key in ("results", "items", "memories", "data", "records"):
            if isinstance(data.get(key), list):
                data = data[key]
                break
        else:
            data = [data]
    if not isinstance(data, list):
        data = [data]

    records = []
    for idx, item in enumerate(data):
        if isinstance(item, str):
            content = item
        elif isinstance(item, dict):
            content = next((str(item[f]) for f in _CONTENT_FIELDS if item.get(f)), "")
        else:
            continue
        if content:
            records.append(MemoryRecord(
                id=str(item.get("id", f"item-{idx}")) if isinstance(item, dict) else f"item-{idx}",
                content=content,
                store="json",
                source=path,
            ))
    return records
