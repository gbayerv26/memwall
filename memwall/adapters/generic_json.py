"""Fallback adapter for generic JSON memory dumps."""
from __future__ import annotations

import json

from ..models import MemoryRecord
from .identity import json_identity

_CONTENT_FIELDS = ("content", "memory", "text", "observation", "value", "fact", "note")


def load(path: str, *, issue=None) -> list:
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
        if issue is not None:
            if isinstance(item, dict):
                fields = [item[key] for key in _CONTENT_FIELDS if key in item]
                if not fields or any(value is not None and not isinstance(value, str) for value in fields):
                    issue("unsupported_item", location=idx + 1)
            elif not isinstance(item, str):
                issue("unsupported_item", location=idx + 1)
        if isinstance(item, str):
            content = item
        elif isinstance(item, dict):
            content = next((str(item[f]) for f in _CONTENT_FIELDS if item.get(f)), "")
        else:
            continue
        if content:
            key, namespace = json_identity(item)
            records.append(MemoryRecord(
                native_key=key, inventory_namespace=namespace, inventory_locator=f"item[{idx}]",
                id=str(item.get("id", f"item-{idx}")) if isinstance(item, dict) else f"item-{idx}",
                content=content,
                store="json",
                source=path,
            ))
    return records
