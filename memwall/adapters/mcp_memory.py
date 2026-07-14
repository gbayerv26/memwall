"""Adapter for the MCP reference memory server (JSONL of entities/relations)."""
from __future__ import annotations

import json

from ..models import MemoryRecord


def load(path: str) -> list:
    records = []
    with open(path, encoding="utf-8-sig") as fh:
        for line_no, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(obj, dict):
                continue
            if obj.get("type") == "entity":
                name = obj.get("name", f"entity-{line_no}")
                for idx, observation in enumerate(obj.get("observations", [])):
                    records.append(MemoryRecord(
                        id=f"{name}#obs{idx}",
                        content=str(observation),
                        store="mcp-memory",
                        source=path,
                        metadata={"entity": name, "entityType": obj.get("entityType")},
                    ))
            elif obj.get("type") == "relation":
                content = f"{obj.get('from')} {obj.get('relationType')} {obj.get('to')}"
                records.append(MemoryRecord(
                    id=f"relation:{line_no}",
                    content=content,
                    store="mcp-memory",
                    source=path,
                    metadata={"relation": True},
                ))
    return records
