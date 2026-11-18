"""Adapter for the MCP reference memory server (JSONL of entities/relations)."""
from __future__ import annotations

import json

from ..models import MemoryRecord


def load(path: str, *, issue=None) -> list:
    records = []
    with open(path, encoding="utf-8-sig", errors="strict" if issue is None else "surrogateescape") as fh:
        for line_no, line in enumerate(fh, 1):
            if issue is not None:
                try:
                    line.encode("utf-8")
                except UnicodeEncodeError:
                    issue("decode_error", location=line_no)
                    continue
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except (ValueError, RecursionError):
                if issue is not None:
                    issue("invalid_jsonl", location=line_no)
                continue
            if not isinstance(obj, dict):
                if issue is not None:
                    issue("unsupported_item", location=line_no)
                continue
            if obj.get("type") == "entity":
                name = obj.get("name", f"entity-{line_no}")
                observations = obj.get("observations", [])
                if issue is not None and not isinstance(observations, list):
                    issue("unsupported_item", location=line_no)
                    continue
                if issue is not None and ("observations" not in obj
                                          or not all(isinstance(value, str) for value in observations)):
                    issue("unsupported_item", location=line_no)
                for idx, observation in enumerate(observations):
                    records.append(MemoryRecord(
                        id=f"{name}#obs{idx}",
                        content=str(observation),
                        store="mcp-memory",
                        source=path,
                        metadata={"entity": name, "entityType": obj.get("entityType")},
                    ))
            elif obj.get("type") == "relation":
                if issue is not None and any(not isinstance(obj.get(key), str)
                                             for key in ("from", "relationType", "to")):
                    issue("unsupported_item", location=line_no)
                content = f"{obj.get('from')} {obj.get('relationType')} {obj.get('to')}"
                records.append(MemoryRecord(
                    id=f"relation:{line_no}",
                    content=content,
                    store="mcp-memory",
                    source=path,
                    metadata={"relation": True},
                ))
            elif issue is not None:
                issue("unsupported_item", location=line_no)
    return records
