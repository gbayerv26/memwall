"""Store adapters: read memories from different sources into MemoryRecords."""
from __future__ import annotations

import os
import sys

from . import files, generic_json, mcp_memory, mem0_export, sqlite_store

ADAPTERS = {
    "files": files.load,
    "mcp": mcp_memory.load,
    "mem0": mem0_export.load,
    "json": generic_json.load,
    "sqlite": sqlite_store.load,
}

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".next"}
# Hidden dirs are skipped except the ones agents actually keep memory in.
KEEP_HIDDEN = {".claude", ".codex", ".cursor", ".gemini", ".github"}
KNOWN_NAMES = {"claude.md", "agents.md", "gemini.md", ".cursorrules", "memory.json", "memory.jsonl"}
DB_EXTS = {".db", ".sqlite", ".sqlite3"}
EXTS = {".md", ".mdc", ".txt", ".json", ".jsonl"} | DB_EXTS


def detect_format(path: str) -> str:
    if sqlite_store.is_sqlite(path):
        return "sqlite"
    ext = os.path.splitext(path)[1].lower()
    if ext == ".jsonl":
        return "mcp"
    if ext == ".json":
        try:
            with open(path, encoding="utf-8-sig") as fh:
                head = fh.read(4096).lstrip()
        except OSError:
            return "json"
        # The MCP reference memory server writes JSONL into a .json file.
        if head.startswith('{"type"') or '"observations"' in head:
            return "mcp"
        if '"memory"' in head or '"results"' in head:
            return "mem0"
        return "json"
    return "files"


MAX_WALK_FILE_BYTES = 5 * 1024 * 1024


def _walkable(file_path: str, low: str, ext: str) -> bool:
    confirmed_sqlite = sqlite_store.is_sqlite(file_path)
    try:
        if os.path.getsize(file_path) > MAX_WALK_FILE_BYTES:
            if not confirmed_sqlite:
                print(f"memwall: skipped {file_path}: larger than "
                      f"{MAX_WALK_FILE_BYTES // (1024 * 1024)} MB", file=sys.stderr)
                return False
    except OSError:
        return False
    if ext in DB_EXTS:
        return confirmed_sqlite
    if ext == ".json" and low not in KNOWN_NAMES:
        # In directory walks, only ingest .json that looks like agent memory -
        # otherwise every package.json and tsconfig.json becomes noise.
        return "memor" in low or "mem0" in low or detect_format(file_path) != "json"
    return True


def load(path: str, fmt: str = "auto") -> list:
    if fmt != "auto":
        return ADAPTERS[fmt](path)
    if os.path.isdir(path):
        records = []
        for root, dirs, names in os.walk(path):
            dirs[:] = [d for d in dirs
                       if d not in SKIP_DIRS and (not d.startswith(".") or d in KEEP_HIDDEN)]
            for name in sorted(names):
                low = name.lower()
                ext = os.path.splitext(low)[1]
                file_path = os.path.join(root, name)
                # Probe the SQLite magic before rejecting unknown extensions.
                if low not in KNOWN_NAMES and ext not in EXTS and not sqlite_store.is_sqlite(file_path):
                    continue
                if not _walkable(file_path, low, ext):
                    continue
                try:
                    records.extend(load(file_path, "auto"))
                except Exception as exc:  # keep walking on malformed files
                    print(f"memwall: skipped {file_path}: {exc}", file=sys.stderr)
        return records
    return ADAPTERS[detect_format(path)](path)
