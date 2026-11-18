"""Store adapters: read memories from different sources into MemoryRecords."""
from __future__ import annotations

import os
import sqlite3
import sys
from functools import partial

from . import files, generic_json, mcp_memory, mem0_export, sqlite_store
from .coverage import Coverage

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


def detect_format(path: str, *, strict=False) -> str:
    if sqlite_store.is_sqlite(path, strict=strict):
        return "sqlite"
    ext = os.path.splitext(path)[1].lower()
    if ext == ".jsonl":
        return "mcp"
    if ext == ".json":
        try:
            with open(path, encoding="utf-8-sig") as fh:
                head = fh.read(4096).lstrip()
        except OSError:
            if strict:
                raise
            return "json"
        # The MCP reference memory server writes JSONL into a .json file.
        if head.startswith('{"type"') or '"observations"' in head:
            return "mcp"
        if '"memory"' in head or '"results"' in head:
            return "mem0"
        return "json"
    return "files"


MAX_WALK_FILE_BYTES = 5 * 1024 * 1024


def _walkable(file_path: str, low: str, ext: str, coverage=None) -> bool:
    try:
        confirmed_sqlite = sqlite_store.is_sqlite(file_path, strict=coverage is not None)
        if ext in DB_EXTS and not confirmed_sqlite:
            return False
        if ext == ".json" and low not in KNOWN_NAMES:
            if ("memor" not in low and "mem0" not in low
                    and detect_format(file_path, strict=coverage is not None) == "json"):
                return False
        if confirmed_sqlite or os.path.getsize(file_path) <= MAX_WALK_FILE_BYTES:
            return True
    except (OSError, UnicodeError) as exc:
        if coverage is not None:
            coverage.selected_sources += 1
            code = "decode_error" if isinstance(exc, UnicodeError) else "source_unreadable"
            coverage.issue(code, file_path)
        return False
    if coverage is None:
        print(f"memwall: skipped {file_path}: larger than "
              f"{MAX_WALK_FILE_BYTES // (1024 * 1024)} MB", file=sys.stderr)
    else:
        coverage.selected_sources += 1
        coverage.issue("file_size_limit", file_path)
    return False


def load(path: str, fmt: str = "auto") -> list:
    return _load(path, fmt)


def load_with_coverage(path: str, fmt: str = "auto"):
    coverage = Coverage(os.fspath(path), fmt)
    records = _load(path, fmt, coverage)
    coverage.records = len(records)
    return records, coverage


def _load_file(path, fmt, coverage=None):
    if coverage is None:
        return ADAPTERS[detect_format(path) if fmt == "auto" else fmt](path)

    coverage.selected_sources += 1
    issues_before = sum(coverage.issue_counts.values())
    try:
        selected_format = fmt
        if fmt == "auto":
            selected_format = ("sqlite" if os.path.splitext(path)[1].lower() in DB_EXTS
                               else detect_format(path, strict=True))
        records = ADAPTERS[selected_format](path, issue=partial(coverage.issue, path=path))
    except FileNotFoundError:
        coverage.issue("source_missing", path)
        return []
    except UnicodeError:
        coverage.issue("decode_error", path)
        return []
    except (ValueError, RecursionError):
        coverage.issue("invalid_document", path)
        return []
    except (OSError, sqlite3.Error):
        coverage.issue("source_unreadable", path)
        return []
    coverage._opened_sources += 1
    if sum(coverage.issue_counts.values()) == issues_before:
        coverage.complete_sources += 1
    return records


def _load(path, fmt, coverage=None):
    if fmt != "auto":
        return _load_file(path, fmt, coverage)
    if os.path.isdir(path):
        records = []

        def walk_error(exc):
            if coverage is not None:
                coverage.issue("directory_unreadable", exc.filename or path)

        for root, dirs, names in os.walk(path, onerror=walk_error):
            dirs[:] = [d for d in dirs
                       if d not in SKIP_DIRS and (not d.startswith(".") or d in KEEP_HIDDEN)]
            for name in sorted(names):
                low = name.lower()
                ext = os.path.splitext(low)[1]
                file_path = os.path.join(root, name)
                # Probe the SQLite magic before rejecting unknown extensions.
                if low not in KNOWN_NAMES and ext not in EXTS and not sqlite_store.is_sqlite(file_path):
                    continue
                try:
                    if _walkable(file_path, low, ext, coverage):
                        records.extend(_load_file(file_path, "auto", coverage))
                except Exception as exc:  # keep walking on malformed files
                    if coverage is not None:
                        raise
                    print(f"memwall: skipped {file_path}: {exc}", file=sys.stderr)
        return records
    return _load_file(path, fmt, coverage)
