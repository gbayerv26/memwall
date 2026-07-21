"""Adapter for SQLite-backed memory stores (Letta, mem0 history, custom agents).

Opens the database read-only and scans every text cell in every table.
Detected by file magic, so any extension works.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

from ..models import MemoryRecord

MAGIC = b"SQLite format 3\x00"
MAX_RECORDS = 20000
MIN_TEXT_LEN = 4


def is_sqlite(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(16) == MAGIC
    except OSError:
        return False


def load(path: str) -> list:
    uri = Path(path).resolve().as_uri() + "?mode=ro"
    try:
        con = sqlite3.connect(uri, uri=True)
    except sqlite3.Error:
        con = sqlite3.connect(path)
    records = []
    try:
        tables = [row[0] for row in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
        for table in tables:
            try:
                cols = [info[1] for info in con.execute(f'PRAGMA table_info("{table}")')]
                cursor = con.execute(f'SELECT rowid, * FROM "{table}"')
            except sqlite3.Error:  # WITHOUT ROWID / virtual tables
                continue
            for row in cursor:
                rowid, values = row[0], row[1:]
                for col, value in zip(cols, values):
                    if not isinstance(value, str) or len(value.strip()) < MIN_TEXT_LEN:
                        continue
                    records.append(MemoryRecord(
                        id=f"{table}.{col}#{rowid}",
                        content=value,
                        store="sqlite",
                        source=path,
                        metadata={"table": table, "column": col},
                    ))
                    if len(records) >= MAX_RECORDS:
                        return records
    finally:
        con.close()
    return records
