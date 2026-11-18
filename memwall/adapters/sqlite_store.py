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


def _quote_identifier(identifier: str) -> str:
    """Quote a SQLite identifier, escaping embedded double quotes."""
    return '"' + identifier.replace('"', '""') + '"'


def is_sqlite(path: str, *, strict=False) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(16) == MAGIC
    except OSError:
        if strict:
            raise
        return False


def load(path: str, *, issue=None) -> list:
    uri = Path(path).resolve().as_uri() + "?mode=ro"
    con = sqlite3.connect(uri, uri=True)
    records = []
    try:
        con.execute("PRAGMA query_only = ON")
        tables = [row[0] for row in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
        for table_no, table in enumerate(tables, 1):
            quoted_table = _quote_identifier(table)
            try:
                cursor = con.execute(f'SELECT rowid, * FROM {quoted_table}')
                cols = [column[0] for column in cursor.description[1:]]
            except sqlite3.Error:  # WITHOUT ROWID / virtual tables
                if issue is not None:
                    issue("table_unreadable", location=table_no)
                continue
            try:
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
                            if issue is not None:
                                issue("record_limit", location=table_no)
                            return records
            except sqlite3.Error:
                if issue is None:
                    raise
                issue("table_unreadable", location=table_no)
    finally:
        con.close()
    return records
