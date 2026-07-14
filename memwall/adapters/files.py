"""Adapter for plain text/markdown memory and instruction files.

Instruction files (CLAUDE.md, AGENTS.md, ...) are marked kind="instructions"
so the rule engine can skip imperative-phrasing rules that are normal there.
Every other text file is kind="notes". Each blank-line-separated block
becomes one MemoryRecord.
"""
from __future__ import annotations

import os

from ..models import MemoryRecord

INSTRUCTION_NAMES = {
    "claude.md", "agents.md", "gemini.md", ".cursorrules",
    "copilot-instructions.md", "system.md",
}


def _blocks(text: str):
    block, start = [], 1
    line_no = 0
    for line_no, line in enumerate(text.splitlines(), 1):
        if line.strip():
            if not block:
                start = line_no
            block.append(line)
        elif block:
            yield start, "\n".join(block)
            block = []
    if block:
        yield start, "\n".join(block)


def load(path: str) -> list:
    with open(path, encoding="utf-8-sig", errors="replace") as fh:
        text = fh.read()
    base = os.path.basename(path)
    low = base.lower()
    kind = "instructions" if low in INSTRUCTION_NAMES or low.endswith(".mdc") else "notes"
    return [
        MemoryRecord(
            id=f"{base}:{line}",
            content=content,
            store="files",
            source=path,
            metadata={"kind": kind},
        )
        for line, content in _blocks(text)
    ]
