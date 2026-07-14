"""Core data models for memwall."""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Optional


class Severity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:
        return self.name


@dataclass
class MemoryRecord:
    """One memory as stored by an agent, normalized across stores."""

    id: str
    content: str
    store: str      # adapter name, e.g. "mcp-memory", "mem0", "files"
    source: str     # file path or store location
    created_at: Optional[str] = None
    metadata: dict = field(default_factory=dict)


@dataclass
class Finding:
    rule_id: str
    rule_name: str
    severity: Severity
    message: str


@dataclass
class RecordReport:
    record: MemoryRecord
    findings: list = field(default_factory=list)
    judge_verdict: Optional[str] = None
    judge_confidence: Optional[float] = None
    judge_reason: Optional[str] = None

    @property
    def max_severity(self) -> Optional[Severity]:
        return max((f.severity for f in self.findings), default=None)


@dataclass
class ScanResult:
    reports: list
    scanned: int
    stores: list

    @property
    def flagged(self) -> list:
        return [r for r in self.reports if r.findings]
