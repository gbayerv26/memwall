"""Per-origin trust policy for the gateway (the provenance handshake).

Agents declare where memory content came from via MCP request metadata
(params._meta.memwall.origin). Each origin maps to a block threshold:
content from the open web is held to a stricter bar than content the user
typed. Undeclared origins fall back to the gateway's --block-at value.
"""
from __future__ import annotations

import json

from .models import Severity

DEFAULT_ORIGIN_THRESHOLDS = {
    "user": Severity.CRITICAL,
    "agent": Severity.HIGH,
    "tool": Severity.MEDIUM,
    "web": Severity.MEDIUM,
    "email": Severity.MEDIUM,
    "document": Severity.MEDIUM,
}


class Policy:
    def __init__(self, default_block_at: Severity = Severity.HIGH, origin_thresholds: dict = None):
        self.default_block_at = default_block_at
        self.origin_thresholds = dict(DEFAULT_ORIGIN_THRESHOLDS)
        if origin_thresholds:
            self.origin_thresholds.update(origin_thresholds)

    def threshold_for(self, origin: str) -> Severity:
        return self.origin_thresholds.get((origin or "unknown").lower(), self.default_block_at)

    @classmethod
    def from_file(cls, path: str) -> "Policy":
        with open(path, encoding="utf-8-sig") as fh:
            data = json.load(fh)
        default = Severity[str(data.get("default_block_at", "high")).upper()]
        origins = {
            str(origin).lower(): Severity[str(level).upper()]
            for origin, level in (data.get("origins") or {}).items()
        }
        return cls(default_block_at=default, origin_thresholds=origins)
