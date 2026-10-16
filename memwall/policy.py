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

    def enforcement_threshold_for(self, claimed_origin: str) -> Severity:
        """Untrusted claims may tighten, but never relax, the operator minimum."""
        return min(self.default_block_at, self.threshold_for(claimed_origin))

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


PRESETS = {
    "balanced": lambda: Policy(),
    "strict": lambda: Policy(default_block_at=Severity.MEDIUM, origin_thresholds={
        "user": Severity.HIGH, "agent": Severity.MEDIUM, "tool": Severity.LOW,
        "web": Severity.LOW, "email": Severity.LOW, "document": Severity.LOW}),
    "permissive": lambda: Policy(default_block_at=Severity.CRITICAL, origin_thresholds={
        "user": Severity.CRITICAL, "agent": Severity.CRITICAL, "tool": Severity.HIGH,
        "web": Severity.HIGH, "email": Severity.HIGH, "document": Severity.HIGH}),
}


def resolve(name_or_path: str) -> Policy:
    """Accept a built-in preset name (strict/balanced/permissive) or a JSON file path."""
    preset = PRESETS.get(str(name_or_path).lower())
    if preset is not None:
        return preset()
    return Policy.from_file(name_or_path)
