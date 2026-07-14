"""Render scan results as terminal text, JSON, or Markdown."""
from __future__ import annotations

import json
import os
import sys

from . import __version__
from .models import ScanResult, Severity

_ANSI = {
    Severity.CRITICAL: "\x1b[1;95m",
    Severity.HIGH: "\x1b[1;91m",
    Severity.MEDIUM: "\x1b[33m",
    Severity.LOW: "\x1b[36m",
    Severity.INFO: "\x1b[90m",
}
_RESET = "\x1b[0m"
_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
_HIDDEN = ("​‌‍⁠﻿"
           "‪‫‬‭‮⁦⁧⁨⁩")


def _clean(text: str, limit: int = 160) -> str:
    out = " ".join(text.split())
    for ch in _HIDDEN:
        out = out.replace(ch, "\\u%04x" % ord(ch))
    if len(out) > limit:
        out = out[:limit] + "..."
    return out


def render_terminal(result: ScanResult, color: "bool | None" = None, quiet: bool = False) -> str:
    if color is None:
        color = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
        if color and os.name == "nt":
            os.system("")  # enable ANSI escape processing on Windows consoles

    def paint(sev: Severity, text: str) -> str:
        return f"{_ANSI[sev]}{text}{_RESET}" if color else text

    lines = [f"scanned {result.scanned} memories from {len(result.stores)} source(s)"]
    flagged = sorted(result.flagged, key=lambda r: r.max_severity, reverse=True)
    if not flagged:
        lines.append("clean: no findings.")
        return "\n".join(lines)

    counts = {}
    for rep in flagged:
        counts[rep.max_severity] = counts.get(rep.max_severity, 0) + 1
    summary = ", ".join(f"{counts[s]} {s.name.lower()}" for s in _SEV_ORDER if s in counts)
    lines.append(f"flagged {len(flagged)} of {result.scanned}: {summary}")
    if quiet:
        return "\n".join(lines)

    for rep in flagged:
        sev = rep.max_severity
        lines.append("")
        lines.append(paint(sev, f"[{sev.name}] {rep.record.id}") + f"  ({rep.record.store}: {rep.record.source})")
        lines.append(f'  "{_clean(rep.record.content)}"')
        for f in sorted(rep.findings, key=lambda f: f.severity, reverse=True):
            lines.append(f"  - {f.rule_id} {f.rule_name} ({f.severity.name}): {f.message}")
        if rep.judge_verdict:
            conf = f" ({rep.judge_confidence:.2f})" if rep.judge_confidence is not None else ""
            lines.append(f"  judge: {rep.judge_verdict}{conf} - {rep.judge_reason or ''}")
    return "\n".join(lines)


def to_dict(result: ScanResult) -> dict:
    return {
        "memwall_version": __version__,
        "scanned": result.scanned,
        "sources": result.stores,
        "flagged": len(result.flagged),
        "records": [
            {
                "id": rep.record.id,
                "source": rep.record.source,
                "store": rep.record.store,
                "severity": rep.max_severity.name if rep.max_severity is not None else None,
                "content": rep.record.content,
                "findings": [
                    {"rule": f.rule_id, "name": f.rule_name, "severity": f.severity.name, "message": f.message}
                    for f in rep.findings
                ],
                "judge": (
                    {"verdict": rep.judge_verdict, "confidence": rep.judge_confidence, "reason": rep.judge_reason}
                    if rep.judge_verdict else None
                ),
            }
            for rep in result.reports
            if rep.findings or rep.judge_verdict
        ],
    }


def write_json(result: ScanResult, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(to_dict(result), fh, indent=2, ensure_ascii=False)


def write_markdown(result: ScanResult, path: str) -> None:
    lines = [
        "# memwall scan report",
        "",
        f"- scanned: {result.scanned} memories",
        f"- sources: {len(result.stores)}",
        f"- flagged: {len(result.flagged)}",
        "",
    ]
    for rep in sorted(result.flagged, key=lambda r: r.max_severity, reverse=True):
        lines.append(f"## [{rep.max_severity.name}] `{rep.record.id}`")
        lines.append(f"*{rep.record.store}: {rep.record.source}*")
        lines.append("")
        lines.append(f"> {_clean(rep.record.content, 400)}")
        lines.append("")
        for f in rep.findings:
            lines.append(f"- **{f.rule_id} {f.rule_name}** ({f.severity.name}): {f.message}")
        if rep.judge_verdict:
            lines.append(f"- **judge**: {rep.judge_verdict} - {rep.judge_reason or ''}")
        lines.append("")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
