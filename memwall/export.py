"""Export scan results to standard formats: SARIF and a standalone HTML report."""
from __future__ import annotations

import html
import json

from . import __version__
from .heuristics import RULES
from .models import ScanResult, Severity

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# Synthetic rules the engine emits that are not in the RULES table.
_EXTRA_RULES = [
    ("MW000", "instruction-plus-destination",
     "Standing order combined with an outbound destination (exfiltration shape).", Severity.CRITICAL),
    ("MW-J", "judge", "Flagged by the Claude semantic judge.", Severity.HIGH),
]


def to_sarif(result: ScanResult) -> dict:
    rules, index = [], {}
    for rule in RULES:
        index[rule.id] = len(rules)
        rules.append({
            "id": rule.id,
            "name": rule.name,
            "shortDescription": {"text": rule.description},
            "defaultConfiguration": {"level": _SARIF_LEVEL[rule.severity]},
        })
    for rid, name, desc, sev in _EXTRA_RULES:
        index[rid] = len(rules)
        rules.append({
            "id": rid, "name": name,
            "shortDescription": {"text": desc},
            "defaultConfiguration": {"level": _SARIF_LEVEL[sev]},
        })

    results = []
    for rep in result.reports:
        for f in rep.findings:
            entry = {
                "ruleId": f.rule_id,
                "level": _SARIF_LEVEL[f.severity],
                "message": {"text": f"[{rep.record.id}] {f.rule_name}: {f.message}"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": _uri(rep.record.source)},
                    "logicalLocations": [{"name": rep.record.id}],
                }}],
            }
            if f.rule_id in index:
                entry["ruleIndex"] = index[f.rule_id]
            results.append(entry)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "memwall",
                "version": __version__,
                "informationUri": "https://github.com/gbayerv26/memwall",
                "rules": rules,
            }},
            "results": results,
        }],
    }


def _uri(source: str) -> str:
    return source.replace("\\", "/")


def write_sarif(result: ScanResult, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(to_sarif(result), fh, indent=2)


_SEV_COLOR = {
    "CRITICAL": "#7c1fa0", "HIGH": "#c0392b", "MEDIUM": "#b8860b",
    "LOW": "#2980b9", "INFO": "#7f8c8d",
}


def write_html(result: ScanResult, path: str) -> None:
    flagged = sorted(result.flagged, key=lambda r: r.max_severity, reverse=True)
    counts = {}
    for rep in flagged:
        counts[rep.max_severity.name] = counts.get(rep.max_severity.name, 0) + 1

    chips = "".join(
        f'<span class="chip" style="background:{_SEV_COLOR[s]}">{counts[s]} {s.lower()}</span>'
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") if s in counts
    ) or '<span class="chip" style="background:#27ae60">clean</span>'

    rows = []
    for rep in flagged:
        sev = rep.max_severity.name
        findings = "".join(
            f'<li><code>{f.rule_id}</code> {html.escape(f.rule_name)} '
            f'<em>({f.severity.name})</em> — {html.escape(f.message)}</li>'
            for f in sorted(rep.findings, key=lambda f: f.severity, reverse=True)
        )
        rows.append(f"""
    <div class="card" style="border-left-color:{_SEV_COLOR[sev]}">
      <div class="cardhead">
        <span class="sev" style="color:{_SEV_COLOR[sev]}">{sev}</span>
        <span class="rid">{html.escape(rep.record.id)}</span>
        <span class="src">{html.escape(rep.record.store)}: {html.escape(rep.record.source)}</span>
      </div>
      <blockquote>{html.escape(rep.record.content[:600])}</blockquote>
      <ul>{findings}</ul>
    </div>""")

    doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>memwall report</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; padding: 2rem;
          background: Canvas; color: CanvasText; line-height: 1.5; }}
  h1 {{ margin: 0 0 .25rem; font-size: 1.5rem; }}
  .meta {{ opacity: .7; font-size: .9rem; margin-bottom: 1rem; }}
  .chip {{ color: #fff; padding: .15rem .6rem; border-radius: 1rem; font-size: .8rem;
           margin-right: .4rem; white-space: nowrap; }}
  .card {{ border: 1px solid #8884; border-left-width: 5px; border-radius: 6px;
           padding: .75rem 1rem; margin: 1rem 0; overflow-x: auto; }}
  .cardhead {{ display: flex; gap: .75rem; align-items: baseline; flex-wrap: wrap; }}
  .sev {{ font-weight: 700; }}
  .rid {{ font-family: ui-monospace, monospace; font-size: .85rem; }}
  .src {{ opacity: .6; font-size: .8rem; }}
  blockquote {{ margin: .5rem 0; padding: .5rem .75rem; background: #8881; border-radius: 4px;
                font-family: ui-monospace, monospace; font-size: .85rem; white-space: pre-wrap;
                word-break: break-word; }}
  ul {{ margin: .25rem 0 0; padding-left: 1.2rem; }}
  li {{ font-size: .9rem; }}
  code {{ font-family: ui-monospace, monospace; }}
  footer {{ margin-top: 2rem; opacity: .6; font-size: .8rem; }}
</style></head><body>
  <h1>memwall report</h1>
  <div class="meta">scanned {result.scanned} memories from {len(result.stores)} source(s) ·
    flagged {len(flagged)}</div>
  <div>{chips}</div>
  {''.join(rows)}
  <footer>memwall {__version__} · https://github.com/gbayerv26/memwall</footer>
</body></html>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)
