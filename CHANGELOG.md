# Changelog

## 0.6.1 — 2026-07-21

- Isolated monitor snapshots by target, recovered safely from invalid state,
  and detected new records even when their poisoned content is duplicated
- Enforced read-only SQLite access, safely quoted table names, and discovered
  SQLite stores by file signature regardless of extension or size
- Fixed empty scan exports/baseline updates and corrected SARIF location
  structure plus cross-platform URI encoding
- Normalized `forget-check` subjects, clarified its literal-match guarantee,
  and rejected invalid `watch` option combinations

## 0.6.0 — 2026-07-21

- `memwall watch`: continuous monitoring with delta detection — first run
  snapshots the store, later runs alert only on NEW findings; `--once
  --fail-on-new` turns any cron/CI job into a poisoning alarm
- `memwall forget-check`: GDPR right-to-be-forgotten verification — proves
  whether a subject (email, name, id) still appears anywhere in agent
  memory, with a JSON proof artifact
- SARIF 2.1.0 export (`scan --sarif`) for GitHub code scanning and security
  dashboards; self-contained HTML report (`scan --html`)

## 0.5.0 — 2026-07-21

- SQLite adapter: scans every text cell of Letta / mem0-history / custom
  agent databases, auto-detected by file magic, opened read-only
- Three new rules: MW014 role-marker smuggling (`<|im_start|>`, `[INST]`),
  MW015 rendering beacons (remote markdown/HTML images), MW016 delayed
  triggers ("when the user asks about X...") — the fire-later implant
  signature, wired into the MW000 combo escalation
- Gateway policy presets: `--policy strict|balanced|permissive`

## 0.4.0 — 2026-07-14

- Baseline files: `--baseline` / `--update-baseline` suppress accepted
  findings so CI only fails on new ones
- `--quiet` scan output for CI logs; JSON reports embed `memwall_version`
- Smarter directory walks: non-memory `.json` (package.json, tsconfig.json,
  ...) is skipped, files over 5 MB are skipped with a note
- GitHub Actions CI (Linux + Windows, Python 3.9 and 3.13), SECURITY.md,
  CONTRIBUTING.md, bundled `examples/` store

## 0.3.0 — 2026-07-14

- Provenance handshake: agents declare content origin via
  `params._meta.memwall.origin`; per-origin block thresholds (`--policy`),
  origin recorded in the audit trail
- Judge-in-the-loop: `gateway --judge` consults the Claude judge before
  quarantining; clearing verdicts allow the write, judge failure keeps the
  block (fail-safe)

## 0.2.0 — 2026-07-14

- MCP quarantine gateway: transparent stdio proxy, writes scanned before
  commit, append-only forensic event log and quarantine store
- Review workflow: `memwall log`, `memwall quarantine list|show|release|drop`
  (release replays the original write via a minimal MCP client)

## 0.1.0 — 2026-07-14

- Scanner with 13 heuristic rules (MW001–MW013) plus the MW000
  instruction-plus-destination escalation
- Adapters: MCP reference memory server, mem0 exports, instruction files
  (CLAUDE.md, AGENTS.md, .cursorrules), generic JSON
- Optional Claude judge pass, JSON/Markdown reports, CI exit-code gate
