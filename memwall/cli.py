"""memwall command-line interface."""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__, adapters, heuristics
from . import judge as judge_mod
from . import report as report_mod
from .models import ScanResult, Severity


def _strip_dashes(argv) -> list:
    argv = list(argv or [])
    return argv[1:] if argv and argv[0] == "--" else argv


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="memwall",
        description="Scan and guard AI agent memory stores against poisoning and hygiene issues.",
    )
    parser.add_argument("--version", action="version", version=f"memwall {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="scan a memory store, export, file, or directory")
    scan_p.add_argument("path", help="memory file, export, or directory to walk")
    scan_p.add_argument("--format", choices=["auto", "files", "mcp", "mem0", "json"], default="auto")
    scan_p.add_argument("--judge", action="store_true",
                        help="run the Claude judge on flagged records (needs ANTHROPIC_API_KEY)")
    scan_p.add_argument("--judge-all", action="store_true",
                        help="judge every record, not just heuristic hits")
    scan_p.add_argument("--model", default=None, help=f"judge model (default: {judge_mod.DEFAULT_MODEL})")
    scan_p.add_argument("--json", dest="json_out", metavar="PATH", help="write a JSON report")
    scan_p.add_argument("--markdown", dest="md_out", metavar="PATH", help="write a Markdown report")
    scan_p.add_argument("--fail-on", choices=["info", "low", "medium", "high", "critical"], default="high",
                        help="exit 1 if any finding is at or above this severity (CI gate)")
    scan_p.add_argument("--baseline", metavar="PATH",
                        help="baseline file of accepted findings to suppress")
    scan_p.add_argument("--update-baseline", action="store_true",
                        help="write current findings to --baseline and exit 0")
    scan_p.add_argument("-q", "--quiet", action="store_true",
                        help="print only the summary lines")

    sub.add_parser("rules", help="list heuristic rules")

    gw_p = sub.add_parser("gateway", help="run the MCP quarantine gateway in front of a memory server")
    gw_p.add_argument("--state-dir", default=".memwall", help="where to keep the event log and quarantine")
    gw_p.add_argument("--block-at", choices=["low", "medium", "high", "critical"], default="high",
                      help="quarantine writes with findings at or above this severity")
    gw_p.add_argument("--policy", metavar="PATH",
                      help="JSON policy file with per-origin block thresholds (overrides --block-at)")
    gw_p.add_argument("--judge", action="store_true",
                      help="consult the Claude judge before quarantining flagged writes (needs ANTHROPIC_API_KEY)")
    gw_p.add_argument("--model", default=None, help="judge model for --judge")
    gw_p.add_argument("backend", nargs=argparse.REMAINDER,
                      help="backend command after --, e.g.: -- npx -y @modelcontextprotocol/server-memory")

    log_p = sub.add_parser("log", help="show the gateway's forensic event log")
    log_p.add_argument("--state-dir", default=".memwall")
    log_p.add_argument("--tail", type=int, default=20, help="show the last N events")

    q_p = sub.add_parser("quarantine", help="review quarantined memory writes")
    q_p.add_argument("--state-dir", default=".memwall")
    q_sub = q_p.add_subparsers(dest="qcmd", required=True)
    q_sub.add_parser("list", help="list quarantine entries")
    q_show = q_sub.add_parser("show", help="show one entry in full")
    q_show.add_argument("qid")
    q_release = q_sub.add_parser("release", help="replay an approved entry to the backend")
    q_release.add_argument("qid")
    q_release.add_argument("backend", nargs=argparse.REMAINDER,
                           help="backend command after --, same as the gateway wraps")
    q_drop = q_sub.add_parser("drop", help="discard an entry (kept in the audit trail)")
    q_drop.add_argument("qid")

    args = parser.parse_args(argv)

    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(errors="replace")
            except Exception:
                pass

    if args.command == "rules":
        width = max(len(r.name) for r in heuristics.RULES)
        for rule in heuristics.RULES:
            print(f"{rule.id}  {rule.name.ljust(width)}  {rule.severity.name.ljust(8)}  {rule.description}")
        return 0

    if args.command == "scan":
        return _cmd_scan(args)
    if args.command == "gateway":
        return _cmd_gateway(args)
    if args.command == "log":
        return _cmd_log(args)
    if args.command == "quarantine":
        return _cmd_quarantine(args)
    return 0


def _cmd_scan(args) -> int:
    try:
        records = adapters.load(args.path, args.format)
    except FileNotFoundError:
        print(f"memwall: path not found: {args.path}", file=sys.stderr)
        return 2
    if not records:
        print(f"memwall: no memories found at {args.path}")
        return 0

    reports = heuristics.scan_records(records)

    if args.judge or args.judge_all:
        targets = reports if args.judge_all else [r for r in reports if r.findings]
        if targets:
            judge_mod.judge(targets, model=args.model or judge_mod.DEFAULT_MODEL)

    if args.update_baseline and not args.baseline:
        print("memwall: --update-baseline needs --baseline PATH", file=sys.stderr)
        return 2

    suppressed = 0
    if args.baseline:
        from . import baseline as baseline_mod
        if args.update_baseline:
            count = baseline_mod.save_baseline(args.baseline, reports)
            print(f"baseline written: {args.baseline} ({count} fingerprints)")
            return 0
        accepted = baseline_mod.load_baseline(args.baseline)
        for rep in reports:
            kept = [f for f in rep.findings
                    if baseline_mod.fingerprint(rep.record, f) not in accepted]
            suppressed += len(rep.findings) - len(kept)
            rep.findings = kept

    sources = sorted({r.record.source for r in reports})
    result = ScanResult(reports=reports, scanned=len(reports), stores=sources)
    print(report_mod.render_terminal(result, quiet=args.quiet))
    if suppressed:
        print(f"suppressed {suppressed} baselined finding(s)")
    if args.json_out:
        report_mod.write_json(result, args.json_out)
        print(f"json report: {args.json_out}")
    if args.md_out:
        report_mod.write_markdown(result, args.md_out)
        print(f"markdown report: {args.md_out}")

    threshold = Severity[args.fail_on.upper()]
    worst = max((f.severity for rep in reports for f in rep.findings), default=None)
    return 1 if worst is not None and worst >= threshold else 0


def _cmd_gateway(args) -> int:
    from .gateway import Gateway
    from .policy import Policy
    backend = _strip_dashes(args.backend)
    if not backend:
        print("memwall: gateway needs a backend command after --", file=sys.stderr)
        return 2
    if args.policy:
        policy = Policy.from_file(args.policy)
    else:
        policy = Policy(default_block_at=Severity[args.block_at.upper()])
    gateway = Gateway(backend, state_dir=args.state_dir, policy=policy,
                      judge_enabled=args.judge, judge_model=args.model)
    return gateway.run()


def _cmd_log(args) -> int:
    from .state import StateStore
    events = StateStore(args.state_dir).events()
    if not events:
        print("no events")
        return 0
    for event in events[-args.tail:]:
        rules = ",".join(event.get("findings") or []) or "-"
        qid = f"  qid={event['qid']}" if event.get("qid") else ""
        origin = event.get("origin")
        origin = f"  origin={origin}" if origin and origin != "unknown" else ""
        print(f"{event['ts']}  {event['event']:<8} {event['tool']:<24} {rules}{origin}{qid}")
    return 0


def _cmd_quarantine(args) -> int:
    from .state import StateStore
    store = StateStore(args.state_dir)
    entries = {e["qid"]: e for e in store.quarantine_entries()}

    if args.qcmd == "list":
        if not entries:
            print("quarantine is empty")
            return 0
        for entry in sorted(entries.values(), key=lambda e: e["ts"]):
            rules = ",".join(sorted({f["rule"] for f in entry["findings"]}))
            origin = entry.get("origin", "-")
            print(f"{entry['qid']}  {entry['status']:<9} {entry['ts']}  {entry['tool']:<24} {origin:<9} {rules}")
        return 0

    entry = entries.get(args.qid)
    if entry is None:
        print(f"memwall: no quarantine entry {args.qid}", file=sys.stderr)
        return 2

    if args.qcmd == "show":
        print(json.dumps(entry, indent=2, ensure_ascii=False))
        return 0

    if args.qcmd == "drop":
        store.set_status(args.qid, "dropped")
        print(f"dropped {args.qid}")
        return 0

    if args.qcmd == "release":
        from .mcp_client import MiniClient
        backend = _strip_dashes(args.backend)
        if not backend:
            print("memwall: release needs the backend command after --", file=sys.stderr)
            return 2
        params = entry["request"].get("params") or {}
        client = MiniClient(backend)
        try:
            client.initialize()
            client.call_tool(params.get("name", ""), params.get("arguments") or {})
        finally:
            client.close()
        store.set_status(args.qid, "released")
        print(f"released {args.qid} to backend")
        return 0
    return 0


def run() -> None:
    sys.exit(main())
