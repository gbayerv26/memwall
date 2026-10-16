"""memwall command-line interface."""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__, adapters, heuristics
from . import judge as judge_mod
from . import report as report_mod
from .models import ScanResult, Severity


def _positive_int(value):
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


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
    scan_p.add_argument("--format", choices=["auto", "files", "mcp", "mem0", "json", "sqlite"], default="auto")
    scan_p.add_argument("--judge", action="store_true",
                        help="run the Claude judge on flagged records (needs ANTHROPIC_API_KEY)")
    scan_p.add_argument("--judge-all", action="store_true",
                        help="judge every record, not just heuristic hits")
    scan_p.add_argument("--model", default=None, help=f"judge model (default: {judge_mod.DEFAULT_MODEL})")
    scan_p.add_argument("--json", dest="json_out", metavar="PATH", help="write a JSON report")
    scan_p.add_argument("--markdown", dest="md_out", metavar="PATH", help="write a Markdown report")
    scan_p.add_argument("--sarif", dest="sarif_out", metavar="PATH",
                        help="write a SARIF report (GitHub code scanning / dashboards)")
    scan_p.add_argument("--html", dest="html_out", metavar="PATH",
                        help="write a standalone HTML report")
    scan_p.add_argument("--fail-on", choices=["info", "low", "medium", "high", "critical"], default="high",
                        help="exit 1 if any finding is at or above this severity (CI gate)")
    scan_p.add_argument("--baseline", metavar="PATH",
                        help="baseline file of accepted findings to suppress")
    scan_p.add_argument("--update-baseline", action="store_true",
                        help="write current findings to --baseline and exit 0")
    scan_p.add_argument("-q", "--quiet", action="store_true",
                        help="print only the summary lines")

    sub.add_parser("rules", help="list heuristic rules")

    watch_p = sub.add_parser("watch", help="continuously monitor a store and alert on NEW findings")
    watch_p.add_argument("path", help="memory file, export, or directory to monitor")
    watch_p.add_argument("--format", choices=["auto", "files", "mcp", "mem0", "json", "sqlite"], default="auto")
    watch_p.add_argument("--state-dir", default=".memwall", help="where to keep the monitoring snapshot")
    watch_p.add_argument("--interval", type=_positive_int, default=60, help="seconds between scans")
    watch_p.add_argument("--once", action="store_true", help="run a single delta check and exit")
    watch_p.add_argument("--fail-on-new", action="store_true",
                         help="with --once, exit 1 if any new finding appeared")

    forget_p = sub.add_parser("forget-check",
                              help="GDPR: find memories that still reference a subject (right to be forgotten)")
    forget_p.add_argument("path", help="memory file, export, or directory to check")
    forget_p.add_argument("--subject", action="append", default=[], metavar="ID",
                          help="identifier to search for (email, name, id); repeatable")
    forget_p.add_argument("--format", choices=["auto", "files", "mcp", "mem0", "json", "sqlite"], default="auto")
    forget_p.add_argument("--json", dest="json_out", metavar="PATH", help="write a JSON report")

    gw_p = sub.add_parser("gateway", help="run the MCP quarantine gateway in front of a memory server")
    gw_p.add_argument("--state-dir", default=".memwall", help="where to keep the event log and quarantine")
    gw_p.add_argument("--block-at", choices=["low", "medium", "high", "critical"], default="high",
                      help="quarantine writes with findings at or above this severity")
    gw_p.add_argument("--policy", metavar="NAME_OR_PATH",
                      help="preset (strict/balanced/permissive) or JSON policy file with "
                           "per-origin block thresholds (overrides --block-at)")
    gw_p.add_argument("--profile", metavar="NAME_OR_PATH",
                      help="enforce a local memory-write contract (reference-memory or a JSON profile); "
                           "unknown tools and inspection failures are refused, judge is advisory")
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

    trial_p = sub.add_parser("trial", help="prepare and report offline memory trials (no model calls)")
    trial_sub = trial_p.add_subparsers(dest="trialcmd", required=True)
    trial_prepare = trial_sub.add_parser("prepare", help="capture a candidate and pinned trial inputs")
    trial_prepare.add_argument("manifest", help="version 1 local trial manifest")
    trial_prepare.add_argument("--out", required=True, help="new bundle JSON path")
    trial_report = trial_sub.add_parser("report", help="validate external paired-run evidence")
    trial_report.add_argument("bundle")
    trial_report.add_argument("results")
    trial_report.add_argument("--manifest", required=True, help="current manifest and files to check for drift")
    trial_report.add_argument("--out", required=True, help="new report JSON path")

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
    if args.command == "watch":
        return _cmd_watch(args)
    if args.command == "forget-check":
        return _cmd_forget(args)
    if args.command == "gateway":
        return _cmd_gateway(args)
    if args.command == "log":
        return _cmd_log(args)
    if args.command == "quarantine":
        return _cmd_quarantine(args)
    if args.command == "trial":
        return _cmd_trial(args)
    return 0


def _cmd_trial(args) -> int:
    from . import trials
    try:
        if args.trialcmd == "prepare":
            value = trials.prepare(args.manifest, args.out)
            print(f"Offline trial bundle: {value['bundle_id']}\nWritten: {args.out}")
        else:
            value = trials.report(args.bundle, args.results, args.manifest, args.out)
            print(value["warning"])
            for case in value["cases"]:
                print(f"{case['id']}: {case['effect']} "
                      f"(baseline disagreements: {case['baseline_disagreements']}; "
                      f"candidate unsafe actions: {case['counts']['candidate']['unsafe_action']})")
            print(f"Written: {args.out}. Quarantine unchanged.")
        return 0
    except (trials.TrialError, OSError, ValueError) as exc:
        print(f"memwall trial: {exc}", file=sys.stderr)
        return 2


def _cmd_scan(args) -> int:
    try:
        records = adapters.load(args.path, args.format)
    except FileNotFoundError:
        print(f"memwall: path not found: {args.path}", file=sys.stderr)
        return 2
    if not records:
        print(f"memwall: no memories found at {args.path}")

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
    if args.sarif_out:
        from . import export as export_mod
        export_mod.write_sarif(result, args.sarif_out)
        print(f"sarif report: {args.sarif_out}")
    if args.html_out:
        from . import export as export_mod
        export_mod.write_html(result, args.html_out)
        print(f"html report: {args.html_out}")

    threshold = Severity[args.fail_on.upper()]
    worst = max((f.severity for rep in reports for f in rep.findings), default=None)
    return 1 if worst is not None and worst >= threshold else 0


def _print_tick(tick) -> None:
    from .report import _clean
    if tick.is_baseline:
        print(f"baseline established: {tick.total_findings} finding(s) across {tick.scanned} memories")
        return
    if not tick.new_items:
        print(f"no new findings ({tick.total_findings} known, {tick.scanned} memories)")
        return
    total_new = sum(len(fs) for _, fs in tick.new_items)
    print(f"ALERT: {total_new} NEW finding(s) in {len(tick.new_items)} memor(ies):")
    for record, fresh in tick.new_items:
        worst = max(f.severity for f in fresh)
        print(f"  [{worst.name}] {record.id} ({record.store}: {record.source})")
        print(f'    "{_clean(record.content)}"')
        for f in sorted(fresh, key=lambda f: f.severity, reverse=True):
            print(f"    - {f.rule_id} {f.rule_name} ({f.severity.name}): {f.message}")


def _cmd_watch(args) -> int:
    from . import monitor
    if args.fail_on_new and not args.once:
        print("memwall: --fail-on-new requires --once", file=sys.stderr)
        return 2
    try:
        if args.once:
            tick = monitor.run_once(args.path, args.state_dir, args.format)
            _print_tick(tick)
            if args.fail_on_new and tick.new_items:
                return 1
            return 0
        print(f"memwall watch: monitoring {args.path} every {args.interval}s "
              f"(state={args.state_dir}); Ctrl-C to stop")
        monitor.watch(args.path, args.state_dir, args.interval, args.format, on_tick=_print_tick)
    except FileNotFoundError:
        print(f"memwall: path not found: {args.path}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nstopped")
    return 0


def _cmd_forget(args) -> int:
    from . import forget
    normalized_subjects = [s.strip() for s in args.subject if s.strip()]
    if not normalized_subjects:
        print("memwall: forget-check needs at least one --subject", file=sys.stderr)
        return 2
    try:
        hits = forget.scan_path(args.path, normalized_subjects, args.format)
    except FileNotFoundError:
        print(f"memwall: path not found: {args.path}", file=sys.stderr)
        return 2

    subjects = ", ".join(normalized_subjects)
    if not hits:
        print(f"erased: no memory references {subjects}")
    else:
        from .report import _clean
        print(f"NOT erased: {len(hits)} memor(ies) still reference {subjects}:")
        for hit in hits:
            print(f"  {hit.record.id} ({hit.record.store}: {hit.record.source}) "
                  f"-> matched {', '.join(hit.matched)}")
            print(f'    "{_clean(hit.record.content)}"')

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump({
                "subjects": normalized_subjects,
                "erased": not hits,
                "matches": [
                    {"id": h.record.id, "source": h.record.source, "store": h.record.store,
                     "matched": h.matched, "content": h.record.content}
                    for h in hits
                ],
            }, fh, indent=2, ensure_ascii=False)
        print(f"json report: {args.json_out}")

    return 1 if hits else 0


def _cmd_gateway(args) -> int:
    from .gateway import Gateway
    from .policy import Policy
    backend = _strip_dashes(args.backend)
    if not backend:
        print("memwall: gateway needs a backend command after --", file=sys.stderr)
        return 2
    try:
        profile = None
        if args.profile:
            from .contracts import load_profile
            profile = load_profile(args.profile)
        if args.policy:
            from .policy import resolve
            policy = resolve(args.policy)
        else:
            policy = Policy(default_block_at=Severity[args.block_at.upper()])
        gateway = Gateway(backend, state_dir=args.state_dir, policy=policy,
                          judge_enabled=args.judge, judge_model=args.model, profile=profile)
        return gateway.run()
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        print(f"memwall: gateway configuration or backend failed: {exc}", file=sys.stderr)
        return 2


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
        if entry["status"] != "pending":
            print(f"memwall: cannot release a {entry['status']} entry", file=sys.stderr)
            return 2
        params = entry["request"].get("params") or {}
        client = None
        try:
            client = MiniClient(backend)
            client.initialize()
            result = client.call_tool(params.get("name", ""), params.get("arguments") or {})
            if (not isinstance(result, dict) or not isinstance(result.get("content"), list)
                    or ("isError" in result and type(result["isError"]) is not bool)
                    or result.get("isError")):
                raise RuntimeError("backend did not accept the released write")
        except (OSError, RuntimeError) as exc:
            print(f"memwall: release failed: {exc}; entry remains pending, "
                  "verify backend state before retrying", file=sys.stderr)
            return 1
        finally:
            if client is not None:
                client.close()
        store.set_status(args.qid, "released")
        print(f"released {args.qid} to backend")
        return 0
    return 0


def run() -> None:
    sys.exit(main())
