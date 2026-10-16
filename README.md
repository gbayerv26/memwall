# memwall

![ci](https://github.com/gbayerv26/memwall/actions/workflows/ci.yml/badge.svg)
![python](https://img.shields.io/badge/python-3.9%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)

**Antivirus for AI agent memory.**

Persistent memory is the newest attack surface in agentic AI. One poisoned
memory — planted through an email, a webpage, or a document your agent read —
survives across sessions and fires days or weeks later. OWASP added *Memory
and Context Poisoning* to its 2026 Agentic AI Top 10 (ASI06); published
research shows attack success rates of 80–99% against real agent stacks.

memwall scans agent memory stores for injected standing orders, exfiltration
vectors, hidden payloads, and hygiene issues like retained PII. Zero
dependencies for the core scan.

## Quickstart

```bash
pip install memwall

memwall scan path/to/memory.json          # one store or export
memwall scan .                            # walk a project: CLAUDE.md, AGENTS.md, memory files
memwall scan memory.json --judge          # add the Claude semantic judge (needs ANTHROPIC_API_KEY)
memwall rules                             # list detection rules
```

60-second demo — scan the bundled example store and watch it catch an
invoice-exfiltration implant and a payment redirect:

```bash
git clone https://github.com/gbayerv26/memwall && cd memwall
pip install -e .
memwall scan examples/
```

Directory scans are memory-aware: `package.json`, `tsconfig.json`, and other
non-memory JSON are skipped automatically, as are files over 5 MB.

## Supported stores

- **MCP reference memory server** — `memory.json` / `.jsonl` of entities and observations
- **mem0-style exports** — JSON lists of memory objects
- **SQLite-backed stores** — Letta, mem0 history, custom agent DBs: every text
  cell in every table, auto-detected by file magic, opened read-only
- **Agent instruction files** — `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursorrules`, `.mdc`
- **Notes / markdown memory files** and generic JSON dumps

## How it works

**Pass 1 — heuristics (free, instant).** Rules MW001–MW016 catch the known
shapes of memory poisoning: instruction overrides, secrecy pressure
("don't tell the user"), authority claims ("system note:", "developer mode"),
payment redirection, crypto wallets, encoded payloads, zero-width/bidi hidden
characters, chat-role smuggling (`<|im_start|>`), rendering beacons (remote
markdown images), delayed triggers ("when the user asks about X..." — the
signature of implants that fire later), and PII that needs an expiry policy.
A combo rule (MW000) escalates to CRITICAL when a standing order and an
outbound destination appear in the same memory — the classic exfiltration
shape.

Instruction files get a calibrated ruleset: imperatives are normal in a
CLAUDE.md, so only the genuinely suspicious rules apply there.

**Pass 2 — the judge (optional).** `--judge` sends flagged records to Claude
for semantic classification (`benign_fact` / `preference` / `task_context` /
`suspicious_instruction` / `likely_injection`). The judge treats memory
content as untrusted data and never follows instructions inside it.

```bash
pip install "memwall[judge]"
export ANTHROPIC_API_KEY=sk-ant-...
memwall scan memory.json --judge
```

## Offline behavioral memory trials

Some memories are ordinary-looking but obsolete or harmful in a particular task.
Use an offline trial bundle to compare the same task with and without one exact
memory operation, plus a repeated baseline to expose variability:

```bash
memwall trial prepare manifest.json --out bundle.json
# A trusted external evaluator runs the agents and exports traces separately.
memwall trial report bundle.json results.json --manifest manifest.json --out report.json
```

The report checks full input/trace digests, model settings, complete paired runs,
identical task inputs and starting environments. It separates task success,
unsafe actions, obsolete assumptions and preferences, and rejects stale evidence.
It never changes gateway decisions or releases quarantine. These two commands
make **no model calls and incur no model API charges**. Actual agent evaluation
needs an external runner and may incur charges.

Try the free deterministic simulation from a source checkout:

```bash
python -m examples.trials.run_demo --out trial-demo
```

The simulation measures no AI agent. Imported real results are trusted runner
assertions, not authenticated execution or a safety guarantee. See the
[trial format, workflow and limitations](docs/TRIALS.md).

## CI gate

```bash
memwall scan ./agent-memory --fail-on high --json memwall-report.json
```

Exit code is 1 when any finding meets the `--fail-on` threshold, so you can
block deploys on a poisoned store.

Accepted findings can be baselined so CI only fails on **new** ones — a
baselined finding stays suppressed until the memory content itself changes:

```bash
memwall scan ./agent-memory --baseline .memwall-baseline.json --update-baseline  # accept current state
memwall scan ./agent-memory --baseline .memwall-baseline.json --fail-on high -q  # gate on new findings
```

## The gateway — quarantine before commit

`memwall gateway` is a transparent MCP proxy you put in front of any stdio
memory server. Every memory write is scanned *before* it reaches the store;
anything at or above the block threshold is quarantined instead of written,
and the agent gets a clear "blocked, do not retry" tool response. Reads and
all other traffic pass through untouched.

```bash
memwall gateway --state-dir ~/.memwall -- npx -y @modelcontextprotocol/server-memory
```

Claude Desktop / Claude Code config — wrap your existing memory server:

```json
{
  "mcpServers": {
    "memory": {
      "command": "memwall",
      "args": ["gateway", "--state-dir", "/home/you/.memwall", "--",
               "npx", "-y", "@modelcontextprotocol/server-memory"]
    }
  }
}
```

Writes (tool names matching create/add/store/save/write/update/remember/...)
are scanned with the same rule engine as `memwall scan`. The gateway fails
open on internal errors and keeps protocol traffic on stdout and diagnostics
on stderr, so it never takes your memory server down.

### Contract enforcement

Use a local backend profile to enforce an explicit inspection boundary:

```bash
memwall gateway --profile reference-memory --state-dir ~/.memwall -- npx -y @modelcontextprotocol/server-memory@1.0.0
```

With `--profile`, exact tool roles replace name guessing. The bundled
`reference-memory` profile covers entity creation, observation insertion,
relation creation, graph reads/searches, and deletions. Unknown tools and
unsupported argument shapes are refused before reaching the backend.
Additional fields in write arguments are refused rather than silently skipped.

Related fields and repeated entries for the same entity within one call are
inspected together. An instruction and destination split across observations
can therefore trigger the existing combination rule. Distinct entities remain
separate. If any group blocks, the entire call is quarantined; batches are
never partially forwarded. Quarantine entries include the original request
and inspected JSON field paths.

The operator's configured threshold is the minimum protection. Caller-declared
origins may tighten it, but cannot relax it: claiming `origin=user` cannot
clear a write already blocked by the operator threshold. Origin metadata is
still a claim, not authenticated provenance.

Inspection, validation, and state-write failures refuse the request. If state
is unavailable, the gateway returns an error without claiming the content was
quarantined. Requests are limited to 1 MiB per wire frame and 32 nesting levels.
Duplicate object keys and non-finite JSON numbers are refused. Oversized frames
are drained in bounded chunks so subsequent requests can be handled.

In this mode `--judge` is **advisory**: it can explain findings but cannot
override a block. Normal allowed traffic makes no judge API calls. Existing
gateway behavior, including judge clearing and scan fail-open, remains available
when no profile is selected.

For a custom backend, provide an operator-owned JSON file. This example maps a
custom writer to the supported observation shape and declares a reader:

```json
{
  "version": 1,
  "name": "custom-memory",
  "tools": {
    "commit_memory": "observations",
    "preset_lookup": "read"
  }
}
```

```bash
memwall gateway --profile ./memory-profile.json -- your-memory-server
```

A file replaces the entire tool map. Supported extractors are `entities`,
`observations`, and `relations`, using the reference server's respective
argument shapes. `read` and `maintenance` explicitly trust the backend not to
insert new memory through those tools; custom shapes for these roles are the
operator's responsibility. Keep profiles local and trusted. Tool descriptions,
annotations, and request metadata cannot grant a tool an exemption.

Contract enforcement strengthens inspection coverage; it does not make regex
detection complete. Malicious paraphrases may pass and benign quotations may
be quarantined. Correlation covers a single request. Direct writes to the
memory file or alternate backend connections bypass the gateway. An `allowed`
audit event records authorization, not confirmation of durable storage.

Review what happened — every write is recorded in an append-only audit trail
with a payload hash, so you can answer "when did this belief enter memory":

```bash
memwall log --state-dir ~/.memwall                # forensic event log
memwall quarantine --state-dir ~/.memwall list    # held writes
memwall quarantine --state-dir ~/.memwall show q1a2b3c4
memwall quarantine --state-dir ~/.memwall release q1a2b3c4 -- npx -y @modelcontextprotocol/server-memory
memwall quarantine --state-dir ~/.memwall drop q1a2b3c4
```

`release` replays the original write to the backend after human review;
`drop` discards it. Both decisions are appended to the audit trail, never
rewritten over it.

Release requires a pending entry and reports backend tool errors as failures.
On failure the entry remains pending. Verify backend state before retrying a
failed release, since a backend can fail after making partial changes.
Run releases serially: the pending-status check is not an atomic lock across
concurrent release processes and does not guarantee exactly-once replay.

## Monitoring — catch poison the moment it lands

`memwall watch` re-scans a store on an interval and alerts **only on new
findings** — the first run establishes a snapshot, every later run reports
what appeared since:

```bash
memwall watch ./agent-memory --interval 300          # continuous, every 5 min
memwall watch ./agent-memory --once --fail-on-new    # one delta check (cron / CI)
```

`--once --fail-on-new` exits 1 when something new appeared, so a cron job,
scheduled CI run, or systemd timer becomes a poisoning alarm with one line.

## Compliance

**Right to be forgotten (GDPR Art. 17).** Erasure quietly fails in summarized
agent memory — a name survives inside a paraphrase after the source row was
deleted. `forget-check` checks whether supplied literal identifiers remain
(case-insensitive); it cannot prove paraphrase or semantic erasure:

```bash
memwall forget-check ./agent-memory --subject "alice@corp.com" --subject "Alice Smith" --json proof.json
```

Exit 0 when identifiers are absent; exit 1 with every remaining literal
reference. Add `--json` to save the result as a report.

**Standard exports.** `memwall scan --sarif report.sarif` emits SARIF 2.1.0
for GitHub code scanning and security dashboards; `--html report.html` writes
a self-contained, dark-mode-aware report you can attach to a compliance
ticket or email to a client.

## Trust-aware policies — the provenance handshake

Agents (or their harnesses) can declare where memory content came from by
attaching MCP metadata to the write call:

```json
{"method": "tools/call",
 "params": {"name": "add_observations",
            "_meta": {"memwall": {"origin": "web"}},
            "arguments": {"...": "..."}}}
```

Each origin maps to a block threshold — content from the open web is held to
a stricter bar than something the user typed:

| origin | blocks at |
|---|---|
| `user` | critical |
| `agent` | high |
| `tool` / `web` / `email` / `document` | medium |
| undeclared | `--block-at` (default high) |

Override with a preset — `--policy strict`, `--policy balanced`, or
`--policy permissive` — or a JSON file:

```json
{"default_block_at": "high", "origins": {"web": "low", "voicemail": "low"}}
```

Unlisted origins keep the built-in table. The declared origin is recorded on
every event and quarantine entry, so the audit trail carries provenance. The
`memwall` meta key is stripped before the call reaches the backend.

## Judge-in-the-loop

```bash
memwall gateway --judge -- npx -y @modelcontextprotocol/server-memory
```

Without a profile, `--judge` gives flagged writes a second opinion from the Claude judge
before quarantining. Clearing verdicts (fact / preference / task context) let
the write through — cutting heuristic false positives without losing the
block on real injections. If the judge is unavailable or unsure, the write
stays quarantined (fail-safe). Needs `pip install "memwall[judge]"` and
`ANTHROPIC_API_KEY`; adds one API call only to writes heuristics already
flagged, so normal traffic pays zero latency.

## Roadmap

- **Hosted memwall.** The `watch` engine as a managed service: fleet
  dashboard, alert routing (Slack/email), and scheduled compliance reports.
  Interested? Open an issue titled "hosted waitlist".
- More stores: Zep, Letta, LangGraph checkpoints, vector DBs.
- Policy packs: shareable, versioned policies per industry / risk appetite.

## Honest limitations

Heuristics have false positives and false negatives by design — they are a
triage layer, not a verdict. Review findings before deleting memories. The
judge pass improves precision but is only as good as the model behind it.

## License

MIT
