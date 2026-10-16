# memwall

![ci](https://github.com/gbayerv26/memwall/actions/workflows/ci.yml/badge.svg)
![python](https://img.shields.io/badge/python-3.9%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)

**Inspect and guard persistent AI agent memory.**

An injected instruction can survive in an agent's memory and influence later
tasks. An ordinary fact can also become obsolete. Memwall scans stored memory,
guards declared MCP memory writes, and prepares offline trials to investigate
whether one proposed memory helps or harms a particular task.

The core uses Python's standard library. Default scans and offline trial commands
make no model calls. The optional Claude judge and externally run agent trials
can incur provider charges. Memwall is a triage and enforcement layer with a
defined boundary, not a guarantee that a memory is safe.

## What's new in 0.7.1

- **Faster delimiter inspection:** MW013 HTML-comment and MW015 Markdown/HTML
  image detection use forward-only scans. Repeated unclosed delimiters no
  longer cause these detectors to repeatedly search the remaining input.
- **Preserved detection behavior:** match selection, matched text, finding
  snippets, severities, Unicode case handling, and MW000 escalation are retained.
- **Stronger regression coverage:** bounded exhaustive delimiter comparisons,
  near-1 MiB gateway requests, and matcher-exception recovery verify detection
  behavior, whole-call quarantine, and subsequent-request handling.

This addresses the two detectors' quadratic scanning paths. It does not add a
runtime inspection timeout or change gateway policy.

### Introduced in 0.7.0

- **Explicit write contracts:** `gateway --profile reference-memory` inspects
  related fields together, refuses unsupported calls and inspection failures,
  and prevents claimed origins from weakening the operator's threshold.
- **Offline behavioral trials:** `trial prepare` binds exact memory, task and
  environment inputs; `trial report` validates external evidence and separates
  useful effects, harm, obsolete assumptions and baseline variability.
- **Reliable release reporting:** rejected backend writes remain pending;
  released or dropped entries cannot be replayed through the release command.

See the [changelog](CHANGELOG.md) and [trial guide](docs/TRIALS.md).

## Quickstart

Install this checkout for version 0.7.1:

```bash
git clone https://github.com/gbayerv26/memwall
cd memwall
python -m pip install -e .

memwall scan path/to/memory.json          # one store or export
memwall scan .                            # walk a project: CLAUDE.md, AGENTS.md, memory files
memwall rules                             # list detection rules
```

`python -m pip install memwall` installs the latest version published on PyPI,
which can differ from this checkout. Python 3.9 or newer is required. The MCP
reference backend example also requires Node.js and npm.

Scan the bundled example store to inspect an invoice-exfiltration implant and
a payment redirect:

```bash
memwall scan examples/
```

The example intentionally contains malicious memories, so a nonzero scan exit
code is expected when findings meet the configured threshold.

Directory scans are memory-aware: `package.json`, `tsconfig.json`, and other
non-memory JSON are skipped automatically, as are files over 5 MB.

## Supported stores

- **MCP reference memory server:** `memory.json` / `.jsonl` of entities and observations
- **mem0-style exports:** JSON lists of memory objects
- **SQLite-backed stores:** Letta, mem0 history, custom agent DBs: every text
  cell in every table, auto-detected by file magic, opened read-only
- **Agent instruction files:** `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursorrules`, `.mdc`
- **Notes / markdown memory files** and generic JSON dumps

## How it works

**Pass 1: local heuristics.** Rules MW001-MW016 flag known
shapes of memory poisoning: instruction overrides, secrecy pressure
("don't tell the user"), authority claims ("system note:", "developer mode"),
payment redirection, crypto wallets, encoded payloads, zero-width/bidi hidden
characters, chat-role smuggling (`<|im_start|>`), rendering beacons (remote
markdown images), delayed triggers ("when the user asks about X...", the
signature of implants that fire later), and PII that needs an expiry policy.
A combo rule (MW000) escalates to CRITICAL when a standing order and an
outbound destination appear in the same memory, the classic exfiltration
shape.

Instruction files get a calibrated ruleset: imperatives are normal in a
CLAUDE.md, so only the genuinely suspicious rules apply there.

**Pass 2: the optional judge.** `--judge` sends flagged records to Claude
for semantic classification (`benign_fact` / `preference` / `task_context` /
`suspicious_instruction` / `likely_injection`). Its prompt treats memory
content as untrusted data, but its verdict can be wrong. This sends memory
content to the configured provider and can incur API charges.

```bash
python -m pip install ".[judge]"
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

Accepted findings can be baselined so CI only fails on **new** ones: a
baselined finding stays suppressed until the memory content itself changes:

```bash
memwall scan ./agent-memory --baseline .memwall-baseline.json --update-baseline  # accept current state
memwall scan ./agent-memory --baseline .memwall-baseline.json --fail-on high -q  # gate on new findings
```

## The gateway: quarantine before storage

`memwall gateway` is a stdio MCP proxy in front of a memory server. A trusted
local profile declares which tools write memory and how to inspect their
arguments. Declared writes are scanned before forwarding; blocking findings
quarantine the entire call and return a tool error to the agent. Declared
reads and maintenance calls pass through after protocol validation. Unknown
tools and unsupported shapes are refused.

```bash
memwall gateway --profile reference-memory --state-dir ~/.memwall -- npx -y @modelcontextprotocol/server-memory@1.0.0
```

Claude Desktop / Claude Code config, using the bundled reference profile:

```json
{
  "mcpServers": {
    "memory": {
      "command": "memwall",
      "args": ["gateway", "--profile", "reference-memory",
               "--state-dir", "/home/you/.memwall", "--",
               "npx", "-y", "@modelcontextprotocol/server-memory@1.0.0"]
    }
  }
}
```

Use paths and executable names appropriate to your host. Other backends need
a profile matching their exact tool schemas. Protocol traffic uses stdout;
diagnostics use stderr.

Omitting `--profile` retains legacy compatibility: write detection guesses from
tool names such as create/add/store/save/write/update/remember. It can miss
custom writers and fails open on internal scan errors. Use an explicit profile
when inspection failures must refuse forwarding.

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

Review recognized write decisions and quarantined calls in the append-only
audit trail. Its payload hashes identify inspected content; they do not prove
when or whether the backend stored it:

```bash
memwall log --state-dir ~/.memwall                # forensic event log
memwall quarantine --state-dir ~/.memwall list    # held writes
memwall quarantine --state-dir ~/.memwall show q1a2b3c4
memwall quarantine --state-dir ~/.memwall release q1a2b3c4 -- npx -y @modelcontextprotocol/server-memory@1.0.0
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

## Monitoring: alert on new findings

`memwall watch` re-scans a store on an interval and alerts **only on new
findings**: the first run establishes a snapshot, every later run reports
what appeared since:

```bash
memwall watch ./agent-memory --interval 300          # continuous, every 5 min
memwall watch ./agent-memory --once --fail-on-new    # one delta check (cron / CI)
```

`--once --fail-on-new` exits 1 when something new appeared, so a cron job,
scheduled CI run, or systemd timer becomes a poisoning alarm with one line.

## Compliance

**Right to be forgotten (GDPR Art. 17).** Erasure quietly fails in summarized
agent memory: a name survives inside a paraphrase after the source row was
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

## Origin policies

Agents (or their harnesses) can declare where memory content came from by
attaching MCP metadata to the write call:

```json
{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
 "params": {"name": "create_entities",
            "_meta": {"memwall": {"origin": "web"}},
            "arguments": {"entities": [
              {"name": "reporting", "entityType": "preference",
               "observations": ["The user prefers concise reports."]}
            ]}}}
```

Built-in origins map to these thresholds. In profile mode, the effective
threshold is the stricter of this mapping and the operator's default. With
the default `high` threshold, claiming `origin=user` therefore still blocks
high-severity findings:

| origin | blocks at |
|---|---|
| `user` | critical |
| `agent` | high |
| `tool` / `web` / `email` / `document` | medium |
| undeclared | `--block-at` (default high) |

Override with a preset (`--policy strict`, `--policy balanced`, or
`--policy permissive`) or a JSON file:

```json
{"default_block_at": "high", "origins": {"web": "low", "voicemail": "low"}}
```

Origins absent from a custom policy retain their built-in thresholds;
unrecognized origins use the default. Origins are caller claims, not
authenticated provenance. Profile mode records the claim and prevents it
from relaxing the operator's threshold. Legacy mode uses the origin mapping
directly. The `memwall` metadata key is stripped before backend forwarding.

## Judge-in-the-loop

```bash
memwall gateway --profile reference-memory --judge -- npx -y @modelcontextprotocol/server-memory@1.0.0
```

In profile mode, the judge is advisory and cannot clear a policy block.
Without a profile, clearing verdicts (fact / preference / task context) can
let a flagged write through. This can reduce false positives but can also
clear a real injection. If the judge is unavailable or unsure, the flagged
write stays blocked. The judge requires the optional `judge` extra and
`ANTHROPIC_API_KEY`; consulting it sends flagged memory content to Claude and
can incur API charges. Writes without heuristic findings make no judge calls.

## Roadmap

- **Hosted memwall.** The `watch` engine as a managed service: fleet
  dashboard, alert routing (Slack/email), and scheduled compliance reports.
  Interested? Open an issue titled "hosted waitlist".
- More stores: Zep, Letta, LangGraph checkpoints, vector DBs.
- Policy packs: shareable, versioned policies per industry / risk appetite.

## Honest limitations

Heuristics have false positives and false negatives. Review findings before
deleting memories. A judge verdict is fallible; an allowed write is not a
safety certificate or proof of storage. Direct store access and alternate
connections bypass the gateway. Contract grouping covers one request, not
attacks split across separate calls.

Memwall cannot observe a host agent's full context or replay an existing
Codex or Claude session. Offline trial reports depend on a trusted external
runner and scorer. Their hashes detect known input drift, not fabricated
execution or hidden provider changes. The included simulation establishes
format behavior only, not improved Astra or Opus performance.

See [SECURITY.md](SECURITY.md) for the protection boundary and reporting policy.

## License

MIT
