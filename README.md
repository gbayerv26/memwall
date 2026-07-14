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
pip install -e .

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

## Supported stores (v0.1)

- **MCP reference memory server** — `memory.json` / `.jsonl` of entities and observations
- **mem0-style exports** — JSON lists of memory objects
- **Agent instruction files** — `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursorrules`, `.mdc`
- **Notes / markdown memory files** and generic JSON dumps

## How it works

**Pass 1 — heuristics (free, instant).** Rules MW001–MW013 catch the known
shapes of memory poisoning: instruction overrides, secrecy pressure
("don't tell the user"), authority claims ("system note:", "developer mode"),
payment redirection, crypto wallets, encoded payloads, zero-width/bidi hidden
characters, and PII that needs an expiry policy. A combo rule (MW000)
escalates to CRITICAL when a standing order and an outbound destination appear
in the same memory — the classic exfiltration shape.

Instruction files get a calibrated ruleset: imperatives are normal in a
CLAUDE.md, so only the genuinely suspicious rules apply there.

**Pass 2 — the judge (optional).** `--judge` sends flagged records to Claude
for semantic classification (`benign_fact` / `preference` / `task_context` /
`suspicious_instruction` / `likely_injection`). The judge treats memory
content as untrusted data and never follows instructions inside it.

```bash
pip install -e ".[judge]"
export ANTHROPIC_API_KEY=sk-ant-...
memwall scan memory.json --judge
```

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

Override with `--policy policy.json`:

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

With `--judge`, flagged writes get a second opinion from the Claude judge
before quarantining. Clearing verdicts (fact / preference / task context) let
the write through — cutting heuristic false positives without losing the
block on real injections. If the judge is unavailable or unsure, the write
stays quarantined (fail-safe). Needs `pip install "memwall[judge]"` and
`ANTHROPIC_API_KEY`; adds one API call only to writes heuristics already
flagged, so normal traffic pays zero latency.

## Roadmap

- **Phase 3 — hosted monitoring.** Continuous scans, alerting, and compliance
  exports (EU AI Act logging, GDPR erasure verification).
- More stores: Zep, Letta, LangGraph checkpoints, vector DBs.
- Policy packs: shareable, versioned policies per industry / risk appetite.

## Honest limitations

Heuristics have false positives and false negatives by design — they are a
triage layer, not a verdict. Review findings before deleting memories. The
judge pass improves precision but is only as good as the model behind it.

## License

MIT
