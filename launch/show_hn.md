# Show HN post

**Title (80 chars max):**

Show HN: Memwall – scanner and firewall for AI agent memory poisoning

**Body:**

Persistent memory became a standard feature of AI agents over the last year,
and it turned into an attack surface: plant one instruction in an agent's
memory (via an email, webpage, or document it reads) and it survives across
sessions and fires weeks later. OWASP added memory poisoning to its 2026
Agentic AI Top 10 (ASI06), but the defenses I could find were papers and
best-practices posts, not tools. So I built one.

Memwall does two things:

1. `memwall scan` — audits existing memory stores (MCP memory servers, mem0
exports, SQLite agent DBs, CLAUDE.md-style instruction files) with 16 heuristic rules: injected
standing orders, secrecy pressure ("don't tell the user"), payment redirects,
zero-width hidden characters, etc. A combo rule flags the classic shape:
standing order + outbound destination in the same memory. Zero dependencies,
exit codes for CI.

2. `memwall gateway -- <your memory server>` — a transparent MCP proxy that
scans every write before it commits. Flagged writes go to quarantine instead
of the store, with an append-only audit trail and a release/drop review flow.
Optionally, agents can declare content origin (user/web/email) for per-source
thresholds, and a Claude-based judge can second-opinion flagged writes to cut
false positives (fail-safe: judge unavailable = write stays blocked).

Honest limitations: heuristics are a triage layer with false positives by
design; closed memory systems (e.g. ChatGPT's built-in memory) can't be
scanned by a third party; the semantic judge costs an API call.

MIT licensed. I'd especially value feedback from anyone running agents with
long-lived memory in production — what does your threat model look like?

https://github.com/gbayerv26/memwall
