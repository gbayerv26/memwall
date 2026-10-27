# Security policy

memwall is a security tool, so reports about its own weaknesses are
especially welcome — including heuristic bypasses.

## Reporting a vulnerability

Please use [GitHub's private vulnerability reporting](https://github.com/gbayerv26/memwall/security/advisories/new)
on this repository (Security tab -> Report a vulnerability). Do not open a public
issue for anything exploitable. Target first response: 72 hours.

## In scope

- Ways to smuggle a poisoned memory past the rule engine or the gateway
  (novel bypass patterns are valid reports — they become new rules)
- Ways to make the gateway corrupt, drop, or leak protocol traffic
- Ways to tamper with the audit trail or quarantine store

## Known, documented trade-offs (not vulnerabilities)

- Without `--profile`, the gateway **fails open** on internal scan errors.
  Select `--profile reference-memory` or a trusted local profile to refuse
  uninspectable requests and inspection/state failures before forwarding.
- Profile enforcement trusts the operator's tool-role declarations, backend,
  and filesystem. Custom `read`/`maintenance` declarations must never describe
  tools that insert memory. Unknown tools are refused; backend upgrades may
  require profile updates. Server annotations cannot grant an exemption.
- Claimed origins cannot relax the operator's threshold in profile mode.
  This is not authenticated provenance. The optional judge is advisory in
  profile mode, since its input may be truncated and its output may be wrong.
- Inspection groups cover related fields in a single call. Direct store
  access, alternate connections, and attacks spanning separate calls are
  outside this enforcement boundary. `allowed` is an authorization event,
  not proof of storage. Quarantine files retain sensitive payloads and need
  the same filesystem protection as the memory store.
- Quarantine release uses a durable reservation and local per-entry advisory
  locks across cooperating v0.8 processes. A dispatched failure can have zero,
  partial, or full backend effects. Uncertain/interrupted attempts cannot replay
  until operator reconciliation. Before reopening one as not applied, stop/drain
  prior backend work, including orphaned processes, and verify no effects remain.
  The `--backend-quiesced` flag is an operator assertion, not process verification.
  A successful release records structural backend acknowledgement, not proof of
  persistence. There is no distributed transaction or exactly-once guarantee.
- State must be on a trusted local filesystem supporting advisory locks and
  fsync. Stop older binaries before upgrading and back up state. Malformed
  quarantine records fail closed without repair. This detects malformed records,
  not deletion/rollback of complete records or malicious filesystem edits. Power
  loss, unsupported network filesystems, and noncooperating writers are outside
  the process-crash/concurrency guarantee. Release can wait on an unresponsive
  backend; interruption leaves an entry requiring recovery.
- Heuristics are a triage layer with false negatives by design; the judge
  pass exists to raise precision, not to guarantee it.
- Offline trial bundles bind exact inputs and imported traces with full digests.
  They trust the local operator, runner, scorer and filesystem. Hashes do not
  authenticate execution, labels or provider settings. The model must not be
  able to write trusted manifests, scorers, labels or receipts. Simulations are
  not agent evidence, and trial reports never grant release or bypass policy.
  Bundles and traces may contain full sensitive memory and source material.
