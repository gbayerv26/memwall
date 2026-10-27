# v0.8 quarantine and release contract

Baseline: `ce44f5359cccf77e0f04dade76a4f74b092d5565` (v0.7.1).
This contract and the regression expectations were written before implementation.

## Release objective and acceptance criteria

Make the existing quarantine workflow preserve each intercepted operation and
prevent accidental replay after concurrent or interrupted release attempts.
This is an operator-controlled replay mechanism, not proof that content is safe.

1. Two identical intercepted requests get distinct IDs and remain separately
   reviewable. A detected ID collision must never replace an existing entry.
2. Only one release process may operate on an entry at a time. A second release,
   drop, or reconciliation must not change an active attempt.
3. A durable reservation precedes dispatch. `pending -> releasing -> released`
   requires a well-formed backend success response. `released` means backend
   acknowledgement, not independent verification of persistence.
4. Once dispatch may have begun, response loss, rejection, malformed responses,
   process death, or failure to record completion must not reopen automatic
   replay. `uncertain` and abandoned `releasing` require operator reconciliation.
   A failure before dispatch may safely return to `pending`.
5. Reconciliation records an explicit backend observation and a nonempty reason:
   `applied -> released`, `not-applied -> pending`. It cannot run during a live
   release. Reopening also requires `--backend-quiesced`, attesting that all prior
   backend work, including orphaned/asynchronous work, is stopped or drained and
   read-back shows no full or partial effects remain. This trusts the operator's
   inspection and attestation, not an automated check.
6. Malformed/truncated journal records, duplicate IDs, invalid transitions, and
   unknown schemas refuse release and further quarantine mutation. No silent
   skipping or automatic repair may resurrect a pending operation.
7. Healthy historical v0.7.1 entries remain readable and releasable; ambiguous
   historical journals require manual review. Older binaries must not share a
   v0.8 state directory. Supported locks require a local filesystem.
8. Existing legitimate gateway traffic, whole-call quarantine, advisory judging,
   and profile-mode refusal on state errors continue to work.

## Trust boundary

The local operator, backend, role declarations, state filesystem, and all
processes using that state directory are trusted. Local advisory locks serialize
cooperating v0.8 processes; they do not stop a malicious writer or older binary.
Journal flush/fsync precedes dispatch. This is process-crash protection on a
supported local filesystem, not a guarantee against hardware/power-loss failure.
MCP does not provide an end-to-end transaction or an idempotency key here, so
exactly-once effects cannot be promised. An uncertain operation may have zero,
one, or partial effects. Reconcile against the same intended backend and store.
Complete-record deletion/rollback and malicious filesystem edits cannot be
detected. A hung backend can require operator interruption; no runtime timeout
is promised. Stop/drain its work before evaluating whether retry is safe.

## State transitions

| Current state | Event | Next state | Can release? |
| --- | --- | --- | --- |
| pending | durable reservation | releasing | Only the reserved attempt |
| pending | operator drop | dropped | No |
| releasing | valid supported success and durable completion | released | No |
| releasing | known failure before tool dispatch | pending | Yes |
| releasing | failure after dispatch may have begun | uncertain | No |
| releasing | parent process dies | releasing | No |
| releasing / uncertain | operator confirms full applied outcome | released | No |
| releasing / uncertain | prior work quiesced and absence of effects confirmed | pending | Yes |

`releasing` can mean active or interrupted. Per-entry locks distinguish a live
local release parent from an abandoned reservation; they cannot prove its
backend work has stopped. A completion persistence error may leave `released`,
`uncertain`, `releasing`, or an invalid journal, depending on the write boundary.
Every case refuses another automatic release. Healthy historical `released`
and `dropped` records remain final; ambiguous historical duplicates fail closed.

## Operator recovery and compatibility

1. Stop older Memwall processes and back up the state directory before upgrade.
   New records use version 2; healthy unversioned historical records remain valid.
   IDs are now `q` followed by 32 random hexadecimal characters. Use the full ID
   printed by `list`; existing short IDs remain valid.
2. Inspect `quarantine --state-dir PATH show QID`. On a busy entry, let the
   active release finish or stop it deliberately. Never run an older binary to
   bypass a reservation.
3. Inspect the exact intended backend/store. If fully applied, use `reconcile
   QID --outcome applied --reason "Read-back evidence"`.
4. If considering another attempt, stop/drain all prior backend work first,
   inspect for partial effects, and resolve them manually. Only with verified
   absence of effects use `reconcile QID --outcome not-applied --backend-quiesced
   --reason "Quiescence and read-back evidence"`. This returns to pending;
   release remains a separate explicit command.
5. On invalid journals, preserve the original bytes and investigate the reported
   line. No repair command discards evidence or guesses a pending status.

Exit codes: 0 is completed command, 1 is release attempt failure, 2 is refused
operation/state or command error. For release, 0 indicates backend acknowledgement,
not independent persistence verification. Retain filesystem permissions because
the journal includes full quarantined payloads.

## Evidence plan

Use synthetic, isolated stores only. Preserve test exit results, raw journals,
exact MCP messages, backend effect records, and before/after results. A counting
backend is needed because a real memory backend can deduplicate repeated writes.
Also verify successful release, rejected release, and refused replay against
the pinned `@modelcontextprotocol/server-memory@1.0.0` backend with read-back.
No provider calls, real-agent effectiveness claims, publication, or deployment.

## Reproduce independently

Run from a clean checkout using Python 3.9+ and Node.js. The local evidence run
used Windows and Python 3.12; the configured Ubuntu/Windows Python 3.9/3.13 CI
matrix is a separate check, not a claim made by this local run.

```powershell
npm install --prefix .reference-backend --ignore-scripts --no-audit --no-fund --save-exact @modelcontextprotocol/server-memory@1.0.0
$env:MEMWALL_REFERENCE_SERVER = (Resolve-Path '.reference-backend/node_modules/@modelcontextprotocol/server-memory/dist/index.js').Path
$env:MEMWALL_EVIDENCE_DIR = Join-Path $env:TEMP 'memwall-v08-independent-evidence'
python -m unittest discover -s tests -t . -v
$LASTEXITCODE
```

The fixture backend counts each applied call independently, including duplicate
effects a deduplicating memory backend could conceal. Evidence JSON includes
unaltered UTF-8 journal contents, exact fixture wire messages, raw wire lines,
process exit results, and persisted effect records. The reference-backend files
include gateway read-back traffic and stored memory contents.

To challenge the baseline with the same five behavioral expectations, create
a separate checkout and copy only the two self-contained test files:

```powershell
git worktree add --detach ../memwall-v071-repro ce44f5359cccf77e0f04dade76a4f74b092d5565
Copy-Item tests/test_release_reliability.py, tests/release_backend.py ../memwall-v071-repro/tests/
Push-Location ../memwall-v071-repro
$env:MEMWALL_EVIDENCE_DIR = Join-Path $env:TEMP 'memwall-v071-independent-evidence'
python -m unittest tests.test_release_reliability -v
$LASTEXITCODE
Pop-Location
```

Expected: baseline exits 1 with five failures; upgraded code passes those tests.
IDs, timestamps, process IDs, and temporary paths will vary. The stored evidence
report identifies the exact implementation commit and observed check results.
These are controlled fixture and interoperability results, not independently
certified security or measurements of real agent behavior.
