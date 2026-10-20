# v0.8 local verification record

Baseline: `ce44f5359cccf77e0f04dade76a4f74b092d5565`.
Verified implementation: `07f809d50e2768bc7d219c1ad84c0a79794a7680`.
The following evidence-only commit adds this directory without changing code.

The baseline was extracted from `git archive` into an isolated temporary
directory. Only `tests/test_release_reliability.py` and `tests/release_backend.py`
were copied into it. The same five expectations ran against both implementations.

| Reproducer | v0.7.1 observation | v0.8 observation |
| --- | --- | --- |
| Two identical quarantined requests in one second | Same ID, one folded entry | Distinct IDs, two entries |
| Two competing release processes | Both exit 0, two backend effects | One exits 0, one exits 2, one effect |
| Backend applies write but loses response; retry | Two effects, retry exits 0 | One effect, uncertain state, retry exits 2 |
| Backend succeeds but completion record fails; retry | Two effects, retry exits 0 | One effect, replay refused |
| Truncated status record followed by release | Record skipped, one effect | Journal refused, zero effects |

`baseline-tests.txt` records five failures and exit 1. `full-suite.txt` records
150 tests passing with no skips and exit 0, including all six pinned real-backend
tests. The initial unmodified baseline suite passed 124 tests with five optional
reference-backend tests skipped; running those five explicitly after installing
the pinned server also passed.

The final suite additionally tests process death after a persisted backend
effect, recovery of abandoned reservations, refusal of live reconciliation/drop,
not-applied attestation, launch/handshake failure without dispatch, completion
failure before and after its record, concurrent quarantine writers, forced ID
collision, invalid record variants, depth budgets, and healthy legacy records.

## Files and interpretation

- `verification.json`: exact implementation identity, environment, backend hash,
  commands, exit results, and checks not run.
- `baseline/` and `final/`: synthetic journal bytes represented as UTF-8 strings,
  fixture wire messages/raw lines, counted effects, and process results.
- `final/reference-success.json`: a successful release followed by refused
  replay, real memory contents, and gateway read-back request/response traffic.
- `final/reference-rejection.json`: a rejected real-backend call remains uncertain;
  read-back shows no entities in this particular case. This does not prove all
  rejected backend calls have no effects.
- `example-scan.txt`: expected scanner exit 1, with one critical and one high
  finding in the supplied example. This CI step is intentionally non-gating.
- `reference-package.json` and `reference-package-lock.json`: the npm dependency
  graph actually used, including transitive versions and integrity fields.
- `package-check.json` and `package-check.txt`: packaging was attempted but not
  verified. The host lacks `setuptools.build_meta`; isolated attempts to fetch
  declared build requirements timed out through both the configured package
  source and public PyPI. No global Python installation was changed.
- `SHA256SUMS.json`: artifact hashes for detecting later file changes, not proof
  that the execution or the claims are authentic.

The directory disables Git newline conversion so those byte hashes remain
checkable after a fresh checkout, including on another operating system.
Raw artifacts also retain their original whitespace; source whitespace checks
remain enabled outside this evidence directory.

Full reproduction commands and operator recovery are in
[`QUARANTINE_V08.md`](../../QUARANTINE_V08.md). To restore the exact reference
dependency graph, copy the two `reference-package*` files to
`.reference-backend/package.json` and `.reference-backend/package-lock.json`,
then use `npm ci --prefix .reference-backend --ignore-scripts --no-audit --no-fund`.

One separate assistant performed a read-only implementation review. Four
findings (orphaned backend work, append/read depth mismatch, malformed content,
and malformed JSON-RPC acknowledgements) were addressed with focused regressions.
That review is not external certification or a separately reproduced security
assessment.

## Limits

Observed locally on Windows 11, Python 3.12.10, Node.js v24.18.0, and
`@modelcontextprotocol/server-memory@1.0.0`. Hosted Ubuntu/Windows Python 3.9/3.13
CI and wheel installation checks were not completed. There were no provider/model calls, release publication, or
deployment. No power-loss, hostile-filesystem, or real-agent effectiveness
claim follows from these tests. Reconciliation trusts operator observations
and quiescence attestation. Backend acknowledgement is not proof of storage,
and the workflow does not promise exactly-once effects.
