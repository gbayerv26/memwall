# Offline memory trials

Memwall can prepare a self-contained trial bundle and validate a trusted external
runner's evidence. Both commands use only Python's standard library and local
files. They never call a model, launch a runner, install packages, fetch URLs, or
change quarantine. Installing Memwall's optional `judge` extra is unnecessary.
Real agent runs are a separate integration and can incur provider charges.

The purpose is a focused comparison: does one exact proposed memory operation
help a representative task, introduce risk or stale assumptions, or show no
measurable value? This is an evidence adapter, not a new evaluation engine or
a claim of a unique memory-evaluation capability.

## Try the free local simulation

From a source checkout, choose a directory that does not exist:

```sh
python -m examples.trials.run_demo --out trial-demo
python -m memwall trial report trial-demo/bundle.json trial-demo/results.json --manifest trial-demo/manifest.json --out trial-demo/rechecked-report.json
```

This creates 36 shuffled fixture runs: four cases, three repetitions, and three
arms. It demonstrates an approved correction, a legitimate format preference,
an already-correct task, and a newer source that supersedes the same memory.
The intentionally naive simulated actor accepts the remembered timeout even
when source is newer. Deterministic checks compare its resulting configuration
against the approved source, check TLS attempts, and check the report format.

All fixture expectations are author-written calibration cases. They are not
independently labeled, held-out cases. **No Astra, Opus, or other AI agent is
measured.** A simulation report always carries a prominent simulation warning.
The fixture is included in the source checkout, not the installed wheel.

## Prepare a real trial without running it

```sh
memwall trial prepare manifest.json --out bundle.json
```

Start with the demo's manifest as a format example. Replace its files and case
definitions, and set `execution_kind` to `agent` only for real agent runs.
Every manifest has exactly these fields:

```json
{
  "version": 1,
  "execution_kind": "agent",
  "configuration": {
    "provider": "your-provider",
    "model": "exact-model-version",
    "reasoning": "your-selected-setting",
    "max_output_tokens": 4096,
    "temperature": 0,
    "region": "your-region",
    "cache_mode": "your-mode"
  },
  "files": {
    "candidate": "candidate.json",
    "baseline": "memory-snapshot.json",
    "task": "tasks.json",
    "instructions": "instructions.json",
    "tools": "tool-schemas-and-permissions.json",
    "environment": "environment-snapshot.json",
    "source": "approved-source.txt",
    "harness": "runner.py",
    "scorer": "scorer.py"
  },
  "label_source": "Reviewer and sealed label-set identifier",
  "cases": [
    {"id": "approved-correction", "label": "beneficial", "split": "held_out", "repetitions": 3}
  ]
}
```

Configuration accepts additional settings. Record **all** settings that matter,
including reasoning, model version, output/thinking budgets, retries, sampling,
tool permissions, retrieval strategy, cache, region, and randomized arm order.
Put complex instructions or environment metadata in the bound files. Memwall
does not check provider model catalogs or silently select different settings.
Do not place API keys in the manifest or bundle.

File paths resolve relative to the manifest and may point to trusted local
files elsewhere. Inputs are copied as exact bytes with full SHA-256 digests;
the bundle ID binds the versioned canonical JSON body, including the manifest.
No source command is executed. Candidate content must be a complete MCP
`jsonrpc: "2.0"`, `method: "tools/call"` request with a tool name and arguments
object. Preserve the whole operation, including related fields and batches.
For quarantine, extract the selected entry's `request` object into the candidate
file after review. A short quarantine ID or truncated audit hash is insufficient.
This initial version deliberately uses explicit request files, not live host
session capture or automatic quarantine extraction.

All nine file roles are required. Up to 32 roles, 100 cases, 2-100 repetitions
per case and 3,000 total runs are supported. Files are limited to 1 MiB each,
inputs to 8 MiB total, JSON documents to 16 MiB, and imported traces to 64 MiB
total. Version 1 rejects duplicate JSON keys, nonfinite numbers, and excessive
nesting. Outputs are created exclusively; existing files are never overwritten.

## External runner contract

An MCP proxy cannot observe the full host prompt or replay an existing Codex or
Claude conversation. Supply a controlled host/API runner with fresh sessions,
identical instructions, tools, approved sources and cloned baseline state.
For each case and repetition, run all three arms:

| Arm | Starting memory | Purpose |
| --- | --- | --- |
| `baseline` | Exact baseline snapshot | Reference behavior |
| `baseline_repeat` | Independent clone of the same snapshot | Baseline variability control |
| `candidate` | Same snapshot plus the exact candidate operation | Candidate effect |

Randomize arm order and preserve it in the runner evidence. Record actual
memory exposure, not just successful insertion. Keep scoring and held-out labels
outside the agent's writable environment. Supply realistic malicious and benign
counterparts, including legitimate corrections, preferences and obsolete facts.
Do not give the evaluated model the manifest's labels or scoring expectations.

The runner, not Memwall, must enforce budget limits, isolate tools and side
effects, verify backend read-back, and execute deterministic task checks. Check
unsafe **attempts**, even when a sandbox blocks them. A refusal without completing
the required task is a task failure. Use independently labeled held-out cases
for real evaluation. Neither a declared `held_out` split nor a hash proves the
labels were independently assigned or the run actually happened.

Export results with exactly these root fields:

```json
{
  "bundle_id": "FULL_BUNDLE_SHA256",
  "execution_kind": "agent",
  "runner": "trusted-runner-and-version",
  "runs": [
    {"case_id": "approved-correction", "repeat": 0, "arm": "baseline",
     "status": "complete", "memory_exposed": false,
     "trace": "traces/case-0-baseline.json", "trace_sha256": "FULL_TRACE_SHA256"}
  ]
}
```

Include every case/repetition/arm exactly once. Repeat indexes start at zero.
Each trace must have these fields (see the demo's generated files for complete
examples):

| Fields | Required content |
| --- | --- |
| `bundle_id`, `case_id`, `repeat`, `arm` | Exact bindings to the run |
| `configuration` | Exact manifest configuration |
| `baseline_sha256` | Bundle's full baseline artifact digest |
| `candidate_sha256` | Bundle's candidate digest in candidate arm; `null` in baseline arms |
| `input_messages` | Fixed task/instruction messages, identical across all three arms |
| `memory_messages` | Actually delivered memory context, separate from the fixed inputs |
| `output_messages`, `tool_calls` | Visible agent outputs and tool-call objects as arrays |
| `environment_before`, `environment_after` | Snapshot objects, including relevant backend read-back and executable outcomes |
| `checks` | Boolean `task_correct`, `unsafe_action`, `obsolete_assumption`, `preference_followed` |

Normalize messages into objects with a `role` of `system`, `developer`, `user`,
`assistant` or `tool`, and nonempty `content` (string, list or object), or a
nonempty `tool_calls` list. Fixed inputs and outputs must be nonempty. Claimed
candidate exposure requires visible memory messages. Vendor event formats may
need a runner-side conversion to this envelope; preserve raw events inside it.

Use `preference_followed: true` when no preference obligation exists. All three
arms must have identical fixed inputs and starting environment snapshots, with
memory treatment represented separately by its digest and `memory_messages`.
Embed relevant
raw tool requests/responses and scorer details in the existing message, tool-call,
and snapshot fields. Trace files must reside beneath the results directory;
absolute paths, parent traversal and escaping symlinks are rejected.

## Validate evidence and inspect effects

```sh
memwall trial report bundle.json results.json --manifest manifest.json --out report.json
```

The current manifest and input files are required. Any byte change in memory,
source, instructions, tools, environment, runner or scorer, or any configuration
change makes the bundle stale and requires a new trial. Missing runs, failed
execution, missing traces, hash/binding mismatches or different starting
environments produce exit code 2 and no new report. Retain failed-run evidence
for diagnosis; never replace it with invented successful results.

The report preserves separate task, safety, obsolescence and preference counts,
baseline disagreements, exposure counts and trace digests. It counts a paired
benefit or harm only when both baseline checks agree and the candidate was
exposed. Benefits include corrected tasks/preferences and reduced unsafe or
obsolete behavior. Harms include the reverse. Both produce `mixed`. Any
baseline disagreement or unexposed repetition makes a case `inconclusive`.
Otherwise the descriptive effect is `beneficial`, `harmful`, or
`no_demonstrated_value`. Case labels remain visible beside observed effects;
they never determine the result. An unsafe attempt remains in the counts even
if the overall effect is inconclusive or unchanged from baseline.

These are descriptive signals, not significance tests, safety certifications,
or an automatic acceptance gate. Repetitions of one case are not independent
new cases. A report does not establish generalization beyond its cases. It
does not authenticate the runner, validate arbitrary scorer code, or prove
that declared model settings were honored. Protect manifests, traces, labels
and receipts from agent writes. Raw bundles and traces can contain sensitive
source and memory data; review before sharing.

Reports are historical evidence bound to the reported configuration. Hidden
provider changes cannot be detected locally. Recheck upstream versions and
rerun when model serving behavior changes. There is no automatic validity TTL.
Re-import against current files to detect known drift; an old receipt does not
update itself. No trial result overrides the fast gateway or releases memory.
Human review and `memwall quarantine release` remain separate operations.
