# Scan coverage in 0.8.1

Coverage describes the selected sources and fields that Memwall could inspect.
An empty but valid memory store is a fully inspected source. A directory where
no stores qualify reports `no_sources`.

| Coverage | Scan | Watch once | Literal identifier check |
| --- | --- | --- | --- |
| `complete` | 0 below the finding threshold, 1 at or above it | 0 for a normal tick, 1 for new findings with `--fail-on-new` | 0 for no matches, 1 for matches |
| `no_sources` | 0 for an ordinary scan, 2 for a baseline update | 2 | 2 |
| `partial` or `failed` | 2, with findings from available records | 2, with provisional findings when an earlier snapshot exists | 2, with any observed matches |

Partial results mean some selected input was readable and the scan encountered
a gap. Failed results mean the reader could not return selected input. Neither
status advances a watch snapshot or an accepted baseline. Continuous watch
reports the gap and resumes at its usual interval. The next complete tick
compares against the last complete snapshot. A complete first tick retains
the existing baseline behavior.

## What the scan selects

- Auto mode walks existing eligible paths and preserves the discovery exclusions
  for dependencies, most hidden directories and unrelated project JSON. Unknown
  extensions are selected when SQLite magic is recognized. A direct file and
  an explicit format use the selected reader without directory discovery.
- Plain text uses nonblank blocks. JSON and mem0 exports use their recognized
  record containers and text fields. MCP JSONL uses entity observations and
  relation text. Other fields are outside the scope of the literal check.
- SQLite reads eligible text cells of four or more characters after stripping
  surrounding whitespace. A skipped table or reaching 20,000 records makes
  coverage incomplete. At exactly the cap, the reader stops without traversing
  the remaining rows or tables to prove exhaustion.
- Discovery still limits selected non-SQLite files to 5 MiB. Passing one file
  directly skips that discovery limit. A file excluded by discovery rules is
  outside the statement of coverage.

JSON coverage includes selected and complete source counts, emitted records,
issue counts by reason, and up to 12 source-relative examples. Issue counts
describe observed gaps. One issue may stand for an unknown number of unread
records. SARIF attaches coverage under the invocation properties. HTML, Markdown,
and quiet terminal output include a coverage summary.

## Upgrade existing automation

Treat exit 2 as requiring review or a rescan. In `forget-check` JSON, use
`result` and `coverage.status` together.

| Result | Meaning |
| --- | --- |
| `literal_match_found` | A supplied identifier appears in an inspected record. Check coverage for possible additional matches. |
| `no_literal_match_in_scope` | A complete check found none of the supplied literal identifiers in the selected fields. |
| `unknown` | Coverage was incomplete or no store was selected, and no inspected record yielded a match. |

The legacy `erased` key remains on complete checks and known hits and is omitted
for `unknown`. A complete literal no-match result only establishes absence in
the reported scope. Paraphrases, undiscovered sources, backups and excluded
fields require their own review. Reports can include memory text and subject
identifiers. Store them in a separate output directory and review them before
sharing.

For upgrades from 0.6.1, read the [0.7 and 0.8 changes](../CHANGELOG.md) and
[0.8 quarantine upgrade guidance](QUARANTINE_V08.md) before reusing state.
Stop older gateway processes and preserve a backup before starting the newer
version. Use the pre-upgrade copy if rolling back to an older version and
separately account for subsequent backend effects.
