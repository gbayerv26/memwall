# Local inventory in Memwall 0.9.0

Install with `python -m pip install memwall==0.9.0`. Existing scan, watch,
quarantine and trial commands keep their own state. Inventory uses a separate
versioned manifest and needs two new observations. No migration is required.

From the parent directory of your store, run the first command, update the store
through its usual API, then run the remaining commands.

```sh
memwall inventory snapshot ./support-memory --scope support --out before.json
memwall inventory snapshot ./support-memory --scope support --out after.json
memwall inventory diff before.json after.json --summary share.json
```

Use the same host, canonical input path, scope label, reader and selection for
both snapshots. For an export, refresh the export at its original location.
Choose unused output filenames outside the input directory. A private manifest
retains extracted wording, namespace, identifiers, revision, local locator and
any supported source timestamp. The observation timestamp describes the capture.
Reading the manifest or diff later reveals earlier wording even if the source
has changed again. Protect both manifests and the terminal output accordingly.

The separate summary file contains counts, coverage states and fixed reason
codes. Duplicate keys produce an unresolved group with the competing evidence.
An absent key is reported as absent from the observed scope when the later
capture was complete. An added key requires complete earlier coverage. A key
observed on both sides can show an edit during partial coverage. Findings refer
only to observations at capture time. Agent usage and events between captures
require independent evidence.

For records without a stable key, compare counts of equal content in the same
source and namespace. The unresolved count sums the larger observed multiplicity
for each group. A count difference counts groups whose observed multiplicity
differs. During incomplete coverage those counts are lower bounds. Paragraph
lines, observation indexes, generated JSON IDs and SQLite row IDs serve as
locators. Content revisions describe the extracted text. See the
[reader selection rules](SCAN_COVERAGE.md) for fields, exclusions and limits.

Exit 0 means capture or comparison succeeded, including a comparison that
found edits or could compare only multiplicities for positional records.
Exit 2 indicates incomplete coverage, no sources, incompatible boundaries,
duplicate stable keys, invalid input or an output error. Review partial
evidence when available. A valid empty store supports absence claims. A
directory without eligible stores yields `no_sources`.

An inventory walks the selected inputs during capture. Quiesce writers or use
a consistent store export when a point-in-time view matters.

Run the [LangGraph Store escalation example](../examples/langgraph_store/README.md) to reproduce a complete and a deliberately partial comparison.

## Release verification

On Windows with Python 3.12.10 the suite passed all 166 tests, including six
interoperability cases with the pinned MCP reference server 1.0.0. The wheel
and source distribution each installed into a separate fresh environment
outside the checkout. Both installed entry points captured and compared a
one-edit store without LangGraph installed. The optional example ran separately
with langgraph-checkpoint 4.3.2. Snapshot and summary publication require a
destination filesystem that supports hard links.
