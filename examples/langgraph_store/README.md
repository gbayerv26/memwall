# Compare a LangGraph Store before and after an instruction changes

Run from the repository root with Python 3.12. These commands install the example dependencies in their own environment and write evidence to a new directory. Choose a fresh output directory for each run.

```sh
python -m venv .venv-demo
. .venv-demo/bin/activate
python -m pip install . -r examples/langgraph_store/requirements.txt
python examples/langgraph_store/demo.py inventory-demo
```

On Windows PowerShell, activate the environment with `& .\.venv-demo\Scripts\Activate.ps1`. The pinned `langgraph-checkpoint==4.3.2` distribution provides LangGraph's `InMemoryStore`. The example uses synthetic data and runs locally without credentials or model calls.

The example writes the same escalation key and instruction in Support and Billing, captures both, then updates only Support using `store.put`. The first diff should show one changed Support instruction, from “Escalate to Tier 1.” to “Escalate to Priority Support.”, and count one unchanged Billing record. The second diff caps the export after one page. It can still verify the Support edit. Billing was present in the first capture and its later state is unknown.

The private evidence files are `inventory-demo/before.json`, `after.json` and `limited.json`. Each preserves its observed wording even after the store process exits. The two `*-summary.json` files contain aggregate results. To inspect the private comparison again, run the following from the repository root.

```sh
memwall inventory diff inventory-demo/before.json inventory-demo/after.json
memwall inventory diff inventory-demo/before.json inventory-demo/limited.json
```

The complete comparison exits 0. The limited capture and comparison exit 2. The demonstration checks both exit codes and verifies the expected counts.

## Export contract

Use `memwall inventory snapshot PATH --format langgraph --scope support --out SNAPSHOT` on successive exports at the same path. The exporter declares a store identifier and its exact selected namespaces. This example supports Store values of the form `{"content":"instruction text"}`. Each item carries the Store namespace, native key, value and source-supplied update time. For example, a complete envelope for a single selected namespace looks like this.

```json
{
  "schema": "memwall.langgraph-export.v1",
  "store": "support-demo",
  "namespaces": [["Support"]],
  "complete": true,
  "items": [{
    "namespace": ["Support"],
    "key": "escalation",
    "value": {"content": "Escalate to Priority Support."},
    "updated_at": "2026-01-01T00:00:00+00:00"
  }]
}
```

LangGraph searches by namespace prefix. The exporter walks each selected prefix with `limit=1` and increasing `offset`, filters each returned item for an exact namespace match and reads through the final short or empty page. It sets `complete` to false if the page budget stops traversal early. This demonstration has a single writer and pauses mutations during export. Offset pagination over a concurrently changing store would need additional consistency guarantees. [LangGraph Store documentation](https://docs.langchain.com/oss/python/langgraph/stores)
