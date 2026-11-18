"""Run the offline Memwall inventory demo with LangGraph's in-memory Store."""
import argparse
import json
from pathlib import Path
import subprocess
import sysconfig

from langgraph.store.memory import InMemoryStore


NAMESPACES = (("Support",), ("Billing",))
KEY = "escalation"
PAGE_SIZE = 1


def export(store, path, max_pages=None):
    envelope = {
        "schema": "memwall.langgraph-export.v1",
        "store": "support-demo",
        "namespaces": NAMESPACES,
        "complete": True,
        "items": [],
    }
    pages_read = 0
    for namespace in NAMESPACES:
        offset = 0
        while True:
            if max_pages is not None and pages_read >= max_pages:
                envelope["complete"] = False
                break
            page = store.search(namespace, offset=offset, limit=PAGE_SIZE)
            pages_read += 1
            for item in page:
                if item.namespace == namespace:
                    envelope["items"].append({
                        "namespace": item.namespace,
                        "key": item.key,
                        "value": item.value,
                        "updated_at": item.updated_at.isoformat(),
                    })
            offset += len(page)
            if len(page) < PAGE_SIZE:
                break
        if not envelope["complete"]:
            break
    path.write_text(json.dumps(envelope, indent=2), encoding="utf-8")


def inventory(cwd, *arguments, expected=0):
    command = Path(sysconfig.get_path("scripts")) / "memwall"
    if not command.exists():
        command = command.with_suffix(".exe")
    result = subprocess.run([str(command), "inventory", *arguments], cwd=cwd)
    if result.returncode != expected:
        raise SystemExit(f"Expected exit {expected}, observed {result.returncode}: {arguments}")


def run(directory):
    directory = directory.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    store_dir = directory / "support-memory"
    store_dir.mkdir()
    source = store_dir / "export.json"
    store = InMemoryStore()
    for namespace in NAMESPACES:
        store.put(namespace, KEY, {"content": "Escalate to Tier 1."})
    for name in ("before", "after", "limited"):
        if name == "after":
            store.put(("Support",), KEY, {"content": "Escalate to Priority Support."})
        limited = name == "limited"
        export(store, source, max_pages=1 if limited else None)
        inventory(directory, "snapshot", str(source), "--format", "langgraph",
                  "--scope", "support", "--out", f"{name}.json", expected=2 if limited else 0)
    for name in ("after", "limited"):
        inventory(directory, "diff", "before.json", f"{name}.json", "--summary",
                  f"{name}-summary.json", expected=2 if name == "limited" else 0)
        summary = json.loads((directory / f"{name}-summary.json").read_text(encoding="utf-8"))
        expected = {"changed": 1, "unchanged" if name == "after" else "presence_only": 1}
        actual = {key: value for key, value in summary["counts"].items() if value}
        if actual != expected:
            raise SystemExit(f"Unexpected {name} comparison counts: {actual}")
    print(f"Private snapshots and shareable summaries: {directory}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, help="a new directory for the evidence")
    run(parser.parse_args().directory)
