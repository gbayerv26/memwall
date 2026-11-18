"""Private, local observations of selected memory records."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import socket
import tempfile
from datetime import datetime, timezone

from .adapters import ADAPTERS, load_with_coverage
from .adapters.coverage import Coverage

SCHEMA = "memwall.inventory.v1"
FORMATS = {"auto", "langgraph", *ADAPTERS}
REASONS = {
    "file_size_limit", "decode_error", "source_unreadable", "source_missing",
    "invalid_document", "directory_unreadable", "unsupported_item", "unsupported_document",
    "invalid_jsonl", "table_unreadable", "record_limit", "export_limited",
}
STORES = {"files", "mem0", "json", "mcp-memory", "sqlite", "langgraph"}
WEAK_BASIS = {"files": "block_location", "mem0": "array_position", "json": "array_position",
              "sqlite": "sqlite_cell", "mcp-memory": "observation_location"}


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _object(value, fields):
    _require(isinstance(value, dict) and set(value) == set(fields), "invalid object fields")


def _text(value):
    return isinstance(value, str) and bool(value)


def _namespace(value):
    return isinstance(value, list) and all(_text(part) for part in value)


def _timestamp(value):
    _require(_text(value), "missing observation time")
    stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    _require(stamp.utcoffset() is not None, "observation time requires a timezone")


def _revision(content):
    return hashlib.sha256(content.encode("utf-8", errors="surrogatepass")).hexdigest()


def _record(source, store, namespace, key, locator, content, timestamp):
    return {
        "source": source, "store": store, "namespace": list(namespace), "key": key,
        "basis": "native_key" if key is not None else WEAK_BASIS[store], "locator": locator,
        "content": content, "revision": _revision(content),
        "store_timestamp": timestamp if _text(timestamp) else None,
    }


def _unique_pairs(pairs):
    obj = {}
    for key, value in pairs:
        _require(key not in obj, "duplicate JSON field")
        obj[key] = value
    return obj


def _read(path):
    with open(path, encoding="utf-8-sig") as stream:
        return json.load(stream, object_pairs_hook=_unique_pairs)


def read_manifest(path):
    data = _read(path)
    validate(data)
    return data


def _export_selection(selection):
    _object(selection, ("rules", "store", "namespaces"))
    _require(selection["rules"] == "langgraph-exact-namespaces-v1" and _text(selection["store"]),
             "invalid export selection")
    ns = selection["namespaces"]
    _require(isinstance(ns, list) and bool(ns) and all(_namespace(n) and n for n in ns)
             and len(set(tuple(n) for n in ns)) == len(ns), "invalid selected namespaces")


def _langgraph(path):
    data = _read(path)
    _object(data, ("schema", "store", "namespaces", "complete", "items"))
    _require(data["schema"] == "memwall.langgraph-export.v1" and type(data["complete"]) is bool
             and isinstance(data["items"], list), "invalid LangGraph export")
    selection = {"rules": "langgraph-exact-namespaces-v1", "store": data["store"],
                 "namespaces": data["namespaces"]}
    _export_selection(selection)
    selection["namespaces"].sort()
    coverage = Coverage(str(path), "langgraph", selected_sources=1, _opened_sources=1)
    if not data["complete"]:
        coverage.issue("export_limited", str(path))
    records = []
    for idx, item in enumerate(data["items"]):
        if not (isinstance(item, dict) and item.get("namespace") in selection["namespaces"]
                and _text(item.get("key")) and isinstance(item.get("value"), dict)
                and isinstance(item["value"].get("content"), str)
                and (item.get("updated_at") is None or _text(item["updated_at"]))):
            coverage.issue("unsupported_item", str(path), idx + 1)
            continue
        records.append(_record(path.name, "langgraph", item["namespace"], item["key"],
                               f"items[{idx}]", item["value"]["content"], item.get("updated_at")))
    coverage.records = len(records)
    coverage.complete_sources = int(not coverage.issue_counts)
    return records, coverage, selection


def capture(path, fmt, scope):
    _require(fmt in FORMATS and _text(scope), "invalid inventory format or scope")
    path = Path(os.path.normcase(os.path.realpath(path)))
    directory = path.is_dir()
    observed_at = datetime.now(timezone.utc).isoformat()
    if fmt == "langgraph":
        records, coverage, selection = _langgraph(path)
    else:
        rows, coverage = load_with_coverage(str(path), fmt)
        selection = {"rules": "scan-0.8.1"}
        records = []
        for row in rows:
            namespace = row.inventory_namespace
            if row.store == "sqlite":
                namespace = (row.metadata["table"], row.metadata["column"])
            source = Path(row.source).relative_to(path).as_posix() if directory else path.name
            records.append(_record(source, row.store, namespace, row.native_key,
                                   row.inventory_locator or row.id, row.content, row.created_at))
    manifest = {
        "schema": SCHEMA, "observed_at": observed_at,
        "boundary": {"path": str(path), "host": socket.gethostname(), "scope": scope,
                     "kind": "directory" if directory else "file", "format": fmt,
                     "selection": selection},
        "coverage": {"status": coverage.status, "records": coverage.records,
                     "selected_sources": coverage.selected_sources, "opened_sources": coverage._opened_sources,
                     "complete_sources": coverage.complete_sources, "issue_counts": dict(coverage.issue_counts)},
        "records": sorted(records, key=lambda row: (row["source"], row["store"], row["namespace"],
                          row["key"] or "", row["revision"], row["locator"])),
    }
    validate(manifest)
    return manifest


def validate(manifest):
    _object(manifest, ("schema", "observed_at", "boundary", "coverage", "records"))
    _require(manifest["schema"] == SCHEMA, "unsupported inventory schema")
    _timestamp(manifest["observed_at"])
    boundary = manifest["boundary"]
    _object(boundary, ("path", "host", "scope", "kind", "format", "selection"))
    _require(all(_text(boundary[k]) for k in ("path", "host", "scope", "format", "kind"))
             and boundary["format"] in FORMATS and boundary["kind"] in ("file", "directory"),
             "invalid source boundary")
    path_class = PurePosixPath if boundary["path"].startswith("/") else PureWindowsPath
    root = path_class(boundary["path"])
    _require(root.is_absolute() and ".." not in root.parts, "invalid source path")
    if boundary["format"] == "langgraph":
        _export_selection(boundary["selection"])
    else:
        _require(boundary["selection"] == {"rules": "scan-0.8.1"}, "unknown selection rules")
    rows = manifest["records"]
    _require(isinstance(rows, list), "invalid records")
    for row in rows:
        _object(row, ("source", "store", "namespace", "key", "basis", "locator", "content",
                      "revision", "store_timestamp"))
        _require(_text(row["store"]) and row["store"] in STORES and _namespace(row["namespace"])
                 and _text(row["source"]) and _text(row["locator"])
                 and isinstance(row["content"], str) and row["revision"] == _revision(row["content"])
                 and (row["store_timestamp"] is None or _text(row["store_timestamp"])),
                 "invalid record or content revision")
        source = path_class(row["source"])
        _require(bool(source.parts) and not source.anchor and ".." not in source.parts
                 and (boundary["kind"] == "directory" or source == path_class(root.name)),
                 "invalid record source")
        fmt = boundary["format"]
        _require(fmt == "auto" and row["store"] != "langgraph"
                 or row["store"] == ("mcp-memory" if fmt == "mcp" else fmt), "record outside format")
        if row["key"] is None:
            _require(row["store"] in WEAK_BASIS and row["basis"] == WEAK_BASIS[row["store"]],
                     "invalid weak identity")
        else:
            _require(_text(row["key"]) and row["basis"] == "native_key"
                     and row["store"] in ("mem0", "json", "langgraph"), "invalid native key")
        if row["store"] == "langgraph":
            _require(row["namespace"] in boundary["selection"]["namespaces"], "out-of-scope namespace")
    cov = manifest["coverage"]
    _object(cov, ("status", "records", "selected_sources", "opened_sources", "complete_sources", "issue_counts"))
    _require(all(type(cov[k]) is int and cov[k] >= 0 for k in
                 ("records", "selected_sources", "opened_sources", "complete_sources")),
             "invalid coverage counters")
    selected, opened, complete = (cov[k] for k in ("selected_sources", "opened_sources", "complete_sources"))
    issues = cov["issue_counts"]
    _require(isinstance(issues, dict) and all(k in REASONS and type(v) is int and v > 0
             for k, v in issues.items()), "invalid coverage reasons")
    _require(complete <= opened <= selected and cov["records"] == len(rows) and (opened or not rows)
             and (issues or selected == complete)
             and len({r["source"] for r in rows}) <= opened, "contradictory coverage counters")
    if issues:
        _require(selected > complete or set(issues) == {"directory_unreadable"},
                 "coverage reasons without an incomplete source")
        _require(selected - complete <= sum(issues.values()), "missing coverage reasons")
    if boundary["kind"] == "file":
        _require(selected == 1 and "directory_unreadable" not in issues,
                 "invalid single-source coverage")
    expected = ("partial" if opened else "failed") if issues else ("complete" if selected else "no_sources")
    _require(cov["status"] == expected, "contradictory coverage status")


def publish(path, data):
    """Stage private bytes in the destination directory, then atomically link without replacement."""
    path = Path(path)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".memwall-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(data, stream, sort_keys=True, indent=2, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
    finally:
        os.unlink(temporary)


def snapshot(path, fmt, scope, out):
    source = Path(path).resolve()
    target = Path(out).resolve()
    _require(source != target and not (source.is_dir() and source in target.parents),
             "choose a new output file outside the selected source")
    manifest = capture(source, fmt, scope)
    publish(out, manifest)
    return manifest
