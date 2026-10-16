"""Operator-owned contracts for bounded, schema-aware MCP memory inspection.

Profiles describe trusted backend behavior. Incoming tool names, annotations
and origin claims never select an exemption from inspection on their own.
"""
from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field
from types import MappingProxyType


MAX_REQUEST_BYTES = 1024 * 1024
MAX_DEPTH = 32
_TOOL_NAME = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")
_EXTRACTORS = {"entities", "observations", "relations", "read", "maintenance"}
_REFERENCE_TOOLS = {
    "create_entities": "entities", "add_observations": "observations",
    "create_relations": "relations", "read_graph": "read",
    "search_nodes": "read", "open_nodes": "read",
    "delete_entities": "maintenance", "delete_relations": "maintenance",
    "delete_observations": "maintenance",
}


class ContractError(ValueError):
    """The request cannot be inspected under the selected local contract."""


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ContractError("duplicate JSON object key")
        result[key] = value
    return result


def _constant(value):
    raise ContractError("non-finite JSON number")


def _float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ContractError("non-finite JSON number")
    return number


def strict_loads(raw):
    try:
        if isinstance(raw, (bytes, bytearray)):
            raw = raw.decode("utf-8")  # MCP wire frames must not auto-detect UTF-16/32.
        return json.loads(raw, object_pairs_hook=_pairs, parse_constant=_constant, parse_float=_float)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ContractError("invalid or ambiguous JSON") from exc


def validate_depth(value):
    """Check containers iteratively before any recursive inspection."""
    stack = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        if depth > MAX_DEPTH:
            raise ContractError(f"JSON nesting exceeds {MAX_DEPTH}")
        if isinstance(item, dict):
            stack.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list):
            stack.extend((v, depth + 1) for v in item)


def _object(value, keys, path):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ContractError(f"{path} requires exactly: {', '.join(keys)}")
    return value


def _array(value, path):
    if not isinstance(value, list):
        raise ContractError(f"{path} must be an array")
    return value


def _text(value, path):
    if not isinstance(value, str):
        raise ContractError(f"{path} must be a string")
    return value


def _texts(value, path):
    return [_text(v, f"{path}/{i}") for i, v in enumerate(_array(value, path))]


@dataclass
class InspectionGroup:
    key: tuple
    fields: list = field(default_factory=list)

    @property
    def content(self):
        # Repeated identity fields must not interrupt consecutive observation
        # fragments from the same entity. Keep every persisted field inspectable.
        context = [text for path, text in self.fields if not path.rsplit("/", 1)[-1].isdigit()]
        content = [text for path, text in self.fields if path.rsplit("/", 1)[-1].isdigit()]
        return "\n".join(context + content)

    @property
    def field_paths(self):
        return [path for path, text in self.fields]


class Profile:
    def __init__(self, name, tools, version=1):
        if type(version) is not int or version != 1:
            raise ContractError("profile version must be 1")
        if not isinstance(name, str) or not name or len(name) > 128:
            raise ContractError("profile name must be a nonempty string up to 128 characters")
        if not isinstance(tools, dict) or not tools:
            raise ContractError("profile tools must be a nonempty object")
        for tool, extractor in tools.items():
            if not isinstance(tool, str) or not _TOOL_NAME.fullmatch(tool):
                raise ContractError("invalid profile tool name")
            if not isinstance(extractor, str) or extractor not in _EXTRACTORS:
                raise ContractError("unsupported profile extractor")
        self.name = name
        self.version = version
        self.tools = MappingProxyType(dict(tools))

    def extract(self, tool, arguments):
        kind = self.tools.get(tool)
        if kind is None:
            raise ContractError("tool is not declared in the selected profile")
        if not isinstance(arguments, dict):
            raise ContractError("arguments must be an object")
        validate_depth(arguments)
        if kind in {"read", "maintenance"}:
            self._validate_passthrough(tool, arguments)
            return []

        collection = {"entities": "entities", "observations": "observations",
                      "relations": "relations"}[kind]
        _object(arguments, (collection,), "arguments")
        grouped = {}
        for i, item in enumerate(_array(arguments[collection], collection)):
            path = f"/{collection}/{i}"
            if kind == "entities":
                _object(item, ("name", "entityType", "observations"), path)
                name = _text(item["name"], path + "/name")
                entity_type = _text(item["entityType"], path + "/entityType")
                texts = _texts(item["observations"], path + "/observations")
                key = ("entity", name)
                fields = [(path + "/name", name), (path + "/entityType", entity_type)]
                fields.extend((f"{path}/observations/{j}", text) for j, text in enumerate(texts))
            elif kind == "observations":
                _object(item, ("entityName", "contents"), path)
                name = _text(item["entityName"], path + "/entityName")
                texts = _texts(item["contents"], path + "/contents")
                key = ("entity", name)
                fields = [(path + "/entityName", name)]
                fields.extend((f"{path}/contents/{j}", text) for j, text in enumerate(texts))
            else:
                _object(item, ("from", "relationType", "to"), path)
                fields = [(path + "/" + key, _text(item[key], path + "/" + key))
                          for key in ("from", "relationType", "to")]
                key = ("relation",) + tuple(text for _, text in fields)
            group = grouped.setdefault(key, InspectionGroup(key))
            group.fields.extend(fields)
        return list(grouped.values())

    @staticmethod
    def _validate_passthrough(tool, arguments):
        # Validate known reference schemas without scanning deletion targets as
        # inserted instructions. Custom read/maintenance shapes are operator-owned.
        if tool == "read_graph":
            _object(arguments, (), "arguments")
        elif tool == "search_nodes":
            _object(arguments, ("query",), "arguments")
            _text(arguments["query"], "/query")
        elif tool in {"open_nodes", "delete_entities"}:
            key = "names" if tool == "open_nodes" else "entityNames"
            _object(arguments, (key,), "arguments")
            _texts(arguments[key], "/" + key)
        elif tool == "delete_relations":
            _object(arguments, ("relations",), "arguments")
            for i, relation in enumerate(_array(arguments["relations"], "/relations")):
                path = f"/relations/{i}"
                _object(relation, ("from", "to", "relationType"), path)
                for key in relation:
                    _text(relation[key], path + "/" + key)
        elif tool == "delete_observations":
            _object(arguments, ("deletions",), "arguments")
            for i, deletion in enumerate(_array(arguments["deletions"], "/deletions")):
                path = f"/deletions/{i}"
                _object(deletion, ("entityName", "observations"), path)
                _text(deletion["entityName"], path + "/entityName")
                _texts(deletion["observations"], path + "/observations")


def load_profile(name_or_path):
    if name_or_path == "reference-memory":
        return Profile("reference-memory", _REFERENCE_TOOLS)
    with open(name_or_path, "rb") as fh:
        raw = fh.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        raise ContractError("profile exceeds 1 MiB")
    # Local JSON profiles may have the UTF-8 BOM produced by Windows editors.
    try:
        data = strict_loads(raw.decode("utf-8-sig"))
    except UnicodeError as exc:
        raise ContractError("profile must be UTF-8 JSON") from exc
    validate_depth(data)
    _object(data, ("version", "name", "tools"), "profile")
    return Profile(data["name"], data["tools"], data["version"])
