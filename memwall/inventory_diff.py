"""Compare observations without deriving identity from text or record position."""
from collections import Counter, defaultdict

from .inventory_capture import validate


def _group(records):
    groups = defaultdict(list)
    for record in records:
        scope = (record["source"], record["store"], tuple(record["namespace"]))
        if record["key"] is None:
            identity = (*scope, "observation", record["revision"])
        else:
            identity = (*scope, "key", record["key"])
        groups[identity].append(record)
    return groups


def compare(before, after):
    for manifest in (before, after):
        validate(manifest)
    states = [manifest["coverage"]["status"] for manifest in (before, after)]
    reasons = set()
    for side, state in zip(("before", "after"), states):
        if state != "complete":
            reasons.add(side + "_" + state)
    counts = Counter(dict.fromkeys(("added", "changed", "unchanged", "absent_from_scope",
                                    "unresolved_identity", "presence_only", "count_difference"), 0))
    details = []
    if before["boundary"] != after["boundary"]:
        reasons.add("incompatible_boundary")
    else:
        left, right = (_group(m["records"]) for m in (before, after))
        for identity in sorted(left.keys() | right.keys()):
            old, new = left.get(identity, []), right.get(identity, [])
            if identity[3] == "observation":
                counts["unresolved_identity"] += max(len(old), len(new))
                status = "count_difference" if len(old) != len(new) else "unresolved_identity"
                if status == "count_difference":
                    counts[status] += 1
                details.append({"status": status, "before_observed": len(old),
                                "after_observed": len(new), "example": (new or old)[0]})
                continue
            if len(old) > 1 or len(new) > 1:
                status = "unresolved_identity"
                reasons.add("duplicate_key")
            elif old and new:
                status = "unchanged" if old[0]["revision"] == new[0]["revision"] else "changed"
            elif new and states[0] == "complete":
                status = "added"
            elif old and states[1] == "complete":
                status = "absent_from_scope"
            else:
                status = "presence_only"
            counts[status] += 1
            if status != "unchanged":
                details.append({"status": status, "before": old, "after": new})
    coverage_reasons = {side: manifest["coverage"]["issue_counts"]
                        for side, manifest in (("before", before), ("after", after))}
    summary = {"coverage_issues": coverage_reasons, "coverage": dict(zip(("before", "after"), states)), "counts": dict(counts),
               "reason_codes": sorted(reasons)}
    return summary, details
