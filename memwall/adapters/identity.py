"""Identity fields explicitly supplied by JSON memory producers."""
import json


def json_identity(item):
    if not isinstance(item, dict):
        return None, ()
    scope_fields = ("project", "project_id", "namespace", "user_id", "agent_id", "run_id", "app_id")
    namespace = tuple(field + "=" + json.dumps(item[field], sort_keys=True, ensure_ascii=True)
                      for field in scope_fields if field in item)
    native = item.get("id")
    return (native if isinstance(native, str) and native else None), namespace
