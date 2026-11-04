"""Offline schema utilities; callers must supply endpoint-specific review."""
from copy import deepcopy


def clean_schema(schema, *, request, name=""):
    """Strip raw annotations and normalize reviewed64-bit ID fields.

    This utility does not resolve placeholder/ambiguous fields, infer effects,
    impose endpoint semantics, or publish a candidate.
    """
    result = {key: deepcopy(value) for key, value in schema.items() if key != "x-documentation"}
    if result.get("type") == "object":
        result["additionalProperties"] = not request
        result["properties"] = {key: clean_schema(value, request=request, name=key)
                                for key, value in result.get("properties", {}).items()}
    if result.get("type") == "array":
        result["items"] = clean_schema(result["items"], request=request, name=name)
    if result.get("x-wire-int64") and (name.endswith("_id") or name.endswith("_id_list")):
        result.pop("x-wire-int64")
        result.update({"x-wire-integer": True, "pattern": r"^(0|[1-9][0-9]*)$"})
    if result.get("type") == "integer" and "minimum" not in result:
        result.update(minimum=-(2**53 - 1), maximum=2**53 - 1)
    return result
