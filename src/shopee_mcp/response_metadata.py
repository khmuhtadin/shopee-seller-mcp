"""Explicit, source-reviewed exceptions to the ordinary response envelope."""
import json
import re

from jsonschema import Draft202012Validator


def validate_response_metadata(endpoint):
    schema = endpoint["response_schema"]
    if "error_message_field" in endpoint and endpoint["error_message_field"] not in ("msg", "message", "error_msg", "mesage"):
        raise ValueError("Unsupported alternate error message field")
    if "business_status" in endpoint:
        status = endpoint["business_status"]
        if not isinstance(status, dict) or set(status) != {"code_field", "message_field", "success_value"}:
            raise ValueError("Invalid business status metadata")
        properties = schema.get("properties", {})
        if (endpoint["response_key"] is not None or type(status["success_value"]) is not int
                or not isinstance(status["code_field"], str) or not isinstance(status["message_field"], str)
                or properties.get(status["code_field"], {}).get("type") != "integer"
                or properties.get(status["message_field"], {}).get("type") != "string"):
            raise ValueError("Business status must refer to documented root integer/string fields")
        if not Draft202012Validator(properties[status["code_field"]]).is_valid(status["success_value"]):
            raise ValueError("Success value must satisfy the documented business code schema")
    for metadata_key in ("embedded_json_paths", "batch_failure_paths"):
        if metadata_key not in endpoint:
            continue
        paths = endpoint[metadata_key]
        if not isinstance(paths, list) or any(not isinstance(path, str) for path in paths) or len(set(paths)) != len(paths):
            raise ValueError("Invalid embedded JSON paths")
        for path in paths:
            if not re.fullmatch(r"(?:/(?:[A-Za-z0-9_]+|\*))+", path):
                raise ValueError("Invalid embedded JSON path")
            node = schema
            for token in path.split("/")[1:]:
                if token == "*" and node.get("type") == "array":
                    node = node["items"]
                elif node.get("type") == "object" and token in node.get("properties", {}):
                    node = node["properties"][token]
                else:
                    raise ValueError("Embedded JSON path must match response schema")
            allowed_types = ("string", "array") if metadata_key == "batch_failure_paths" else ("string",)
            if node.get("type") not in allowed_types:
                raise ValueError("Response path has an unsupported terminal type")


def sanitize_embedded_json(data, paths, sanitizer):
    """Preserve string wire shape while sanitizing the documented JSON within it."""
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate embedded JSON key")
            result[key] = value
        return result

    def invalid_constant(_):
        raise ValueError("Nonfinite embedded JSON")

    def visit(value, tokens):
        if not tokens:
            parsed = json.loads(value, object_pairs_hook=unique, parse_constant=invalid_constant)
            if not isinstance(parsed, (dict, list)):
                raise ValueError("Embedded JSON must be an object or array")
            return json.dumps(sanitizer(parsed), ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        head, *tail = tokens
        if head == "*" and isinstance(value, list):
            return [visit(child, tail) for child in value]
        if isinstance(value, dict) and head in value:
            return {key: visit(child, tail) if key == head else child for key, child in value.items()}
        return value  # Optional documented fields may be absent.

    for path in paths:
        data = visit(data, path.split("/")[1:])
    return data


def has_batch_failure(data, paths):
    def values(value, tokens):
        if not tokens:
            yield value
        elif tokens[0] == "*" and isinstance(value, list):
            for child in value:
                yield from values(child, tokens[1:])
        elif isinstance(value, dict) and tokens[0] in value:
            yield from values(value[tokens[0]], tokens[1:])
    return any(value for path in paths for value in values(data, path.split("/")[1:]))
