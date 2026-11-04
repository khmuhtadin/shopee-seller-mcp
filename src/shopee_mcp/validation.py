"""Strict MCP inputs and explicit lossless wire conversion."""
from copy import deepcopy
import re

from .constraints import ConstraintViolation, enforce_constraint
from .schema_validation import ExactDraft202012Validator

SUBJECT_IDS = {"shop_id", "merchant_id", "supplier_id", "user_id", "principal_id"}
RESERVED = {"partner_id", "partner_key", "access_token", "refresh_token", "timestamp", "sign"} | SUBJECT_IDS


class InputError(ValueError):
    pass


def parameter_aliases(endpoint):
    """Only reviewed target-ID aliases may map to credential-reserved names.

    A body shop_id is a business field, not the context's authentication query
    shop_id. Query aliases must additionally avoid the actual signing fields.
    """
    aliases = endpoint.get("parameter_aliases", {})
    if not isinstance(aliases, dict):
        raise InputError("Invalid parameter aliases")
    properties = endpoint["input_schema"].get("properties", {})
    auth_fields = {"partner_id", "timestamp", "sign"}
    if endpoint["auth_strategy"] != "public":
        auth_fields.update({"access_token", endpoint["auth_strategy"] + "_id"})
    request_encoding = (
        endpoint.get("binary_request_encoding", "json")
        if endpoint["encoding"] == "binary"
        else endpoint["encoding"]
    )
    destinations = set()
    for source, target in aliases.items():
        if (not isinstance(target, str) or target not in SUBJECT_IDS
                or source != "target_" + target or source not in properties
                or target in properties or target in destinations
                or endpoint["encoding"] not in {"query", "json", "binary", "multipart"}
                or (request_encoding == "query" and target in auth_fields)):
            raise InputError("Invalid or authentication-colliding parameter alias")
        destinations.add(target)
    return aliases


def tool_input_schema(endpoint, context):
    properties = {
        "context": {"type": "string", "const": context},
        "request": endpoint["input_schema"],
        "output": {"type": "object", "additionalProperties": False, "properties": {
            "fields": {"type": "array", "minItems": 1, "uniqueItems": True, "items": {
                "type": "string", "enum": sorted(endpoint["response_schema"].get("properties", {}))}}
        }},
    }
    return {"type": "object", "properties": properties, "required": ["request"], "additionalProperties": False}


def validate_arguments(endpoint, arguments, context, *, clock=None):
    schema = tool_input_schema(endpoint, context)
    if not ExactDraft202012Validator(schema).is_valid(arguments):
        # jsonschema's default message includes rejected values. Never echo it.
        raise InputError("invalid_arguments: check the tool input schema")
    request = deepcopy(arguments["request"])
    constraint_request = to_wire(request, endpoint["input_schema"])
    for constraint in endpoint.get("constraints", []):
        try:
            enforce_constraint(constraint, constraint_request, clock=clock)
        except ConstraintViolation as error:
            raise InputError(f"invalid_arguments: {error}") from None
    return request, arguments.get("output", {})


def to_wire(value, schema):
    if value is None:
        return value
    if schema.get("x-wire-uint64"):
        if (type(value) is not str or not re.fullmatch(r"0|[1-9][0-9]*", value)
                or int(value) > 2**64 - 1):
            raise InputError("invalid_arguments: uint64 value must be a canonical decimal string within range")
        return int(value)
    if schema.get("x-wire-int64"):
        if (type(value) is not str
                or not re.fullmatch(r"0|-?[1-9][0-9]*", value)
                or not -(2**63) <= int(value) <= 2**63 - 1):
            raise InputError("invalid_arguments: int64 value must be a canonical decimal string within range")
        return int(value)
    if schema.get("x-wire-integer"):
        if not isinstance(value, str) or not re.fullmatch(r"0|[1-9][0-9]*", value) or int(value) > 2**63 - 1:
            raise InputError("invalid_arguments: int64 identifier must be a decimal string within range")
        return int(value)
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        return {key: to_wire(item, properties.get(key, {})) for key, item in value.items()}
    if isinstance(value, list):
        return [to_wire(item, schema.get("items", {})) for item in value]
    return value


def from_wire(value, schema):
    if value is None:
        return None
    if schema.get("x-wire-uint64"):
        if (type(value) is not int
                and not (type(value) is str and re.fullmatch(r"0|[1-9][0-9]*", value))):
            raise InputError("invalid_response: value is not a lossless uint64")
        if not 0 <= int(value) <= 2**64 - 1:
            raise InputError("invalid_response: value outside uint64 range")
        return str(value)
    if schema.get("x-wire-int64"):
        if (type(value) is not int
                and not (type(value) is str and re.fullmatch(r"0|-?[1-9][0-9]*", value))):
            raise InputError("invalid_response: value is not a lossless int64")
        if not -(2**63) <= int(value) <= 2**63 - 1:
            raise InputError("invalid_response: value outside int64 range")
        return str(value)
    if schema.get("x-wire-integer"):
        if type(value) is not int and not (type(value) is str and re.fullmatch(r"0|[1-9][0-9]*", value)):
            raise InputError("invalid_response: identifier is not a lossless integer")
        if not 0 <= int(value) <= 2**63 - 1:
            raise InputError("invalid_response: identifier outside int64 range")
        return str(value)
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        return {key: from_wire(item, properties.get(key, {})) for key, item in value.items()}
    if isinstance(value, list):
        return [from_wire(item, schema.get("items", {})) for item in value]
    # Preserve precision of new, undocumented integer fields at the JS boundary.
    if type(value) is int and abs(value) > 2**53 - 1 and not schema:
        return str(value)
    return value
