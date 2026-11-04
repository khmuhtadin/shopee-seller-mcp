"""Compile explicit endpoint reviews into pinned, verified definitions offline."""

from __future__ import annotations

import argparse
from copy import deepcopy
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import sys

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

from .catalog import Catalog, CatalogError
from .import_structured import StructuredImportError, normalize_document


class ReviewedCompileError(ValueError):
    """A review record cannot safely produce a verified endpoint."""


_MAX_REVIEW_BYTES = 4 * 1024 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}")
_TEST_FILE = re.compile(r"test_[A-Za-z0-9_.-]+\.py")
_TOP_LEVEL = {
    "api_name",
    "source_sha256",
    "decisions",
    "request_schema",
    "response_schema",
    "response_key",
    "contract_fixtures",
    "tests",
    "rationale",
    "resolved_unresolved",
}
_DECISION_REQUIRED = {
    "description",
    "auth_strategy",
    "encoding",
    "effects",
    "idempotent",
    "retry_policy",
    "query_arrays",
    "constraints",
    "sensitive_paths",
    "batch_failure_fields",
    "pagination_fields",
    "permissions",
    "regions",
}
_DECISION_OPTIONAL = {"parameter_aliases", "upload_fields", "download_mime_types",
                      "download_mime_policy", "binary_request_encoding"}
_RATIONALE_KEYS = {"authentication", "encoding", "effects", "schema_constraints", "fixtures"}
_FIXTURE_KEYS = {
    "request",
    "expected_serialization",
    "raw_response",
    "expected_converted_response",
}


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ReviewedCompileError("Duplicate JSON key")
        result[key] = value
    return result


def _reject_nonfinite(_value):
    raise ReviewedCompileError("Nonfinite numbers are invalid JSON")


def _read_bounded(path):
    if path.is_symlink() or not path.is_file():
        raise ReviewedCompileError("Review input must be a regular non-symlink file")
    try:
        with path.open("rb") as stream:
            raw = stream.read(_MAX_REVIEW_BYTES + 1)
    except OSError:
        raise ReviewedCompileError("Unable to read review input") from None
    if len(raw) > _MAX_REVIEW_BYTES:
        raise ReviewedCompileError("Review input exceeds size limit")
    return raw


def load_review(path):
    """Load one bounded review JSON file with strict JSON semantics."""
    try:
        value = json.loads(
            _read_bounded(Path(path)),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_nonfinite,
        )
    except ReviewedCompileError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, TypeError):
        raise ReviewedCompileError("Invalid review JSON") from None
    if not isinstance(value, dict):
        raise ReviewedCompileError("Review must be a JSON object")
    return value


def _ensure_json_value(value, location="review"):
    if value is None or isinstance(value, (str, bool)):
        return
    if type(value) is int:
        return
    if type(value) is float:
        if not math.isfinite(value):
            raise ReviewedCompileError(f"Nonfinite number at {location}")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _ensure_json_value(item, f"{location}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ReviewedCompileError(f"Non-string object key at {location}")
            _ensure_json_value(item, f"{location}.{key}")
        return
    raise ReviewedCompileError(f"Non-JSON value at {location}")


def _exact_keys(value, expected, location):
    if not isinstance(value, dict):
        raise ReviewedCompileError(f"{location} must be an object")
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        raise ReviewedCompileError(
            f"Invalid {location} keys: missing={missing}, unknown={unknown}"
        )


def _nonempty_string(value, location):
    if not isinstance(value, str) or not value.strip():
        raise ReviewedCompileError(f"{location} must be a nonempty string")


def _string_list(value, location):
    if (
        not isinstance(value, list)
        or any(not isinstance(item, str) or not item for item in value)
        or len(value) != len(set(value))
    ):
        raise ReviewedCompileError(f"{location} must be a list of unique nonempty strings")


def _validate_decisions(decisions):
    if not isinstance(decisions, dict):
        raise ReviewedCompileError("decisions must be an object")
    actual = set(decisions)
    missing = _DECISION_REQUIRED - actual
    unknown = actual - _DECISION_REQUIRED - _DECISION_OPTIONAL
    if missing or unknown:
        raise ReviewedCompileError(
            f"Invalid decisions keys: missing={sorted(missing)}, unknown={sorted(unknown)}"
        )
    _nonempty_string(decisions["description"], "decisions.description")
    for name in ("auth_strategy", "encoding", "effects"):
        _nonempty_string(decisions[name], f"decisions.{name}")
    if type(decisions["idempotent"]) is not bool:
        raise ReviewedCompileError("decisions.idempotent must be a boolean")
    if not isinstance(decisions["query_arrays"], dict):
        raise ReviewedCompileError("decisions.query_arrays must be an object")
    if any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in decisions["query_arrays"].items()
    ):
        raise ReviewedCompileError("decisions.query_arrays entries must be strings")
    if not isinstance(decisions["constraints"], list) or any(
        not isinstance(item, dict) for item in decisions["constraints"]
    ):
        raise ReviewedCompileError("decisions.constraints must contain objects")
    for name in (
        "sensitive_paths",
        "batch_failure_fields",
        "pagination_fields",
        "permissions",
        "regions",
    ):
        _string_list(decisions[name], f"decisions.{name}")
    retry = decisions["retry_policy"]
    _exact_keys(retry, {"max_attempts", "statuses", "errors"}, "retry_policy")
    if type(retry["max_attempts"]) is not int:
        raise ReviewedCompileError("retry_policy.max_attempts must be an integer")
    if not isinstance(retry["statuses"], list) or any(
        type(status) is not int for status in retry["statuses"]
    ):
        raise ReviewedCompileError("retry_policy.statuses must contain integers")
    _string_list(retry["errors"], "retry_policy.errors")


def _validate_rationale(review, candidate):
    rationale = review["rationale"]
    _exact_keys(rationale, _RATIONALE_KEYS, "rationale")
    for name, explanation in rationale.items():
        _nonempty_string(explanation, f"rationale.{name}")
    resolved = review["resolved_unresolved"]
    if not isinstance(resolved, dict):
        raise ReviewedCompileError("resolved_unresolved must be an object")
    expected = set(candidate["unresolved"])
    if set(resolved) != expected:
        raise ReviewedCompileError("resolved_unresolved must exactly cover candidate reasons")
    for reason, explanation in resolved.items():
        if reason == "*":
            raise ReviewedCompileError("Wildcard unresolved resolution is not allowed")
        _nonempty_string(explanation, f"resolved_unresolved[{reason!r}]")


def _validate_typed_fields(schema, location, *, request):
    if not isinstance(schema, dict):
        raise ReviewedCompileError(f"{location} must be an object schema")
    if request and schema.get("not") == {}:
        raise ReviewedCompileError(f"Reject-all placeholder at {location}")
    properties = schema.get("properties")
    if properties is not None:
        if not isinstance(properties, dict):
            raise ReviewedCompileError(f"Invalid properties at {location}")
        for name, field in properties.items():
            if not isinstance(name, str) or not isinstance(field, dict) or "type" not in field:
                raise ReviewedCompileError(f"Known field lacks an explicit type at {location}.{name}")
            _validate_typed_fields(field, f"{location}.{name}", request=request)
    if schema.get("type") == "array":
        items = schema.get("items")
        if not isinstance(items, dict) or "type" not in items:
            raise ReviewedCompileError(f"Array items lack an explicit type at {location}")
        _validate_typed_fields(items, f"{location}[]", request=request)


def _validate_fixtures(fixtures):
    if not isinstance(fixtures, list) or not fixtures:
        raise ReviewedCompileError("contract_fixtures must be a nonempty list")
    for index, fixture in enumerate(fixtures):
        _exact_keys(fixture, _FIXTURE_KEYS, f"contract_fixtures[{index}]")
        for field in _FIXTURE_KEYS:
            if not isinstance(fixture[field], dict):
                raise ReviewedCompileError(
                    f"contract_fixtures[{index}].{field} must be an object"
                )


def _validate_tests(tests, root):
    _string_list(tests, "tests")
    if not tests:
        raise ReviewedCompileError("tests must name at least one contract test")
    test_root = root.parent / "tests"
    if test_root.is_symlink() or not test_root.is_dir():
        raise ReviewedCompileError("Local tests directory is missing or unsafe")
    resolved_root = test_root.resolve()
    for value in tests:
        if "\\" in value:
            raise ReviewedCompileError("Contract test path must use safe POSIX separators")
        relative = PurePosixPath(value)
        if (
            relative.is_absolute()
            or not relative.parts
            or any(part in {"", ".", ".."} for part in relative.parts)
            or not _TEST_FILE.fullmatch(relative.name)
        ):
            raise ReviewedCompileError("Invalid contract test path")
        path = test_root.joinpath(*relative.parts)
        try:
            resolved = path.resolve(strict=True)
        except OSError:
            raise ReviewedCompileError("Contract test path does not exist") from None
        if path.is_symlink() or not resolved.is_relative_to(resolved_root) or not resolved.is_file():
            raise ReviewedCompileError("Contract test path escapes local tests")


def _source_reference(candidate):
    source = candidate["source"]
    return {
        "file": source["file"],
        "url": source["url"],
        "sha256": source["sha256"],
        "captured_at": source["captured_at"],
    }


def _runtime_validate(endpoint, root):
    validator = Catalog.__new__(Catalog)
    validator.root = root
    try:
        validator._validate_endpoint(endpoint)
    except (CatalogError, KeyError, TypeError, ValueError, SchemaError):
        raise ReviewedCompileError("Invalid reviewed runtime metadata") from None


def compile_review(review, *, source, catalog_root):
    """Compile a complete review without writing or activating an endpoint."""
    try:
        _ensure_json_value(review)
        _exact_keys(review, _TOP_LEVEL, "review")
        root = Path(catalog_root).resolve()
        source_sha256 = review["source_sha256"]
        if not isinstance(source_sha256, str) or not _SHA256.fullmatch(source_sha256):
            raise ReviewedCompileError("source_sha256 must be a lowercase SHA-256")
        candidate = normalize_document(
            Path(source), catalog_root=root, expected_sha256=source_sha256
        )
        if review["api_name"] != candidate["api_name"]:
            raise ReviewedCompileError("Review API identity differs from official source")
        _validate_decisions(review["decisions"])
        _validate_rationale(review, candidate)
        request_schema = review["request_schema"]
        response_schema = review["response_schema"]
        Draft202012Validator.check_schema(request_schema)
        Draft202012Validator.check_schema(response_schema)
        _validate_typed_fields(request_schema, "request_schema", request=True)
        _validate_typed_fields(response_schema, "response_schema", request=False)
        if review["response_key"] is not None:
            _nonempty_string(review["response_key"], "response_key")
        _validate_fixtures(review["contract_fixtures"])
        _validate_tests(review["tests"], root)

        decisions = review["decisions"]
        endpoint = {
            "api_name": candidate["api_name"],
            "module": candidate["api_name"].split(".")[1],
            "tool_name": candidate["tool_name"],
            "method": candidate["method"],
            "path": candidate["path"],
            "description": decisions["description"],
            "input_schema": deepcopy(request_schema),
            "response_schema": deepcopy(response_schema),
            "response_key": review["response_key"],
            "encoding": decisions["encoding"],
            "auth_strategy": decisions["auth_strategy"],
            "effects": decisions["effects"],
            "idempotent": decisions["idempotent"],
            "retry_policy": deepcopy(decisions["retry_policy"]),
            "query_arrays": deepcopy(decisions["query_arrays"]),
            "constraints": deepcopy(decisions["constraints"]),
            "sensitive_paths": deepcopy(decisions["sensitive_paths"]),
            "batch_failure_fields": deepcopy(decisions["batch_failure_fields"]),
            "pagination_fields": deepcopy(decisions["pagination_fields"]),
            "permissions": deepcopy(decisions["permissions"]),
            "regions": deepcopy(decisions["regions"]),
        }
        for name in sorted(_DECISION_OPTIONAL):
            if name in decisions:
                endpoint[name] = deepcopy(decisions[name])
        endpoint.update(
            contract_fixtures=deepcopy(review["contract_fixtures"]),
            source=_source_reference(candidate),
            review_status="verified",
            implementation="implemented",
            tests=deepcopy(review["tests"]),
        )
        _runtime_validate(endpoint, root)
        return endpoint
    except ReviewedCompileError:
        raise
    except StructuredImportError as error:
        raise ReviewedCompileError(f"Invalid official source: {error}") from None
    except (KeyError, TypeError, ValueError, RecursionError, SchemaError):
        raise ReviewedCompileError("Invalid reviewed endpoint definition") from None


def write_reviewed(review, *, source, catalog_root):
    """Compile and exclusively create one catalog endpoint definition."""
    try:
        root = Path(catalog_root).resolve()
        endpoint = compile_review(review, source=source, catalog_root=root)
        payload = (
            json.dumps(endpoint, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        ).encode()
        directory = root / "endpoints"
        if directory.is_symlink():
            raise ReviewedCompileError("Endpoint directory must not be a symlink")
        directory.mkdir(exist_ok=True)
        filename = f"{endpoint['api_name']}.json"
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            fd = os.open(
                filename,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=directory_fd,
            )
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(payload)
                    stream.flush()
                    os.fsync(stream.fileno())
            except BaseException:
                os.unlink(filename, dir_fd=directory_fd)
                raise
        finally:
            os.close(directory_fd)
        return directory / filename
    except ReviewedCompileError:
        raise
    except (OSError, TypeError, ValueError, KeyError):
        raise ReviewedCompileError("Unable to create exclusive endpoint definition") from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("review", type=Path)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--catalog", required=True, type=Path)
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--check", action="store_true", help="compile and print without writes (default)")
    action.add_argument("--write", action="store_true", help="exclusively create catalog/endpoints definition")
    args = parser.parse_args(argv)
    try:
        review = load_review(args.review)
        if args.write:
            path = write_reviewed(review, source=args.source, catalog_root=args.catalog)
            print(json.dumps({"endpoint": str(path)}, ensure_ascii=False))
        else:
            endpoint = compile_review(review, source=args.source, catalog_root=args.catalog)
            print(json.dumps(endpoint, ensure_ascii=False, indent=2, allow_nan=False))
        return 0
    except ReviewedCompileError as error:
        print(f"Compile refused: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
