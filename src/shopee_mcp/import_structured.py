"""Normalize saved first-party Shopee documentation into disabled candidates.

This module is deliberately offline. It accepts only JSON files below a
catalog's ``upstream`` directory and never publishes executable endpoint
definitions. ``--check`` is the default; ``--write`` exclusively creates
source-derived review artifacts below ``catalog/candidates``.
"""

from __future__ import annotations

import argparse
from datetime import date
from html.parser import HTMLParser
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import urlencode, urlsplit

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError


class StructuredImportError(ValueError):
    """A structured document cannot be normalized safely."""


_MAX_BYTES = 8 * 1024 * 1024
_PATH = re.compile(r"/api/v2/[A-Za-z0-9_]+(?:/[A-Za-z0-9_]+)+")
_FIELD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_TOOL = re.compile(r"[A-Za-z0-9_]{1,64}")
_METHODS = {1: "POST", 2: "GET"}
_SAFE_INTEGER = 9_007_199_254_740_991
_INT64_PATTERN = r"^(?:0|-?[1-9][0-9]*)$"
_DRAFT_STATES = {
    "review_status": "draft",
    "specification": "unverified",
    "implementation": "unimplemented",
    "exposure": "disabled",
    "verification": [],
}


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise StructuredImportError("Duplicate JSON key")
        result[key] = value
    return result


def _reject_nonfinite(_value):
    raise StructuredImportError("Nonfinite numbers are invalid JSON")


def _decode_json(value, *, field):
    if not isinstance(value, (str, bytes, bytearray)):
        raise StructuredImportError(f"{field} must be encoded JSON")
    try:
        return json.loads(
            value,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_nonfinite,
        )
    except StructuredImportError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, TypeError):
        raise StructuredImportError(f"Invalid JSON in {field}") from None


class _TextExtractor(HTMLParser):
    _BLOCKS = {
        "address", "article", "aside", "blockquote", "br", "div", "dl", "dt", "dd",
        "figcaption", "figure", "footer", "h1", "h2", "h3", "h4", "h5", "h6",
        "header", "hr", "li", "main", "nav", "ol", "p", "pre", "section", "table",
        "tbody", "td", "tfoot", "th", "thead", "tr", "ul",
    }

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.ignored_depth = 0

    def handle_starttag(self, tag, _attrs):
        tag = tag.lower()
        if tag in {"script", "style"}:
            self.ignored_depth += 1
        elif not self.ignored_depth and tag in self._BLOCKS:
            self.parts.append("\n")

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag.lower() in {"script", "style"}:
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in {"script", "style"}:
            if self.ignored_depth:
                self.ignored_depth -= 1
        elif not self.ignored_depth and tag in self._BLOCKS:
            self.parts.append("\n")

    def handle_data(self, data):
        if not self.ignored_depth:
            self.parts.append(data)


def _html_text(value):
    if value is None:
        return ""
    if not isinstance(value, str):
        raise StructuredImportError("Description must be a string or null")
    parser = _TextExtractor()
    try:
        parser.feed(value)
        parser.close()
    except (ValueError, RecursionError):
        raise StructuredImportError("Invalid description HTML") from None
    lines = []
    for line in "".join(parser.parts).splitlines():
        normalized = " ".join(line.split())
        if normalized:
            lines.append(normalized)
    return "\n".join(lines)


def _definition_text(value):
    if isinstance(value, str) and value.lstrip().startswith("{"):
        rich = _decode_json(value, field="define")
        if not isinstance(rich, dict) or not isinstance(rich.get("content"), str):
            raise StructuredImportError("Rich-text define must contain string content")
        return _html_text(rich["content"])
    return _html_text(value)


def _under_upstream(path, root, *, expect_directory=False):
    upstream = root / "upstream"
    if upstream.is_symlink():
        raise StructuredImportError("Catalog upstream directory must not be a symlink")
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        raise StructuredImportError("Upstream input does not exist") from None
    if not resolved.is_relative_to(upstream.resolve()):
        raise StructuredImportError("Input must be within catalog upstream")
    current = path
    while current != root and current.is_relative_to(root):
        if current.is_symlink():
            raise StructuredImportError("Upstream input must not use symlinks")
        current = current.parent
    if expect_directory:
        if not resolved.is_dir():
            raise StructuredImportError("Batch input must be a directory")
    elif not resolved.is_file():
        raise StructuredImportError("Upstream document must be a regular file")
    return resolved


def _read_bounded(path):
    try:
        with path.open("rb") as stream:
            raw = stream.read(_MAX_BYTES + 1)
    except OSError:
        raise StructuredImportError("Unable to read upstream document") from None
    if len(raw) > _MAX_BYTES:
        raise StructuredImportError("Upstream document exceeds size limit")
    return raw


def _catalog_identity(root, raw_api_name):
    manifest_path = root / "manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise StructuredImportError("Missing regular catalog manifest")
    manifest = _decode_json(_read_bounded(manifest_path), field="manifest.json")
    if not isinstance(manifest, dict) or not isinstance(manifest.get("entries"), list):
        raise StructuredImportError("Catalog manifest must contain entries")
    matches = []
    raw_names = []
    api_names = []
    for entry in manifest["entries"]:
        if not isinstance(entry, dict):
            raise StructuredImportError("Invalid catalog manifest entry")
        api_name = entry.get("api_name")
        source_name = entry.get("raw_name")
        if not isinstance(api_name, str) or not isinstance(source_name, str):
            raise StructuredImportError("Catalog manifest entry lacks API identity")
        parts = api_name.split(".")
        if (
            len(parts) != 3
            or parts[0] != "v2"
            or any(not part or not all(char.isalnum() or char == "_" for char in part) for part in parts[1:])
        ):
            raise StructuredImportError("Invalid canonical API name in catalog manifest")
        api_names.append(api_name)
        raw_names.append(source_name)
        if source_name == raw_api_name:
            matches.append(api_name)
    if len(api_names) != len(set(api_names)) or len(raw_names) != len(set(raw_names)):
        raise StructuredImportError("Catalog manifest contains duplicate API identities")
    if len(matches) != 1:
        raise StructuredImportError("Raw API name is not uniquely present in catalog manifest")
    api_name = matches[0]

    path = root / "tool-name-map.json"
    if path.is_symlink() or not path.is_file():
        raise StructuredImportError("Missing regular tool-name map")
    data = _decode_json(_read_bounded(path), field="tool-name-map.json")
    if not isinstance(data, dict):
        raise StructuredImportError("Tool-name map must be an object")
    name = data.get(api_name)
    if not isinstance(name, str) or not _TOOL.fullmatch(name):
        raise StructuredImportError("API is missing a valid existing tool name")
    values = list(data.values())
    if any(not isinstance(value, str) for value in values) or len(values) != len(set(values)):
        raise StructuredImportError("Tool-name map contains collisions")
    return api_name, name


def _documentation(node):
    required = node.get("required")
    if required is not None and not isinstance(required, str):
        raise StructuredImportError("Required clause must be a string or null")
    sample = node.get("sample")
    if sample is not None and not isinstance(sample, (str, int, float, bool)):
        raise StructuredImportError("Parameter sample must be scalar or null")
    raw_description = node.get("description")
    text = _html_text(raw_description)
    return text, {
        "type": node.get("type"),
        "required": required,
        "sample": sample,
        "description": raw_description,
    }


def _reject_schema(node):
    description, documentation = _documentation(node)
    schema = {"not": {}}
    if description:
        schema["description"] = description
    schema["x-documentation"] = documentation
    return schema


def _known_scalar(type_name, unresolved, location):
    if type_name == "string":
        return {"type": "string"}
    if type_name in {"boolean", "bool"}:
        return {"type": "boolean"}
    if type_name == "int32":
        return {"type": "integer", "minimum": -2_147_483_648, "maximum": 2_147_483_647}
    if type_name == "int64":
        return {"type": "string", "pattern": _INT64_PATTERN, "x-wire-int64": True}
    if type_name == "uint64":
        return {"type": "string", "pattern": "^(0|[1-9][0-9]*)$", "x-wire-uint64": True}
    if type_name == "timestamp":
        return {"type": "integer", "minimum": -_SAFE_INTEGER, "maximum": _SAFE_INTEGER}
    if type_name in {"float", "double"}:
        return {"type": "number"}
    if type_name == "int":
        unresolved.append(f"Integer width and bounds are unspecified at {location} (type int).")
        return {"type": "integer"}
    return None


def _field_schema(node, *, request, unresolved, location):
    type_name = node.get("type")
    if not isinstance(type_name, str) or not type_name:
        unresolved.append(f"Unknown or missing type at {location}.")
        return _reject_schema(node)
    children_present = "children" in node
    children = node.get("children")
    if children_present and not isinstance(children, list):
        unresolved.append(f"Contradictory children at {location}: children is not an array.")
        return _reject_schema(node)
    has_children = bool(children)

    is_array = type_name.endswith("[]")
    base_type = type_name[:-2] if is_array else type_name
    if base_type == "object":
        if not has_children:
            unresolved.append(f"Freeform or empty object at {location} requires review.")
            return _reject_schema(node)
        nested = _object_schema(children, request=request, unresolved=unresolved, location=location)
        core = {"type": "array", "items": nested} if is_array else nested
    else:
        if has_children:
            unresolved.append(f"Contradictory children on non-object field {location}.")
            return _reject_schema(node)
        scalar = _known_scalar(base_type, unresolved, location)
        if scalar is None:
            unresolved.append(f"Unknown type {type_name!r} at {location}.")
            return _reject_schema(node)
        core = {"type": "array", "items": scalar} if is_array else scalar

    description, documentation = _documentation(node)
    if description:
        core["description"] = description
    core["x-documentation"] = documentation
    return core


def _object_schema(nodes, *, request, unresolved, location):
    if not isinstance(nodes, list):
        raise StructuredImportError(f"{location} must be an array")
    schema = {"type": "object", "additionalProperties": False, "properties": {}, "required": []}
    duplicates = set()
    for index, node in enumerate(nodes):
        if not isinstance(node, dict):
            raise StructuredImportError(f"Invalid parameter node at {location}[{index}]")
        name = node.get("name")
        if not isinstance(name, str) or not _FIELD.fullmatch(name):
            raise StructuredImportError(f"Invalid parameter name at {location}[{index}]")
        child_location = f"{location}.{name}"
        if name in schema["properties"]:
            if name not in duplicates:
                unresolved.append(f"Duplicate parameter name at {child_location}.")
                duplicates.add(name)
            schema["properties"][name] = _reject_schema(node)
            schema["required"] = [item for item in schema["required"] if item != name]
            continue
        field = _field_schema(
            node,
            request=request,
            unresolved=unresolved,
            location=child_location,
        )
        schema["properties"][name] = field
        if request:
            required = node.get("required")
            if required in {"True", "yes"}:
                schema["required"].append(name)
            elif required == "False":
                pass
            else:
                unresolved.append(
                    f"Conditional or unknown required clause at {child_location}: {required!r}."
                )
    return schema


def _common_parameters(value, unresolved):
    raw = _decode_json(value, field="common_params")
    if not isinstance(raw, list):
        raise StructuredImportError("common_params must encode an array")
    normalized = []
    names = []
    seen = set()
    sign_descriptions = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise StructuredImportError(f"Invalid common parameter at index {index}")
        name = item.get("name")
        type_name = item.get("type")
        sample = item.get("sample")
        raw_description = item.get("description")
        if not isinstance(name, str) or not _FIELD.fullmatch(name) or not isinstance(type_name, str):
            raise StructuredImportError(f"Invalid common parameter at index {index}")
        if sample is not None and not isinstance(sample, (str, int, float, bool)):
            raise StructuredImportError(f"Invalid common parameter sample at index {index}")
        description = _html_text(raw_description)
        normalized.append(
            {
                "name": name,
                "type": type_name,
                "sample": sample,
                "description": description,
                "raw_description": raw_description,
            }
        )
        names.append(name)
        if name in seen:
            unresolved.append(f"Duplicate common parameter name {name!r}.")
        seen.add(name)
        if name == "sign":
            sign_descriptions.append(description)
    if len(sign_descriptions) != 1:
        unresolved.append("Exactly one documented sign parameter is required for review.")
    return {
        "parameter_names": names,
        "parameters": normalized,
        "sign_description": sign_descriptions[0] if len(sign_descriptions) == 1 else None,
    }


def _examples(data, unresolved):
    parsed = {}
    raw_examples = {}
    for output_name, source_name in (
        ("request", "request_sample"),
        ("response", "response_sample"),
        ("error", "error_example"),
    ):
        raw_value = data.get(source_name)
        raw_examples[source_name] = raw_value
        if source_name == "error_example" and raw_value == "":
            parsed[output_name] = []
            unresolved.append("No error example is published; error handling needs independent contract fixtures.")
            continue
        value = _decode_json(raw_value, field=source_name)
        if not isinstance(value, list):
            raise StructuredImportError(f"{source_name} must encode an array")
        valid = True
        for index, item in enumerate(value):
            if (
                not isinstance(item, dict)
                or not isinstance(item.get("type"), str)
                or not isinstance(item.get("value"), str)
            ):
                unresolved.append(f"Malformed {source_name} entry at index {index}.")
                valid = False
        parsed[output_name] = value if valid else []
    return parsed, raw_examples


def _source_metadata(data):
    keys = (
        "api_id", "api_type", "define", "module_id", "module_name", "api_permission",
        "update_log_list", "perm_mtime", "perm_operator", "perm_type", "status", "rate_limit",
        "error_list", "common_error_list", "related_documents",
    )
    return {key: data[key] for key in keys if key in data}


def normalize_document(source, *, catalog_root, expected_sha256=None):
    """Return a deterministic disabled candidate for one local raw document."""
    try:
        root = Path(catalog_root).resolve()
        path = _under_upstream(Path(source), root)
        raw = _read_bounded(path)
        digest = hashlib.sha256(raw).hexdigest()
        if expected_sha256 is not None and digest != expected_sha256:
            raise StructuredImportError("Upstream document hash mismatch")
        data = _decode_json(raw, field="upstream document")
        if not isinstance(data, dict):
            raise StructuredImportError("Upstream document must be an object")

        raw_api_name = data.get("api_name")
        api_path = data.get("path")
        raw_method = data.get("method")
        if not isinstance(raw_api_name, str):
            raise StructuredImportError("Invalid API name")
        source_api_name = path.name.removesuffix(".json")
        if not path.name.endswith(".json") or raw_api_name.strip() != source_api_name:
            raise StructuredImportError("Upstream filename/API name mismatch")
        if not isinstance(api_path, str) or not _PATH.fullmatch(api_path) or ".." in api_path:
            raise StructuredImportError("Invalid API path")
        if type(raw_method) is not int or raw_method not in _METHODS:
            raise StructuredImportError("Unknown official method code")
        partner_url = data.get("url")
        if not isinstance(partner_url, str):
            raise StructuredImportError("Missing partner endpoint URL")
        parsed_url = urlsplit(partner_url)
        if (
            parsed_url.scheme != "https"
            or parsed_url.netloc != "partner.shopeemobile.com"
            or parsed_url.path != api_path
            or parsed_url.query
            or parsed_url.fragment
        ):
            raise StructuredImportError("Partner URL/API path mismatch")
        relative_parts = path.relative_to(root / "upstream").parts
        if len(relative_parts) != 3 or relative_parts[1] != "endpoints":
            raise StructuredImportError(
                "Upstream document must be under upstream/<capture-date>/endpoints"
            )
        captured_at = relative_parts[0]
        try:
            if date.fromisoformat(captured_at).isoformat() != captured_at:
                raise ValueError
        except ValueError:
            raise StructuredImportError("Upstream directory must be an ISO capture date") from None

        api_name, tool_name = _catalog_identity(root, source_api_name)
        unresolved = [
            "Authentication strategy requires review; common parameters are documentation only.",
            "Encoding, effects, retry policy, and serialization require review.",
            "Permissions and examples are documentation only; this candidate is not executable.",
        ]
        params = _decode_json(data.get("params"), field="params")
        if not isinstance(params, dict):
            raise StructuredImportError("params must encode an object")
        if set(params) != {"request_params", "response_params"}:
            raise StructuredImportError("params must contain only request_params and response_params")
        request = _object_schema(
            params["request_params"], request=True, unresolved=unresolved, location="request"
        )
        response = _object_schema(
            params["response_params"], request=False, unresolved=unresolved, location="response"
        )
        auth = _common_parameters(data.get("common_params"), unresolved)
        examples, raw_examples = _examples(data, unresolved)
        Draft202012Validator.check_schema(request)
        Draft202012Validator.check_schema(response)

        method = _METHODS[raw_method]
        source_url = "https://open.shopee.com/opservice/api/v1/doc/api/?" + urlencode(
            {"version": 2, "api_name": source_api_name}
        )
        return {
            "candidate_format": 1,
            "api_name": api_name,
            "tool_name": tool_name,
            "path": api_path,
            "method": method,
            **_DRAFT_STATES,
            "description": _definition_text(data.get("define")),
            "source": {
                "file": path.relative_to(root).as_posix(),
                "sha256": digest,
                "url": source_url,
                "captured_at": captured_at,
                "identity": {
                    "api_name": api_name,
                    "raw_api_name": raw_api_name,
                    "source_api_name": source_api_name,
                    "path": api_path,
                    "method": method,
                    "raw_method": raw_method,
                },
            },
            "source_metadata": _source_metadata(data),
            "auth_documentation": auth,
            "candidate_request_schema": request,
            "candidate_response_schema": response,
            "raw_parameters": params,
            "examples": examples,
            "raw_examples": raw_examples,
            "unresolved": unresolved,
        }
    except StructuredImportError:
        raise
    except (OSError, ValueError, TypeError, KeyError, RecursionError, SchemaError):
        raise StructuredImportError("Invalid structured upstream document") from None


def write_candidate(candidate, *, catalog_root):
    """Exclusively write a source-regenerated candidate below candidates/."""
    try:
        root = Path(catalog_root).resolve()
        source = candidate["source"]
        checked = normalize_document(
            root / source["file"],
            catalog_root=root,
            expected_sha256=source["sha256"],
        )
        if checked != candidate:
            raise StructuredImportError("Candidate differs from source-derived normalization")
        payload = (json.dumps(checked, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode()
        directory = root / "candidates"
        if directory.is_symlink():
            raise StructuredImportError("Candidate directory must not be a symlink")
        directory.mkdir(exist_ok=True)
        name = f"{checked['api_name']}.{source['sha256'][:16]}.json"
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            fd = os.open(
                name,
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
                os.unlink(name, dir_fd=directory_fd)
                raise
        finally:
            os.close(directory_fd)
        return directory / name
    except StructuredImportError:
        raise
    except (OSError, ValueError, TypeError, KeyError):
        raise StructuredImportError("Unable to create exclusive candidate file") from None


def _input_files(input_path, root):
    path = Path(input_path)
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        raise StructuredImportError("Upstream input does not exist") from None
    if resolved.is_dir():
        directory = _under_upstream(path, root, expect_directory=True)
        if directory.name != "endpoints":
            endpoints = directory / "endpoints"
            if endpoints.is_symlink() or not endpoints.is_dir():
                raise StructuredImportError("Batch input has no regular endpoints directory")
            directory = endpoints
        files = sorted(directory.glob("*.json"), key=lambda item: item.name)
        if not files:
            raise StructuredImportError("Batch input contains no endpoint documents")
        return files
    return [_under_upstream(path, root)]


def process_input(input_path, *, catalog_root, write=False):
    """Normalize one file or a directory and return a deterministic batch report."""
    root = Path(catalog_root).resolve()
    documents = []
    for path in _input_files(input_path, root):
        relative = path.relative_to(root).as_posix()
        try:
            candidate = normalize_document(path, catalog_root=root)
            item = {
                "file": relative,
                "api_name": candidate["api_name"],
                "status": "ok",
                "unresolved": candidate["unresolved"],
            }
            if write:
                item["candidate"] = write_candidate(candidate, catalog_root=root).relative_to(root).as_posix()
            documents.append(item)
        except StructuredImportError as error:
            documents.append({"file": relative, "status": "error", "error": str(error)})
    ok = sum(item["status"] == "ok" for item in documents)
    errors = len(documents) - ok
    return {
        "mode": "write" if write else "check",
        "documents": documents,
        "summary": {
            "total": len(documents),
            "ok": ok,
            "error": errors,
            "unresolved": sum(bool(item.get("unresolved")) for item in documents),
        },
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="upstream JSON file or directory")
    parser.add_argument("--catalog", required=True, type=Path)
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--check", action="store_true", help="validate and summarize without writes (default)")
    action.add_argument("--write", action="store_true", help="exclusively create catalog/candidates files")
    args = parser.parse_args(argv)
    try:
        report = process_input(args.input, catalog_root=args.catalog, write=args.write)
        print(json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False))
        return 1 if report["summary"]["error"] else 0
    except StructuredImportError as error:
        print(json.dumps({"mode": "write" if args.write else "check", "error": str(error)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
