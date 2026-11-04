"""Offline rendered-document import; creates review drafts, never executable tools.

Run ``python -m shopee_mcp.import_docs SNAPSHOT --catalog CATALOG --api-name NAME
--api-path PATH --source-url URL`` to inspect a candidate without writing files.
Only ``--write`` creates an exclusive file beneath CATALOG/drafts. The expected
identity must be supplied by the operator, since documented names do not always
map mechanically to paths (for example public.refresh_access_token).

Candidate schemas describe documented wire types, not final MCP input types.
Int64 precision, constraints in prose, auth, encoding, effects and permissions
always require manual review. No API calls or catalog promotion are performed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from datetime import date
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError


class ImportDocsError(ValueError):
    """A local snapshot or draft cannot safely be imported."""


_NAME = re.compile(r"v2\.[A-Za-z0-9_]+\.[A-Za-z0-9_]+")
_PATH = re.compile(r"/api/v2/[A-Za-z0-9_]+(?:/[A-Za-z0-9_]+)+")
_FIELD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_TYPES = {"string": "string", "int": "integer", "int32": "integer", "int64": "integer",
          "timestamp": "integer", "float": "number", "double": "number", "boolean": "boolean"}
_DRAFT_STATES = {"review_status": "draft", "specification": "unverified",
                 "implementation": "unimplemented", "exposure": "disabled", "verification": []}
_MAX_BYTES = 8 * 1024 * 1024


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ImportDocsError("Duplicate JSON key")
        result[key] = value
    return result


def _reject_nonfinite(value):
    raise ImportDocsError("Nonfinite numbers are invalid JSON")


def _source_file(path: Path, root: Path) -> Path:
    resolved = path.resolve()
    snapshots = root / "snapshots"
    if snapshots.is_symlink() or not resolved.is_relative_to(snapshots):
        raise ImportDocsError("Snapshot must be within catalog snapshots")
    if not resolved.is_file():
        raise ImportDocsError("Snapshot must be a regular file")
    return resolved


def _object_schema(request):
    result = {"type": "object", "properties": {}}
    if request:
        result.update(additionalProperties=False, required=[])
    return result


def _type_schema(value, request):
    if value.endswith("[]"):
        return {"type": "array", "items": _type_schema(value[:-2], request)}
    if value == "object":
        return _object_schema(request)
    if value in _TYPES:
        return {"type": _TYPES[value]}
    raise ImportDocsError("Unknown or mixed documented field type")


def _parse_rows(section, *, request, unresolved):
    if not isinstance(section, dict) or not isinstance(section.get("rows"), list):
        raise ImportDocsError("Missing rendered parameter rows")
    if not isinstance(section.get("text"), str):
        raise ImportDocsError("Missing rendered section text")
    schema = _object_schema(request)
    # A container at stack[n] accepts fields at DOM depth n.
    stack = [schema]
    previous = None
    previous_depth = -1
    if not section["rows"]:
        unresolved.append("Empty parameter section requires review; it may have been collapsed during capture.")
    for index, row in enumerate(section["rows"]):
        if not isinstance(row, dict):
            raise ImportDocsError("Invalid parameter row")
        cells, depth = row.get("cells"), row.get("depth")
        count = 5 if request else 4
        if not isinstance(cells, list) or len(cells) != count or any(type(c) is not str for c in cells):
            raise ImportDocsError("Ambiguous parameter columns")
        if type(depth) is not int or not 0 <= depth <= 32 or depth > previous_depth + 1:
            raise ImportDocsError("Invalid parameter depth")
        if depth > previous_depth:
            if depth:
                container = previous
                if container.get("type") == "array":
                    container = container["items"]
                if container.get("type") != "object":
                    raise ImportDocsError("Nested field has no object parent")
                stack.append(container)
        else:
            stack = stack[:depth + 1]
        name, type_text = cells[:2]
        if not _FIELD.fullmatch(name):
            raise ImportDocsError("Invalid documented field name")
        parent = stack[depth]
        if name in parent["properties"]:
            raise ImportDocsError("Duplicate field at the same parameter depth")
        field = _type_schema(type_text, request)
        field["description"] = cells[-1]
        field["x-documentation"] = {"type_text": type_text, "sample_text": cells[-2],
                                    "row": index, "depth": depth}
        if request:
            required = cells[2]
            field["x-documentation"]["required_text"] = required
            if required == "True":
                parent["required"].append(name)
            elif required != "False":
                unresolved.append(f"Conditional or unknown required text for {name} at request row {index}: {required}")
        parent["properties"][name] = field
        previous, previous_depth = field, depth
    Draft202012Validator.check_schema(schema)
    return schema


def import_snapshot(snapshot: Path, *, catalog_root: Path, expected_name: str,
                    expected_path: str, expected_url: str, expected_sha256: str | None = None) -> dict:
    """Read a bounded local snapshot, validate identity, return a disabled draft.

    No writes occur. The SHA256 pins the exact captured bytes. When supplied,
    expected_sha256 additionally verifies an existing operator-provided pin.
    Unknown types/invalid hierarchy fail closed; ambiguous required text stays
    explicitly unresolved with the original row preserved for human review.
    """
    try:
        root = Path(catalog_root).resolve()
        path = _source_file(Path(snapshot), root)
        with path.open("rb") as stream:
            raw = stream.read(_MAX_BYTES + 1)
        if len(raw) > _MAX_BYTES:
            raise ImportDocsError("Snapshot exceeds size limit")
        digest = hashlib.sha256(raw).hexdigest()
        if expected_sha256 is not None and digest != expected_sha256:
            raise ImportDocsError("Snapshot hash mismatch")
        data = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_reject_nonfinite)
        if not isinstance(data, dict):
            raise ImportDocsError("Snapshot must be an object")
        if not _NAME.fullmatch(expected_name) or path.name != f"{expected_name}.json":
            raise ImportDocsError("Snapshot filename/name mismatch")
        if not _PATH.fullmatch(expected_path):
            raise ImportDocsError("Invalid expected API path")
        if (data.get("name"), data.get("path"), data.get("url")) != (expected_name, expected_path, expected_url):
            raise ImportDocsError("Snapshot name/path/url mismatch")
        url = urlsplit(expected_url)
        if (url.scheme != "https" or url.netloc != "open.shopee.com" or url.fragment
                or url.path != f"/documents/v2/{expected_name}"):
            raise ImportDocsError("Source URL must match the official API document")
        captured = data.get("captured_at")
        if not isinstance(captured, str) or date.fromisoformat(captured).isoformat() != captured:
            raise ImportDocsError("Invalid capture date")
        if path.parent.name != captured:
            raise ImportDocsError("Capture date and snapshot directory mismatch")
        if data.get("method") not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
            raise ImportDocsError("Unknown HTTP method")
        sections = data.get("sections")
        if not isinstance(sections, dict):
            raise ImportDocsError("Missing rendered sections")
        unresolved = [
            "Manual review required: prose constraints, conditional semantics, enums and numeric precision.",
            "Authentication, common parameters, encoding, effects, permissions and endpoint contracts are not inferred.",
            "Candidate schemas are documented wire types, not approved MCP tool schemas.",
        ]
        request = _parse_rows(sections.get("Request Parameters"), request=True, unresolved=unresolved)
        response = _parse_rows(sections.get("Response Parameters"), request=False, unresolved=unresolved)
        return {"draft_format": 1, "api_name": expected_name, "path": expected_path, "method": data["method"],
                **_DRAFT_STATES, "verification": [],
                "source": {"file": path.relative_to(root).as_posix(), "sha256": digest,
                           "url": expected_url, "captured_at": captured},
                "candidate_request_schema": request, "candidate_response_schema": response,
                "raw_sections": sections, "unresolved": unresolved}
    except ImportDocsError:
        raise
    except (OSError, ValueError, TypeError, KeyError, RecursionError, SchemaError):
        raise ImportDocsError("Invalid rendered-document snapshot") from None


def write_draft(draft: dict, *, catalog_root: Path) -> Path:
    """Write a regenerated draft exclusively under catalog/drafts.

    Regeneration detects tampering, stale sources, invalid schemas or promotion
    attempts. Existing output is never overwritten. Symlinked drafts directories
    and destination files are refused.
    """
    try:
        root = Path(catalog_root).resolve()
        source = draft["source"]
        checked = import_snapshot(root / source["file"], catalog_root=root,
                                  expected_name=draft["api_name"], expected_path=draft["path"],
                                  expected_url=source["url"], expected_sha256=source["sha256"])
        if checked != draft:
            raise ImportDocsError("Draft differs from source-derived candidate; refusing to publish changes")
        payload = (json.dumps(checked, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode()
        directory = root / "drafts"
        if directory.is_symlink():
            raise ImportDocsError("Draft directory must not be a symlink")
        directory.mkdir(exist_ok=True)
        name = f"{draft['api_name']}.{source['sha256'][:16]}.json"
        dir_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dir_fd)
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(payload)
                    stream.flush()
                    os.fsync(stream.fileno())
            except BaseException:
                os.unlink(name, dir_fd=dir_fd)
                raise
        finally:
            os.close(dir_fd)
        return directory / name
    except ImportDocsError:
        raise
    except (OSError, ValueError, TypeError, KeyError):
        raise ImportDocsError("Unable to create exclusive draft file") from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("--catalog", required=True, type=Path)
    parser.add_argument("--api-name", required=True)
    parser.add_argument("--api-path", required=True)
    parser.add_argument("--source-url", required=True)
    parser.add_argument("--sha256")
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--check", action="store_true", help="Validate and print a draft without writes (default)")
    action.add_argument("--write", action="store_true", help="Create an exclusive file under catalog/drafts")
    args = parser.parse_args(argv)
    try:
        draft = import_snapshot(args.snapshot, catalog_root=args.catalog, expected_name=args.api_name,
                                expected_path=args.api_path, expected_url=args.source_url, expected_sha256=args.sha256)
        if args.write:
            print(json.dumps({"draft": str(write_draft(draft, catalog_root=args.catalog))}))
        else:
            print(json.dumps(draft, ensure_ascii=False, indent=2))
        return 0
    except ImportDocsError as error:
        print(f"Import refused: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
