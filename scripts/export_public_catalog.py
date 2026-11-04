"""Export executable API metadata without copied documentation or examples.

The input catalog is maintained privately. Only the generated output belongs in
the public repository or distribution package.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


RUNTIME_KEYS = frozenset({
    "api_name", "auth_strategy", "batch_failure_fields", "batch_failure_paths",
    "binary_request_encoding", "business_status", "constraints", "download_mime_policy",
    "download_mime_types", "effects", "embedded_json_paths", "encoding",
    "error_message_field", "idempotent", "implementation", "input_schema", "method",
    "module", "pagination_fields", "parameter_aliases", "path", "query_arrays",
    "response_key", "response_schema", "retry_policy", "review_status",
    "scope_coverage", "sensitive_paths", "tool_name", "upload_fields",
})
SCHEMA_PROSE_KEYS = frozenset({"description", "title", "$comment", "example", "examples"})
ENTRY_KEYS = frozenset({
    "api_name", "exposure", "implementation", "specification", "verification",
    "scope_coverage",
})


def _schema_without_prose(value, *, property_map=False):
    if isinstance(value, list):
        return [_schema_without_prose(item) for item in value]
    if isinstance(value, dict):
        return {
            key: _schema_without_prose(item, property_map=key == "properties")
            for key, item in value.items()
            if property_map or key not in SCHEMA_PROSE_KEYS
        }
    return value


def _json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()


def export(private_root: Path, output_root: Path) -> int:
    private_root = private_root.resolve()
    output_root = output_root.resolve()
    if private_root == output_root or output_root.is_relative_to(private_root):
        raise ValueError("Public output must be outside the private catalog")

    manifest = json.loads((private_root / "manifest.json").read_text())
    name_map = json.loads((private_root / "tool-name-map.json").read_text())
    entries = [{key: value for key, value in entry.items() if key in ENTRY_KEYS}
               for entry in manifest["entries"]]
    active = {entry["api_name"] for entry in entries
              if entry["exposure"] != "retired" and entry["implementation"] in {"implemented", "partial"}}
    output_endpoints = output_root / "endpoints"
    output_endpoints.mkdir(parents=True, exist_ok=True)
    hashes = {}
    for api_name in sorted(active):
        private_file = private_root / "endpoints" / f"{api_name}.json"
        original = json.loads(private_file.read_text())
        endpoint = {key: value for key, value in original.items() if key in RUNTIME_KEYS}
        endpoint["description"] = f"Call the Shopee Open Platform {api_name} endpoint."
        endpoint["input_schema"] = _schema_without_prose(endpoint["input_schema"])
        endpoint["response_schema"] = _schema_without_prose(endpoint["response_schema"])
        content = _json_bytes(endpoint)
        filename = f"{api_name}.json"
        (output_endpoints / filename).write_bytes(content)
        hashes[filename] = hashlib.sha256(content).hexdigest()

    for stale_file in output_endpoints.glob("*.json"):
        if stale_file.name not in hashes:
            stale_file.unlink()
    public_manifest = {
        "catalog_format": "public-v1",
        "version": manifest["version"],
        "entries": entries,
        "endpoint_sha256": hashes,
    }
    output_root.mkdir(parents=True, exist_ok=True)
    (output_root / "manifest.json").write_bytes(_json_bytes(public_manifest))
    (output_root / "tool-name-map.json").write_bytes(_json_bytes(name_map))
    return len(hashes)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-root", type=Path, default=Path("catalog"))
    parser.add_argument("--output", type=Path, default=Path("public_catalog"))
    args = parser.parse_args()
    print(f"Exported {export(args.private_root, args.output)} endpoints")


if __name__ == "__main__":
    main()
