"""Pinned, reviewed endpoint definitions; no runtime website requests."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

from jsonschema import Draft202012Validator

from .validation import InputError, RESERVED, parameter_aliases, tool_input_schema
from .catalog_files import validate_file_contract
from .constraints import validate_constraint_metadata
from .response_metadata import validate_response_metadata


class CatalogError(ValueError):
    pass


def stable_tool_name(api_name):
    simple = re.sub(r"[^A-Za-z0-9_]", "_", api_name)
    if len(simple) <= 64 and simple == api_name.replace(".", "_"):
        return simple
    digest = hashlib.sha256(api_name.encode()).hexdigest()[:12]
    return simple[:51] + "_" + digest


def _validate_schema(schema, *, strict=False):
    Draft202012Validator.check_schema(schema)
    def visit(node):
        if isinstance(node, dict):
            if "$ref" in node or "$dynamicRef" in node:
                raise CatalogError("Schema references are not supported; definitions must be self-contained")
            if strict and node.get("type") == "object" and node.get("additionalProperties") is not False:
                raise CatalogError("Request objects must reject unknown fields")
            for value in node.values():
                visit(value)
        elif isinstance(node, list):
            for value in node:
                visit(value)
    visit(schema)


def output_schema(endpoint):
    # Projection may remove fields required by the full wire response contract.
    data = {**endpoint["response_schema"], "required": []}
    artifact = {"type": "object", "required": ["artifact"], "properties": {
        "artifact": {"type": "object", "required": ["uri", "size", "mime_type"], "properties": {
            "uri": {"type": "string"}, "size": {"type": "integer"}, "mime_type": {"type": "string"}}}}}
    return {"type": "object", "required": ["ok", "meta", "data", "error"], "additionalProperties": False,
            "properties": {"ok": {"type": "boolean"}, "meta": {"type": "object"},
                           "data": {"anyOf": [data, artifact, {"type": "null"}]},
                           "error": {"type": ["object", "null"]}}}


class Catalog:
    def __init__(self, root=None):
        source_root = Path(__file__).resolve().parents[2] / "public_catalog"
        self.root = Path(root) if root is not None else (source_root if source_root.is_dir() else Path(__file__).parent / "data")
        try:
            self.manifest = json.loads((self.root / "manifest.json").read_text())
            self.name_map = json.loads((self.root / "tool-name-map.json").read_text())
            self.public = self.manifest.get("catalog_format") == "public-v1"
            entries = self.manifest["entries"]
            names = [entry["api_name"] for entry in entries]
            if len(names) != len(set(names)):
                raise CatalogError("Duplicate manifest API names")
            if self.public:
                hashes = self.manifest["endpoint_sha256"]
                files = sorted((self.root / "endpoints").glob("*.json"))
                if set(hashes) != {file.name for file in files}:
                    raise CatalogError("Published endpoint inventory mismatch")
                for file in files:
                    if hashlib.sha256(file.read_bytes()).hexdigest() != hashes[file.name]:
                        raise CatalogError("Published endpoint hash mismatch")
            else:
                index = self._source_bytes(self.manifest["index_source"])
                indexed_names = [re.sub(r"^\(coming offline soon\)\s*", "", line.strip()) for line in index.decode().splitlines() if line.strip()]
                if indexed_names != names:
                    raise CatalogError("Discovery index and manifest differ")
            if set(self.name_map) != set(names) or len(set(self.name_map.values())) != len(names):
                raise CatalogError("Missing or colliding stable tool names")
            if any(not re.fullmatch(r"[A-Za-z0-9_]{1,64}", name) for name in self.name_map.values()):
                raise CatalogError("Invalid tool name")
            by_name = {entry["api_name"]: entry for entry in entries}
            for entry in entries:
                if entry["specification"] not in {"discovered", "verified"} or entry["implementation"] not in {"unimplemented", "partial", "implemented"} or entry["exposure"] not in {"enabled", "opt_in", "disabled", "retired"}:
                    raise CatalogError("Invalid catalog coverage state")
                if entry.get("scope_coverage", {}).get("unresolved") and entry["implementation"] == "implemented":
                    raise CatalogError("Unresolved scopes cannot be fully implemented")
            self.endpoints = {}
            for file in sorted((self.root / "endpoints").glob("*.json")):
                endpoint = json.loads(file.read_text())
                name = endpoint["api_name"]
                if name not in by_name or endpoint["tool_name"] != self.name_map[name]:
                    raise CatalogError("Endpoint not matched by manifest/name map")
                if endpoint["tool_name"] in self.endpoints:
                    raise CatalogError("Duplicate endpoint tool")
                if endpoint["review_status"] != "verified" or by_name[name]["specification"] != "verified":
                    raise CatalogError("Unverified endpoint must not be loaded as executable")
                if endpoint["implementation"] != by_name[name]["implementation"] or endpoint["implementation"] not in {"implemented", "partial"}:
                    raise CatalogError("Implementation status mismatch")
                if endpoint.get("scope_coverage") != by_name[name].get("scope_coverage"):
                    raise CatalogError("Scope coverage mismatch")
                endpoint["exposure"] = by_name[name]["exposure"]
                if endpoint["implementation"] == "partial":
                    coverage = endpoint["scope_coverage"]
                    scope_schema = endpoint["input_schema"]["properties"]["scope"]
                    if not coverage["unresolved"] or set(scope_schema["enum"]) != set(coverage["supported"]) or set(coverage["unresolved"]) & set(coverage["supported"]):
                        raise CatalogError("Partial endpoint requires exact restricted scope schema")
                self._validate_endpoint(endpoint)
                self.endpoints[endpoint["tool_name"]] = endpoint
            for entry in entries:
                if (entry["exposure"] != "retired" and entry["implementation"] in {"implemented", "partial"}
                        and self.name_map[entry["api_name"]] not in self.endpoints):
                    raise CatalogError("Implemented manifest entry lacks an endpoint definition")
        except CatalogError:
            raise
        except Exception:
            raise CatalogError("Invalid catalog data") from None

    def _validate_endpoint(self, endpoint):
        if endpoint["method"] not in {"GET", "POST", "PUT", "DELETE", "PATCH"}:
            raise CatalogError("Unsupported HTTP method")
        if not re.fullmatch(r"/api/v2/[A-Za-z0-9_/-]+", endpoint["path"]) or ".." in endpoint["path"]:
            raise CatalogError("Invalid endpoint path")
        if endpoint["encoding"] not in {"query", "json", "multipart", "binary", "credential_refresh"}:
            raise CatalogError("Unsupported endpoint encoding")
        if endpoint["auth_strategy"] not in {"public", "shop", "merchant", "principal", "user"}:
            raise CatalogError("Unimplemented auth strategy")
        if endpoint["effects"] not in {"read", "write", "credential"}:
            raise CatalogError("Unknown endpoint effects")
        if type(endpoint["idempotent"]) is not bool:
            raise CatalogError("Idempotency must be an explicit boolean")
        retry = endpoint["retry_policy"]
        if type(retry["max_attempts"]) is not int or not 1 <= retry["max_attempts"] <= 5:
            raise CatalogError("Invalid retry attempts")
        if endpoint["effects"] != "read" and retry["max_attempts"] != 1:
            raise CatalogError("Mutations must not be automatically retried")
        if any(mode not in {"repeat", "csv", "json"} for mode in endpoint.get("query_arrays", {}).values()):
            raise CatalogError("Unknown query array serialization")
        try:
            validate_file_contract(endpoint)
        except (ValueError, TypeError, KeyError):
            raise CatalogError("Invalid file transport metadata") from None
        if endpoint["input_schema"].get("type") != "object" or endpoint["response_schema"].get("type") != "object":
            raise CatalogError("Endpoint schemas must be objects")
        _validate_schema(endpoint["input_schema"], strict=True)
        _validate_schema(endpoint["response_schema"])
        try:
            validate_response_metadata(endpoint)
        except (ValueError, TypeError, KeyError):
            raise CatalogError("Invalid response metadata") from None
        if RESERVED.intersection(endpoint["input_schema"]["properties"]):
            raise CatalogError("Credential fields cannot be supplied by model")
        try:
            parameter_aliases(endpoint)
        except InputError:
            raise CatalogError("Invalid or authentication-colliding parameter aliases") from None
        try:
            for constraint in endpoint.get("constraints", []):
                validate_constraint_metadata(constraint, endpoint["input_schema"])
        except (ValueError, TypeError, KeyError):
            raise CatalogError("Invalid endpoint constraint metadata") from None
        query_request = (endpoint["encoding"] == "query" or
                         (endpoint["encoding"] == "binary" and endpoint.get("binary_request_encoding") == "query"))
        for field, schema in endpoint["input_schema"]["properties"].items():
            if schema.get("type") == "array" and query_request and field not in endpoint["query_arrays"]:
                raise CatalogError("Query array requires explicit serialization")
        if self.public:
            if any(key in endpoint for key in ("source", "fixture", "contract_fixture", "tests")):
                raise CatalogError("Published endpoint contains private review material")
        else:
            self._source_bytes(endpoint["source"])

    def _source_bytes(self, source):
        source_path = (self.root / source["file"]).resolve()
        if not source_path.is_relative_to(self.root.resolve()):
            raise CatalogError("Invalid source path")
        content = source_path.read_bytes()
        if hashlib.sha256(content).hexdigest() != source["sha256"]:
            raise CatalogError("Catalog source hash mismatch; re-review required")
        return content

    @property
    def version(self):
        return self.manifest["version"]

    def get(self, tool_name, policy):
        endpoint = self.endpoints.get(tool_name)
        if endpoint is None or not policy.permits(endpoint):
            raise CatalogError("Unknown or disabled tool")
        return endpoint

    def tools(self, policy):
        return [{"name": e["tool_name"], "description": e["description"],
                 "inputSchema": tool_input_schema(e, policy.context), "outputSchema": output_schema(e),
                 "annotations": {"readOnlyHint": e["effects"] == "read", "destructiveHint": e["effects"] != "read",
                                 "idempotentHint": e["idempotent"], "openWorldHint": True}}
                for _, e in sorted(self.endpoints.items()) if policy.permits(e)]

    def coverage(self):
        entries = [e for e in self.manifest["entries"] if e["exposure"] != "retired"]
        retired = [e for e in self.manifest["entries"] if e["exposure"] == "retired"]
        verified = sum(e["specification"] == "verified" for e in entries)
        tested = sum("contract_passed" in e["verification"] for e in entries)
        implemented = sum(e["implementation"] == "implemented" for e in entries)
        partial = sum(e["implementation"] == "partial" for e in entries)
        variants = sum(len(e.get("scope_coverage", {}).get("unresolved", [])) for e in entries)
        complete = sum(e["specification"] == "verified" and e["implementation"] == "implemented" and "contract_passed" in e["verification"] and not e.get("scope_coverage", {}).get("unresolved") for e in entries)
        return {"catalog_version": self.version, "discovered": len(self.manifest["entries"]),
                "active": len(entries), "retired": len(retired),
                "retired_implemented": sum(e["implementation"] == "implemented" for e in retired),
                "verified": verified,
                "implemented": implemented, "partially_implemented": partial, "contract_tested": tested,
                "unresolved_specifications": len(entries) - verified, "unresolved_variants": variants,
                "unresolved": len(entries) - complete, "all_supported": bool(entries) and complete == len(entries)}


def main():
    parser = argparse.ArgumentParser(description="Offline catalog integrity and honest coverage report")
    parser.add_argument("--catalog", type=Path)
    parser.add_argument("--require-all", action="store_true")
    parser.add_argument("--unresolved", action="store_true")
    args = parser.parse_args()
    catalog = Catalog(args.catalog)
    result = catalog.coverage()
    if args.unresolved:
        result["unresolved_apis"] = [e["api_name"] for e in catalog.manifest["entries"]
                                    if e["exposure"] != "retired" and (
                                        e["specification"] != "verified" or e["implementation"] != "implemented"
                                        or "contract_passed" not in e["verification"]
                                        or e.get("scope_coverage", {}).get("unresolved"))]
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 1 if args.require_all and not result["all_supported"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
