"""Shopee stdio MCP adapter; individual tools generated from a pinned catalog."""
from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import math
import sys
from pathlib import Path

from jsonschema import Draft202012Validator
from mcp import types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from mcp.shared.exceptions import MCPError

from . import __version__
from .catalog import Catalog, CatalogError, output_schema
from .credentials import CredentialError, CredentialStore
from .policy import Policy
from .results import ArtifactStore, ResultError, build_result, error_result
from .transport import Transport, TransportError
from .validation import InputError, validate_arguments


class MCPService:
    def __init__(self, catalog, policy, transport, artifacts, *, page_size=None, inline_bytes=24_000):
        if (page_size is not None and page_size <= 0) or inline_bytes <= 0:
            raise ValueError("Output limits must be positive")
        self.catalog, self.policy, self.transport, self.artifacts = catalog, policy, transport, artifacts
        self.tools = [types.Tool(**tool) for tool in catalog.tools(policy)]
        # Some hosts register only the first tools/list page. Default to a complete
        # policy-filtered list; retain explicit pagination for other callers.
        self.page_size = max(1, len(self.tools)) if page_size is None else page_size
        self.inline_bytes = inline_bytes
        names = ",".join(tool.name for tool in self.tools)
        self.cursor_version = hashlib.sha256((catalog.version + policy.context + names).encode()).hexdigest()[:16]
        self.server = Server("shopee", version=__version__,
                             instructions="Individual Shopee v2 endpoint tools. One Shopee API call fetches one data page; use returned cursors. Credentials are internal. Available tools are controlled by operator policy. API/account coverage is partial; permissions vary.",
                             on_list_tools=self.list_tools, on_call_tool=self.call_tool,
                             on_list_resources=self.list_resources,
                             on_read_resource=self.read_resource)

    async def list_tools(self, context, params):
        offset = 0
        if params and params.cursor:
            try:
                if len(params.cursor) > 4096:
                    raise ValueError()
                raw = json.loads(base64.urlsafe_b64decode(params.cursor.encode()))
                offset = raw["offset"]
                if raw["version"] != self.cursor_version or type(offset) is not int or not 0 <= offset < len(self.tools):
                    raise ValueError()
            except (ValueError, KeyError, TypeError):
                raise MCPError(-32602, "Invalid tools/list cursor") from None
        end = offset + self.page_size
        next_cursor = None
        if end < len(self.tools):
            next_cursor = base64.urlsafe_b64encode(json.dumps({"offset": end, "version": self.cursor_version}).encode()).decode()
        return types.ListToolsResult(tools=self.tools[offset:end], next_cursor=next_cursor)

    async def list_resources(self, context, params):
        # Artifacts are connection-scoped and are discovered through tool results.
        return types.ListResourcesResult(resources=[])

    async def call_tool(self, context, params):
        try:
            endpoint = self.catalog.get(params.name, self.policy)
        except CatalogError:
            raise MCPError(-32602, "Unknown or disabled tool") from None
        try:
            request, output = validate_arguments(endpoint, params.arguments, self.policy.context)
            payload = await self.transport.execute(endpoint, request)
            result = build_result(endpoint, payload, self.policy.context, self.catalog.version, output,
                                  getattr(payload, "secrets", self.transport.secrets), self.artifacts,
                                  inline_bytes=self.inline_bytes)
        except InputError:
            result = error_result(endpoint, self.policy.context, self.catalog.version, "invalid_arguments")
        except CredentialError as error:
            known = str(error).split(":", 1)[0]
            kind = known if known in {"credential_quarantined", "credential_persistence_failed", "refresh_outcome_unknown", "refresh_not_sent", "credential_binding_changed"} else "credential_error"
            result = error_result(endpoint, self.policy.context, self.catalog.version, kind,
                                  retryable=kind == "refresh_not_sent")
            result["error"]["message"] = str(error)  # CredentialError contains only controlled diagnostics.
        except TransportError as error:
            result = error_result(endpoint, self.policy.context, self.catalog.version, error.kind,
                                  outcome="unknown" if error.kind == "outcome_unknown" else "failed",
                                  retryable=error.retryable, status=error.status)
        except ResultError:
            result = error_result(endpoint, self.policy.context, self.catalog.version, "invalid_response")
        except (ValueError, OSError, TypeError):
            result = error_result(endpoint, self.policy.context, self.catalog.version, "execution_failed")
        if not Draft202012Validator(output_schema(endpoint)).is_valid(result):
            result = error_result(endpoint, self.policy.context, self.catalog.version, "invalid_response")
        result["meta"]["server_version"] = __version__
        summary = {"ok": result["ok"], "meta": result["meta"], "error": result["error"]}
        content = [types.TextContent(type="text", text=json.dumps(summary, ensure_ascii=False))]
        artifact = (result.get("data") or {}).get("artifact")
        if artifact:
            content.append(types.ResourceLink(type="resource_link", uri=artifact["uri"], name="Shopee response",
                                               mime_type=artifact["mime_type"], size=artifact["size"]))
        return types.CallToolResult(content=content, structured_content=result, is_error=not result["ok"])

    async def read_resource(self, context, params):
        try:
            content, mime = self.artifacts.read(str(params.uri))
        except ResultError:
            raise MCPError(-32602, "Unknown or expired artifact") from None
        if mime == "application/json" or mime.startswith("text/"):
            item = types.TextResourceContents(uri=params.uri, mime_type=mime, text=content.decode("utf-8"))
        else:
            item = types.BlobResourceContents(uri=params.uri, mime_type=mime, blob=base64.b64encode(content).decode())
        return types.ReadResourceResult(contents=[item])


def parser():
    result = argparse.ArgumentParser(description="Read-only by default, individual Shopee MCP endpoint tools")
    config = result.add_mutually_exclusive_group(required=True)
    config.add_argument("--env-file", type=Path, help="One shop's owner-only credential file (legacy mode)")
    config.add_argument("--shops-file", type=Path, help="Owner-only JSON mapping shop aliases to credential files (read-only multi-shop mode)")
    result.add_argument("--context", default="ph-shop")
    result.add_argument("--catalog", type=Path)
    result.add_argument("--module", action="append")
    result.add_argument("--endpoint", action="append")
    result.add_argument("--allow-write", action="append", default=[], metavar="API_NAME|*",
                        help="Allow an exact API name (repeatable), or '*' for all executable tools, including credential actions; catalog and scope filters still apply")
    result.add_argument("--upload-root", action="append", type=Path, default=[])
    result.add_argument("--artifact-dir", type=Path)
    result.add_argument("--timeout", type=float, default=30.0)
    result.add_argument("--concurrency", type=int, default=4)
    result.add_argument("--max-response-bytes", type=int, default=8_000_000)
    result.add_argument("--inline-bytes", type=int, default=24_000)
    result.add_argument("--artifact-ttl", type=int, default=3600)
    result.add_argument("--check", action="store_true", help="Validate local configuration and report coverage without HTTP")
    return result


async def run(args):
    selected_file = args.shops_file or args.env_file
    if not selected_file.is_absolute():
        raise CredentialError("Configuration file must be an absolute path")
    if args.shops_file and args.allow_write:
        raise ValueError("Multi-shop mode is read-only; --allow-write is not allowed")
    if not math.isfinite(args.timeout) or args.timeout <= 0 or any(
        limit <= 0 for limit in (args.concurrency, args.max_response_bytes, args.inline_bytes, args.artifact_ttl)
    ):
        raise ValueError("Runtime limits must be positive and finite")
    if any(not root.is_dir() for root in args.upload_root):
        raise ValueError("Upload roots must be existing directories")
    store = None
    if args.env_file:
        store = CredentialStore(args.env_file)
        store.snapshot("shop")  # Local validation and pinned identity only; no refresh.
    catalog = Catalog(args.catalog)
    known_modules = {name.split(".", 2)[1] for name in catalog.name_map if name.count(".") >= 2}
    if set(args.module or []) - known_modules:
        raise ValueError("Unknown module in operator configuration")
    policy = Policy(args.context, frozenset(args.module) if args.module is not None else None,
                    frozenset(args.endpoint) if args.endpoint is not None else None, frozenset(args.allow_write))
    known_names = set(catalog.name_map)
    if (set(args.endpoint or []) | (set(args.allow_write) - {"*"})) - known_names:
        raise ValueError("Unknown endpoint in operator configuration")
    if args.shops_file:
        # Imports kept local so the existing single-shop CLI stays backwards compatible.
        from .multi_shop import MultiShopRegistry
        from .multi_server import MultiShopMCPService
        registry = MultiShopRegistry.from_config_file(
            args.shops_file, timeout=args.timeout, concurrency=args.concurrency,
            max_response_bytes=args.max_response_bytes, upload_roots=args.upload_root)
        if args.check:
            try:
                service = MultiShopMCPService(catalog, policy, registry, None, inline_bytes=args.inline_bytes)
                print(json.dumps({**catalog.coverage(), "mode": "multi-shop-read-only",
                                  "shops": registry.describe(), "tools": [t.name for t in service.tools]}, indent=2))
            finally:
                await registry.close()
            return 0
        artifacts = ArtifactStore(args.artifact_dir or args.shops_file.parent / "local-data/shopee-mcp/artifacts", ttl=args.artifact_ttl)
        try:
            service = MultiShopMCPService(catalog, policy, registry, artifacts, inline_bytes=args.inline_bytes)
            async with stdio_server() as (read, write):
                await service.server.run(read, write, service.server.create_initialization_options())
        finally:
            await registry.close()
            artifacts.cleanup(all_records=True)
        return 0
    if args.check:
        print(json.dumps({**catalog.coverage(), "context": policy.context, "tools": [t["name"] for t in catalog.tools(policy)]}, indent=2))
        return 0
    transport = Transport(store, timeout=args.timeout, concurrency=args.concurrency,
                          max_response_bytes=args.max_response_bytes, upload_roots=args.upload_root)
    artifacts = ArtifactStore(args.artifact_dir or args.env_file.parent / "local-data/shopee-mcp/artifacts", ttl=args.artifact_ttl)
    try:
        service = MCPService(catalog, policy, transport, artifacts, inline_bytes=args.inline_bytes)
        async with stdio_server() as (read, write):
            await service.server.run(read, write, service.server.create_initialization_options())
    finally:
        await transport.close()
        artifacts.cleanup(all_records=True)
    return 0


def main():
    args = parser().parse_args()
    try:
        return asyncio.run(run(args))
    except KeyboardInterrupt:
        return 130
    except (CredentialError, CatalogError) as error:
        print(f"Shopee MCP configuration error: {error}", file=sys.stderr)
        return 1
    except Exception:
        print("Shopee MCP stopped: startup or protocol failure (secret details suppressed)", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
