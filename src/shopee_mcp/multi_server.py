"""Read-only, operator-configured multi-shop MCP adapter.

Every original catalog tool keeps its validation and transport path. A caller
must select an explicit alias, never a credential path or arbitrary shop ID.
"""
from __future__ import annotations

import asyncio
import copy
import json

from jsonschema import Draft202012Validator
from mcp import types
from mcp.shared.exceptions import MCPError

from .ads_summary import AdsSummaryInputError, BALANCE_API, DAILY_API, HOURLY_API, summarize_ads, _to_decimal, _to_int, plan_daily_chunks
from .catalog import CatalogError
from .multi_shop import MultiShopError
from .policy import Policy
from .results import ResultError, redact
from .server import MCPService
from .validation import validate_arguments


class _NoDefaultTransport:
    """A missing shop may never resolve to the first configured credential."""
    secrets = frozenset()

    async def execute(self, *_args, **_kwargs):
        raise RuntimeError("Explicit shop alias required")


class EmptyShopService:
    """Served by the HTTP mode while no shop is configured yet.

    Only ``list_connected_shops`` exists (returning an empty list), so clients can
    connect before the operator adds the first shop through ``/admin/shops``.
    """

    registry = None
    note = "No shops are connected yet. The server operator can add one at /admin/shops."

    def __init__(self, artifacts=None):
        self.artifacts = artifacts  # artifacts from before the last shop was removed stay readable
        self.tools = [types.Tool(name="list_connected_shops",
                                 description="List configured shop aliases. No Shopee request is sent.",
                                 inputSchema={"type": "object", "properties": {}, "additionalProperties": False},
                                 annotations=types.ToolAnnotations(readOnlyHint=True))]

    async def list_tools(self, context, params):
        return types.ListToolsResult(tools=list(self.tools), next_cursor=None)

    async def call_tool(self, context, params):
        if params.name != "list_connected_shops":
            raise MCPError(-32602, "Unknown or disabled tool")
        data = {"shops": [], "note": self.note}
        return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps(data))],
                                    structured_content=data, is_error=False)

    async def list_resources(self, context, params):
        return types.ListResourcesResult(resources=[])

    async def read_resource(self, context, params):
        if self.artifacts is None:
            raise MCPError(-32602, "Unknown or expired artifact")
        return await MCPService.read_resource(self, context, params)


class MultiShopMCPService(MCPService):
    """One MCP connection serving only preconfigured, explicitly selected shops."""

    summary_deadline = 80.0  # seconds for one whole get_ads_summary call

    def __init__(self, catalog, policy, registry, artifacts, *, page_size=None, inline_bytes=24_000):
        if policy.allow_writes:
            raise ValueError("Multi-shop mode is read-only")
        if not registry.aliases:
            raise ValueError("Multi-shop registry must not be empty")
        self.registry = registry
        self.delegates = {}
        super().__init__(catalog, policy, _NoDefaultTransport(), artifacts,
                         page_size=page_size, inline_bytes=inline_bytes)
        for index, tool in enumerate(self.tools):
            schema = copy.deepcopy(tool.input_schema)
            schema["properties"].pop("context", None)
            schema["properties"]["shop"] = {"type": "string", "enum": list(registry.aliases),
                                            "description": "Explicit operator-configured shop alias."}
            schema["required"] = list(dict.fromkeys([*schema.get("required", []), "shop"]))
            self.tools[index] = tool.model_copy(update={"input_schema": schema})
        self.tools.append(types.Tool(name="list_connected_shops", description="List configured shop aliases. No Shopee request is sent.",
                                     inputSchema={"type": "object", "properties": {}, "additionalProperties": False},
                                     annotations=types.ToolAnnotations(readOnlyHint=True)))
        shops_schema = {"type": "array", "minItems": 1, "maxItems": min(25, len(registry.aliases)),
                        "uniqueItems": True, "items": {"type": "string", "enum": list(registry.aliases)}}
        self._custom_schemas = {"list_connected_shops": {"type": "object", "properties": {}, "additionalProperties": False}}
        if self._permitted(BALANCE_API):
            self._custom_schemas["get_ads_balances"] = {
                "type": "object", "properties": {"shops": shops_schema}, "required": ["shops"], "additionalProperties": False}
            self.tools.append(types.Tool(name="get_ads_balances", description="Read current Ads balance for each selected shop. Paid and free credits are combined; currency is not provided by Shopee.", inputSchema=self._custom_schemas["get_ads_balances"], annotations=types.ToolAnnotations(readOnlyHint=True)))
        if all(self._permitted(name) for name in (DAILY_API, HOURLY_API, BALANCE_API)):
            self._custom_schemas["get_ads_summary"] = {
                "type": "object", "properties": {"shops": shops_schema,
                    "start_date": {"type": "string", "pattern": "^[0-9]{2}-[0-9]{2}-[0-9]{4}$"},
                    "end_date": {"type": "string", "pattern": "^[0-9]{2}-[0-9]{2}-[0-9]{4}$"}},
                "required": ["shops", "start_date", "end_date"], "additionalProperties": False}
            self.tools.append(types.Tool(name="get_ads_summary", description="Read per-shop CPC Ads expense, direct/broad orders and GMV with separate attribution. Dates use DD-MM-YYYY. Incomplete data is explicitly marked; results are not reconciled against Seller Center.", inputSchema=self._custom_schemas["get_ads_summary"], annotations=types.ToolAnnotations(readOnlyHint=True)))
        self.tools.sort(key=lambda tool: tool.name)
        if page_size is None:
            self.page_size = max(1, len(self.tools))
        # The list schema is specific to the configured aliases; old cursors cannot be reused.
        import hashlib
        names = ",".join(tool.name for tool in self.tools)
        self.cursor_version = hashlib.sha256((catalog.version + policy.context + names + ",".join(registry.aliases)).encode()).hexdigest()[:16]

    def _permitted(self, api_name):
        try:
            endpoint = self.catalog.get(self.catalog.name_map[api_name], self.policy)
            return endpoint["effects"] == "read"
        except (CatalogError, KeyError):
            return False

    def _delegate(self, alias):
        if alias not in self.delegates:
            scoped = Policy(alias, self.policy.modules, self.policy.endpoints, frozenset())
            self.delegates[alias] = MCPService(self.catalog, scoped, self.registry.transport(alias), self.artifacts,
                                               inline_bytes=self.inline_bytes)
        return self.delegates[alias]

    async def _execute_read(self, alias, api_name, request):
        delegate = self._delegate(alias)
        try:
            endpoint = self.catalog.get(self.catalog.name_map[api_name], delegate.policy)
        except (CatalogError, KeyError):
            raise ValueError("endpoint_not_permitted") from None
        if endpoint["effects"] != "read":
            raise ValueError("endpoint_not_permitted")
        validated, _ = validate_arguments(endpoint, {"request": request}, alias)
        payload = await delegate.transport.execute(endpoint, validated)
        # No API token, signature, URL or arbitrary raw exception leaves the server.
        secrets = getattr(payload, "secrets", frozenset()) | frozenset(delegate.transport.secrets)
        return redact(payload, secrets, endpoint.get("sensitive_paths", []), all_urls=True)

    def _result(self, data, *, error=False):
        try:
            raw = json.dumps(data, ensure_ascii=False, allow_nan=False).encode("utf-8")
        except (TypeError, ValueError, OverflowError):
            data, error = {"error": "invalid_response"}, True
            raw = b'{"error":"invalid_response"}'
        if len(raw) > max(2048, self.inline_bytes):
            # Keep the important per-shop totals visible even when the full
            # daily rows must be moved into an artifact.
            shops = []
            for entry in data.get("shops", []):
                if not isinstance(entry, dict):
                    continue
                if isinstance(entry.get("summary"), dict):
                    summary = entry["summary"]
                    compact = {key: summary.get(key) for key in ("status", "complete", "totals", "partial_totals", "balance")}
                    compact["missing_date_count"] = len(summary.get("missing_dates", []))
                    compact["failed_date_count"] = len(summary.get("failed_dates", []))
                    shops.append({"shop": entry.get("shop"), "summary": compact})
                else:
                    shops.append(entry)
            preview = {"partial": True, "shops": shops, "note": "Full detail is in the response artifact."}
            try:
                artifact = self.artifacts.save(raw, "application/json")
            except (ResultError, OSError):
                preview.update(error="artifact_unavailable", note="Full detail could not be stored; only the summary is available.")
                return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps(preview, ensure_ascii=False))], structured_content=preview, is_error=True)
            preview["artifact"] = {k: artifact[k] for k in ("uri", "size", "mime_type")}
            return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps(preview, ensure_ascii=False)),
                                        types.ResourceLink(type="resource_link", uri=artifact["uri"], name="Shopee response", mime_type="application/json", size=artifact["size"])],
                                        structured_content=preview, is_error=error)
        return types.CallToolResult(content=[types.TextContent(type="text", text=raw.decode("utf-8"))],
                                    structured_content=data, is_error=error)

    async def call_tool(self, context, params):
        if params.name not in self._custom_schemas:
            try:
                self.catalog.get(params.name, self.policy)
            except CatalogError:
                raise MCPError(-32602, "Unknown or disabled tool") from None
            if isinstance(params.arguments, dict) and "context" in params.arguments:
                raise MCPError(-32602, "Invalid arguments")
            try:
                alias, arguments = self.registry.split_arguments(params.arguments)
            except (MultiShopError, TypeError, ValueError):
                raise MCPError(-32602, "An explicit configured shop alias is required") from None
            return await self._delegate(alias).call_tool(context, params.model_copy(update={"arguments": arguments}))

        arguments = params.arguments if params.arguments is not None else {}
        if not Draft202012Validator(self._custom_schemas[params.name]).is_valid(arguments):
            raise MCPError(-32602, "Invalid arguments")
        if params.name == "list_connected_shops":
            return self._result({"shops": self.registry.describe()})

        shops = arguments["shops"]
        # Validate the entire selection before any API request.
        try:
            aliases = [self.registry.resolve_alias(name) for name in shops]
        except (MultiShopError, TypeError, ValueError):
            raise MCPError(-32602, "Unknown shop alias") from None
        reports = []
        if params.name == "get_ads_balances":
            for alias in aliases:
                try:
                    payload = await self._execute_read(alias, BALANCE_API, {})
                    response = payload.get("response") if isinstance(payload, dict) else None
                    value = _to_decimal(response.get("total_balance")) if isinstance(response, dict) else None
                    if not isinstance(payload, dict) or payload.get("error") or value is None:
                        code = payload.get("error") if isinstance(payload, dict) else None
                        reports.append({"shop": alias, "ok": False, "error": "unavailable_or_invalid_response",
                                        "error_code": code[:128] if isinstance(code, str) and code else None})
                    else:
                        reports.append({"shop": alias, "ok": True, "total_balance": str(value),
                                        "data_timestamp": _to_int(response.get("data_timestamp")), "currency": None})
                except Exception:
                    reports.append({"shop": alias, "ok": False, "error": "request_failed"})
            return self._result({"shops": reports, "note": "Currency is not supplied by the balance API; no cross-shop sum is calculated."})

        # Validate the entire date range before making calls for any shop.
        from .ads_summary import parse_ads_date
        try:
            start = parse_ads_date(arguments["start_date"], "start_date")
            end = parse_ads_date(arguments["end_date"], "end_date")
            if start > end or (end - start).days + 1 > 366:
                raise AdsSummaryInputError("Invalid date range")
        except AdsSummaryInputError:
            raise MCPError(-32602, "Invalid date range") from None
        call_count = len(aliases) * (1 + (1 if start == end else len(plan_daily_chunks(start, end))))
        if call_count > 60:
            return self._result({"error": "request_too_large", "message": "Use fewer shops or a shorter date range; maximum 60 API calls."}, error=True)
        limiter = asyncio.Semaphore(3)
        async def one_shop(alias):
            async with limiter:
                async def execute(api_name, request):
                    return await self._execute_read(alias, api_name, request)
                try:
                    async with asyncio.timeout(60):
                        summary = await summarize_ads(execute, arguments["start_date"], arguments["end_date"],
                                                      include_raw=False, shop_label=alias)
                    return {"shop": alias, "summary": summary}
                except TimeoutError:
                    return {"shop": alias, "summary": None, "error": "shop_timeout"}
                except Exception:
                    return {"shop": alias, "summary": None, "error": "summary_failed"}
        # One total deadline per call so remote clients/proxies (~100-120s) always get an
        # answer; shops still running are reported as timed out, finished shops are kept.
        tasks = [asyncio.create_task(one_shop(alias)) for alias in aliases]
        try:
            await asyncio.wait(tasks, timeout=self.summary_deadline)
        finally:
            pending = [task for task in tasks if not task.done()]
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
        reports = []
        for alias, task in zip(aliases, tasks):
            if task.done() and not task.cancelled() and task.exception() is None:
                reports.append(task.result())
            else:
                reports.append({"shop": alias, "summary": None, "error": "shop_timeout"})
        return self._result({"shops": reports, "note": "Shop reports are separate; verify attribution, permissions and Seller Center reconciliation before reporting."})
