"""Integration tests for the read-only multi-shop MCP adapter.

Everything runs offline: each alias gets a real ``CredentialStore`` and a real
``Transport`` whose ``httpx.AsyncClient`` is backed by ``httpx.MockTransport``.
The fake Shopee router records every request so tests can prove which shop
(and which access token) was used, and that rejected input never reaches HTTP.
"""
import asyncio
import contextlib
import json
import sys
from datetime import date, timedelta

import httpx
import pytest
from mcp import Client, types
from mcp.client.stdio import StdioServerParameters
from mcp.shared.exceptions import MCPError

from shopee_mcp.ads_summary import plan_daily_chunks
from shopee_mcp.catalog import Catalog
from shopee_mcp.credentials import CredentialError, CredentialStore
from shopee_mcp.multi_server import MultiShopMCPService, _NoDefaultTransport
from shopee_mcp.multi_shop import MultiShopError, MultiShopRegistry
from shopee_mcp.policy import Policy
from shopee_mcp.results import ArtifactStore
from shopee_mcp.server import MCPService, parser, run
from shopee_mcp.transport import Transport
from shopee_mcp.validation import tool_input_schema
from test_credentials import make_env


# --------------------------------------------------------------------- fixtures

SHOPS = {
    # alias: (shop_id, access token, refresh token). Only store-a/store-b are
    # configured by default; the extra shops exist for the 60-call limit test.
    "store-a": (111, "access-a-secret", "refresh-a-secret"),
    "store-b": (222, "access-b-secret", "refresh-b-secret"),
    "store-d": (444, "access-d-secret", "refresh-d-secret"),
    "store-e": (555, "access-e-secret", "refresh-e-secret"),
    "store-f": (666, "access-f-secret", "refresh-f-secret"),
}
FIVE_SHOPS = ("store-a", "store-b", "store-d", "store-e", "store-f")
TOKEN_BY_SHOP_ID = {str(shop_id): token for shop_id, token, _ in SHOPS.values()}
ALL_SECRETS = tuple(secret for _, access, refresh in SHOPS.values() for secret in (access, refresh)) + ("partner-secret",)

BALANCE_PATH = "/api/v2/ads/get_total_balance"
DAILY_PATH = "/api/v2/ads/get_all_cpc_ads_daily_performance"
HOURLY_PATH = "/api/v2/ads/get_all_cpc_ads_hourly_performance"
SHOP_INFO_PATH = "/api/v2/shop/get_shop_info"
CUSTOM_TOOLS = {"list_connected_shops", "get_ads_balances", "get_ads_summary"}
MAX_SUMMARY_CALLS = 60


@pytest.fixture
def base(tmp_path):
    # MultiShopRegistry refuses group/world writable parents.
    tmp_path.chmod(0o700)
    return tmp_path


def write_env(base, alias):
    shop_id, access, refresh = SHOPS[alias]
    path = base / f"{alias}.env"
    # Access token valid at the injected clock (1000 < 5000): no refresh traffic.
    make_env(path, SHOPEE_SHOP_ID=str(shop_id), SHOPEE_ACCESS_TOKEN=access,
             SHOPEE_REFRESH_TOKEN=refresh, SHOPEE_ACCESS_TOKEN_EXPIRES_AT="5000")
    return path


def write_shops_file(base, aliases=("store-a", "store-b"), name="shops.json"):
    """Test credential files (one per alias) plus the owner-only alias registry."""
    envs = {alias: write_env(base, alias) for alias in aliases}
    path = base / name
    path.write_text(json.dumps({"shops": {alias: str(env) for alias, env in envs.items()}}))
    path.chmod(0o600)
    return path, envs


def snapshot_files(paths):
    return {path: path.read_bytes() for path in paths}


def ok(payload_response, request_id="req"):
    return {"error": "", "message": "", "request_id": request_id, "response": payload_response}


def info(**fields):
    """Envelope for response_key=None endpoints such as v2.shop.get_shop_info."""
    fields.setdefault("status", "NORMAL")  # status and region are required by the
    fields.setdefault("region", "ID")      # reviewed get_shop_info response schema
    return {"error": "", "message": "", "request_id": "info", **fields}


class FakeShopee:
    """httpx.MockTransport handler routing by (shop_id, path).

    Never raises inside the handler (that would surface as an unrelated server
    error); token/shop mismatches are recorded and asserted by the tests.
    """

    def __init__(self):
        self.requests = []
        self.mismatches = []
        self.routes = {}

    def route(self, alias, path, payload):
        self.routes[(str(SHOPS[alias][0]), path)] = payload

    def __call__(self, request):
        params = dict(request.url.params)
        shop_id, token = params.get("shop_id"), params.get("access_token")
        self.requests.append({"path": request.url.path, "shop_id": shop_id, "access_token": token, "params": params})
        if TOKEN_BY_SHOP_ID.get(shop_id) != token:
            self.mismatches.append((shop_id, token))
        handler = self.routes.get((shop_id, request.url.path))
        if handler is None:
            return httpx.Response(200, json={"error": "error_not_found", "message": "no fixture", "request_id": "nf"})
        payload = handler(request) if callable(handler) else handler
        if isinstance(payload, httpx.Response):
            return payload
        return httpx.Response(200, json=payload)

    def shops_called(self):
        return {entry["shop_id"] for entry in self.requests}

    def assert_clean(self):
        assert self.mismatches == [], "a request was signed with another shop's access token"


async def no_sleep(_):
    return None


@contextlib.asynccontextmanager
async def multi_service(base, fake, *, policy=None, aliases=("store-a", "store-b"), **kwargs):
    config, envs = write_shops_file(base, aliases)
    async with httpx.AsyncClient(transport=httpx.MockTransport(fake)) as http:
        registry = MultiShopRegistry.from_config_file(
            config,
            store_factory=lambda path: CredentialStore(path, clock=lambda: 1000),
            transport_factory=lambda store, **_: Transport(store, client=http, clock=lambda: 1000, sleep=no_sleep),
        )
        try:
            service = MultiShopMCPService(Catalog(), policy or Policy("multi"), registry,
                                          ArtifactStore(base / "artifacts"), **kwargs)
            yield service, registry, envs
        finally:
            await registry.close()


async def all_tools(client):
    page = await client.list_tools()
    tools = list(page.tools)
    while page.next_cursor:
        page = await client.list_tools(cursor=page.next_cursor)
        tools.extend(page.tools)
    return tools


async def assert_rejected(client, name, arguments):
    """Invalid input must fail at the MCP boundary (protocol error or error result)."""
    try:
        result = await client.call_tool(name, arguments)
    except MCPError:
        return None
    assert result.is_error, f"{name} accepted {arguments!r}"
    return result


def is_artifact_preview(data):
    return isinstance(data, dict) and data.get("partial") is True and isinstance(data.get("artifact"), dict)


async def full(client, result):
    """Structured content, following the artifact link when the result exceeded inline_bytes."""
    data = result.structured_content
    if is_artifact_preview(data):
        contents = await client.read_resource(data["artifact"]["uri"])
        return json.loads(contents.contents[0].text)
    return data


def dump(result):
    """Everything a client can see inline: text content plus structured content."""
    texts = [getattr(item, "text", "") for item in result.content]
    return json.dumps({"content": texts, "structured": result.structured_content}, ensure_ascii=False, default=str)


def assert_no_secrets(text, base=None):
    for secret in ALL_SECRETS:
        assert secret not in text, f"secret {secret!r} leaked"
    assert "sign=" not in text
    if base is not None:
        assert str(base) not in text and ".env" not in text


def daily_row(day, impression, clicks, d_order, d_sold, b_order, b_sold, expense, d_gmv, b_gmv):
    return {"date": day, "impression": impression, "clicks": clicks, "direct_order": d_order,
            "direct_item_sold": d_sold, "broad_order": b_order, "broad_item_sold": b_sold,
            "expense": expense, "direct_gmv": d_gmv, "broad_gmv": b_gmv,
            "ctr": 0.1, "direct_roas": 2.5, "broad_roas": 3.5}


DAYS = ("01-10-2026", "02-10-2026", "03-10-2026")
ROWS_A = [daily_row(day, 100, 10, 1, 2, 3, 4, 100.25, 1000.5, 2500) for day in DAYS]
ROWS_B = [daily_row(day, 50, 5, 0, 0, 1, 1, 7.5, 0, 80) for day in DAYS]
TOTALS_A = {"impression": 300, "clicks": 30, "direct_order": 3, "direct_item_sold": 6, "broad_order": 9,
            "broad_item_sold": 12, "expense": "300.75", "direct_gmv": "3001.5", "broad_gmv": "7500"}
TOTALS_B = {"impression": 150, "clicks": 15, "direct_order": 0, "direct_item_sold": 0, "broad_order": 3,
            "broad_item_sold": 3, "expense": "22.5", "direct_gmv": "0", "broad_gmv": "240"}


def route_ads(fake):
    fake.route("store-a", DAILY_PATH, ok(ROWS_A, "daily-a"))
    fake.route("store-b", DAILY_PATH, ok(ROWS_B, "daily-b"))
    fake.route("store-a", BALANCE_PATH, ok({"total_balance": 150000.5, "data_timestamp": 1790000000}, "bal-a"))
    fake.route("store-b", BALANCE_PATH, ok({"total_balance": 2500, "data_timestamp": 1790000001}, "bal-b"))


def route_empty_ads(fake, aliases):
    for alias in aliases:
        fake.route(alias, DAILY_PATH, ok([]))
        fake.route(alias, HOURLY_PATH, ok([]))
        fake.route(alias, BALANCE_PATH, ok({"total_balance": 1, "data_timestamp": 1}))


# ------------------------------------------------------------- construction/tools

async def test_construction_succeeds_and_delegates_are_isolated_per_shop(base):
    fake = FakeShopee()
    async with multi_service(base, fake) as (service, registry, _):
        a, b = service._delegate("store-a"), service._delegate("store-b")
        assert a is service._delegate("store-a") and a is not b
        assert a.transport is not b.transport
        assert a.transport.store.snapshot().subject_id == 111
        assert b.transport.store.snapshot().subject_id == 222
        assert a.policy.context == "store-a" and b.policy.context == "store-b"
        assert not a.policy.allow_writes and not b.policy.allow_writes
        assert a.artifacts is service.artifacts and a.inline_bytes == service.inline_bytes
    assert fake.requests == []


async def test_no_default_shop_transport(base):
    """The base service must never be wired to the first configured shop."""
    fake = FakeShopee()
    async with multi_service(base, fake) as (service, registry, _):
        # Construction and discovery create no per-shop transport at all.
        assert isinstance(service.transport, _NoDefaultTransport)
        assert service.transport.secrets == frozenset()
        assert registry._transports == {}
        async with Client(service.server) as client:
            await all_tools(client)
            await client.call_tool("list_connected_shops", {})
            await assert_rejected(client, "v2_shop_get_shop_info", {"request": {}})
            await assert_rejected(client, "v2_shop_get_shop_info", {"shop": None, "request": {}})
        assert registry._transports == {}
        # Even bypassing the multi-shop dispatcher, the inherited path cannot reach a shop.
        params = types.CallToolRequestParams(name="v2_shop_get_shop_info", arguments={"request": {}})
        with pytest.raises(RuntimeError, match="Explicit shop alias required"):
            await MCPService.call_tool(service, None, params)
        with pytest.raises(RuntimeError):
            await service.transport.execute({}, {})
        assert registry._transports == {}
    assert fake.requests == []


async def test_tools_list_requires_explicit_shop_and_is_read_only(base):
    fake = FakeShopee()
    async with multi_service(base, fake) as (service, _, envs):
        before = snapshot_files(envs.values())
        async with Client(service.server) as client:
            first = await client.list_tools()
            assert first.next_cursor is None  # every permitted tool on the first page
            tools = await all_tools(client)
        names = [tool.name for tool in tools]
        assert names == sorted(names) and len(names) == len(set(names))
        assert CUSTOM_TOOLS <= set(names)
        assert "v2_shop_get_shop_info" in names and "v2_product_get_item_list" in names
        # Read-only: no write or credential tools even though they exist in the catalog.
        assert "v2_product_update_stock" not in names
        assert "v2_public_refresh_access_token" not in names
        assert "call_endpoint" not in names
        catalog_names = [tool["name"] for tool in Catalog().tools(Policy("multi"))]
        assert set(names) - CUSTOM_TOOLS == set(catalog_names)
        for tool in tools:
            assert tool.annotations is not None and tool.annotations.read_only_hint is True, tool.name
            schema = tool.input_schema
            if tool.name in CUSTOM_TOOLS:
                continue
            assert "context" not in schema["properties"], tool.name
            assert schema["properties"]["shop"]["enum"] == ["store-a", "store-b"], tool.name
            assert schema["properties"]["shop"]["type"] == "string"
            assert "shop" in schema["required"] and "request" in schema["required"], tool.name
            assert schema.get("additionalProperties") is False
        by_name = {tool.name: tool for tool in tools}
        balances = by_name["get_ads_balances"].input_schema
        assert balances["required"] == ["shops"] and balances["additionalProperties"] is False
        assert balances["properties"]["shops"]["items"]["enum"] == ["store-a", "store-b"]
        assert balances["properties"]["shops"]["uniqueItems"] is True
        assert balances["properties"]["shops"]["maxItems"] == 2
        summary = by_name["get_ads_summary"].input_schema
        assert set(summary["required"]) == {"shops", "start_date", "end_date"}
        # Discovery is offline and never rotates credentials.
        assert fake.requests == []
        assert snapshot_files(envs.values()) == before


async def test_multi_shop_schema_is_derived_from_source_input_schema(base):
    """Each tool keeps the catalog's request/output schema; only context -> shop changes."""
    fake = FakeShopee()
    catalog = Catalog()
    async with multi_service(base, fake) as (service, _, _envs):
        served = {tool.name: tool for tool in service.tools}
        delegate = service._delegate("store-a")
        delegate_tools = {tool.name: tool for tool in delegate.tools}
        source_tools = {tool["name"]: tool for tool in catalog.tools(Policy("multi"))}
        assert set(served) - CUSTOM_TOOLS == set(source_tools)
        for name, source in source_tools.items():
            endpoint = catalog.get(name, Policy("multi"))
            schema = served[name].input_schema
            expected = tool_input_schema(endpoint, "multi")
            assert source["inputSchema"] == expected
            assert schema["properties"]["request"] == endpoint["input_schema"], name
            assert schema["properties"]["output"] == expected["properties"]["output"], name
            assert set(schema["properties"]) == {"shop", "request", "output"}, name
            assert schema["required"] == [*expected["required"], "shop"], name
            assert schema["additionalProperties"] is expected["additionalProperties"]
            assert served[name].output_schema == source["outputSchema"], name
            assert served[name].description == source["description"], name
            # model_copy must not leak the multi-shop schema into per-shop delegates.
            delegate_schema = delegate_tools[name].input_schema
            assert "shop" not in delegate_schema["properties"], name
            assert delegate_schema["properties"]["context"] == {"type": "string", "const": "store-a"}
            assert delegate_schema is not schema
    assert fake.requests == []


async def test_legacy_mcpservice_keeps_context_schema_without_shop(base):
    """Backward compatibility: single-shop MCPService is untouched by multi-shop mode."""
    fake = FakeShopee()
    env = write_env(base, "store-a")
    async with httpx.AsyncClient(transport=httpx.MockTransport(fake)) as http:
        transport = Transport(CredentialStore(env, clock=lambda: 1000), client=http, clock=lambda: 1000)
        service = MCPService(Catalog(), Policy("legacy"), transport, ArtifactStore(base / "artifacts"))
        async with Client(service.server) as client:
            tools = await all_tools(client)
    names = {tool.name for tool in tools}
    assert not names & CUSTOM_TOOLS
    shop_info = next(tool for tool in tools if tool.name == "v2_shop_get_shop_info")
    assert "shop" not in shop_info.input_schema["properties"]
    assert shop_info.input_schema["properties"]["context"]["const"] == "legacy"
    assert fake.requests == []


async def test_multi_shop_service_refuses_any_write_policy(base):
    config, _ = write_shops_file(base)
    registry = MultiShopRegistry.from_config_file(config, transport_factory=lambda store, **_: object())
    for allow in (frozenset({"*"}), frozenset({"v2.product.update_stock"})):
        with pytest.raises(ValueError, match="read-only"):
            MultiShopMCPService(Catalog(), Policy("multi", allow_writes=allow), registry, ArtifactStore(base / "artifacts"))


# ---------------------------------------------------------- explicit shop routing

async def test_explicit_shop_routes_to_its_own_credentials_without_cross_leak(base):
    fake = FakeShopee()
    fake.route("store-a", SHOP_INFO_PATH, info(shop_name="Toko A", region="ID"))
    fake.route("store-b", SHOP_INFO_PATH, info(shop_name="Toko B", region="ID"))
    async with multi_service(base, fake) as (service, _, _envs):
        async with Client(service.server) as client:
            result_b = await client.call_tool("v2_shop_get_shop_info", {"shop": "store-b", "request": {}})
            assert [entry["shop_id"] for entry in fake.requests] == ["222"]
            result_a = await client.call_tool("v2_shop_get_shop_info", {"shop": "store-a", "request": {}})
            assert [entry["shop_id"] for entry in fake.requests] == ["222", "111"]
    fake.assert_clean()
    assert not result_a.is_error and not result_b.is_error
    a, b = result_a.structured_content, result_b.structured_content
    assert a["data"]["shop_name"] == "Toko A" and b["data"]["shop_name"] == "Toko B"
    assert a["meta"]["context"] == "store-a" and b["meta"]["context"] == "store-b"
    assert "Toko B" not in dump(result_a) and "Toko A" not in dump(result_b)
    assert "access-b-secret" not in json.dumps(fake.requests[1]) and "access-a-secret" not in json.dumps(fake.requests[0])


@pytest.mark.parametrize("arguments", [
    {"request": {}},                                   # omitted: no default shop in multi mode
    {"shop": None, "request": {}},
    {"shop": "", "request": {}},
    {"shop": "store-c", "request": {}},                # not configured
    {"shop": "STORE-A", "request": {}},                # no case folding
    {"shop": "store-a ", "request": {}},
    {"shop": "store", "request": {}},                  # no prefix matching
    {"shop": 111, "request": {}},                      # shop id is not an alias
    {"shop": ["store-a"], "request": {}},
    {"shop": "/tmp/store-a.env", "request": {}},       # never a credential path
    {"shop": "store-a", "context": "store-b", "request": {}},  # cannot redirect via context
    {"shop": "store-a", "request": {"shop_id": "222"}},       # cannot inject another shop id
    {"shop": "store-a", "request": {"access_token": "access-b-secret"}},
])
async def test_shop_selection_is_explicit_exact_and_fails_closed_before_http(base, arguments):
    fake = FakeShopee()
    fake.route("store-a", SHOP_INFO_PATH, info(shop_name="Toko A"))
    fake.route("store-b", SHOP_INFO_PATH, info(shop_name="Toko B"))
    async with multi_service(base, fake) as (service, _, _envs):
        async with Client(service.server) as client:
            result = await assert_rejected(client, "v2_shop_get_shop_info", arguments)
    assert fake.requests == []
    if result is not None:
        assert_no_secrets(dump(result), base)
        assert "Toko" not in dump(result)


@pytest.mark.parametrize("context", ["store-a", "store-b", "multi", "", None, 1, {"shop": "store-b"}])
async def test_context_argument_is_rejected_even_when_it_matches_the_shop(base, context):
    """context is not part of the multi-shop schema; any value is invalid input and sends nothing."""
    fake = FakeShopee()
    fake.route("store-a", SHOP_INFO_PATH, info(shop_name="Toko A"))
    fake.route("store-b", SHOP_INFO_PATH, info(shop_name="Toko B"))
    async with multi_service(base, fake) as (service, registry, _envs):
        async with Client(service.server) as client:
            with pytest.raises(MCPError) as caught:
                await client.call_tool("v2_shop_get_shop_info", {"shop": "store-a", "context": context, "request": {}})
            assert caught.value.error.code == -32602
            # Without shop as well: still invalid, never routed to a default.
            await assert_rejected(client, "v2_shop_get_shop_info", {"context": context, "request": {}})
            for tool, arguments in (("get_ads_balances", {"shops": ["store-a"]}),
                                    ("get_ads_summary", {"shops": ["store-a"], "start_date": DAYS[0], "end_date": DAYS[2]}),
                                    ("list_connected_shops", {})):
                await assert_rejected(client, tool, {**arguments, "context": context})
        assert registry._transports == {}
    assert fake.requests == []


async def test_list_connected_shops_is_offline_and_exposes_only_aliases(base):
    fake = FakeShopee()
    async with multi_service(base, fake) as (service, _, _envs):
        async with Client(service.server) as client:
            result = await client.call_tool("list_connected_shops", {})
            assert not result.is_error
            assert result.structured_content == {"shops": [{"alias": "store-a", "env": "sandbox"},
                                                           {"alias": "store-b", "env": "sandbox"}]}
            assert json.loads(result.content[0].text) == result.structured_content
            text = dump(result)
            assert_no_secrets(text, base)
            assert "111" not in text and "222" not in text and "123456" not in text
            await assert_rejected(client, "list_connected_shops", {"shop": "store-a"})
    assert fake.requests == []


# ------------------------------------------------------------ read-only / policy

@pytest.mark.parametrize("tool", ["v2_product_update_stock", "v2_public_refresh_access_token", "v2_shop_update_profile"])
async def test_write_and_credential_tools_are_not_callable_even_with_shop(base, tool):
    fake = FakeShopee()
    async with multi_service(base, fake) as (service, registry, envs):
        before = snapshot_files(envs.values())
        async with Client(service.server) as client:
            await assert_rejected(client, tool, {"shop": "store-a", "request": {}})
            await assert_rejected(client, tool, {"shop": "store-a", "request": {
                "item_id": "1", "stock_list": [{"seller_stock": [{"stock": "1"}]}]}})
        assert snapshot_files(envs.values()) == before
        assert registry._transports == {}  # rejected before any shop is touched
    assert fake.requests == []


async def test_module_policy_hides_ads_tools_and_they_cannot_be_called(base):
    fake = FakeShopee()
    route_ads(fake)
    async with multi_service(base, fake, policy=Policy("multi", modules=frozenset({"shop"}))) as (service, _, _envs):
        async with Client(service.server) as client:
            names = {tool.name for tool in await all_tools(client)}
            assert "list_connected_shops" in names
            assert "get_ads_balances" not in names and "get_ads_summary" not in names
            assert all(name in CUSTOM_TOOLS or name.startswith("v2_shop_") for name in names)
            await assert_rejected(client, "get_ads_balances", {"shops": ["store-a"]})
            await assert_rejected(client, "get_ads_balances", {"shop": "store-a", "shops": ["store-a"]})
            await assert_rejected(client, "get_ads_summary", {"shops": ["store-a"], "start_date": DAYS[0], "end_date": DAYS[2]})
            await assert_rejected(client, "v2_ads_get_total_balance", {"shop": "store-a", "request": {}})
    assert fake.requests == []


async def test_endpoint_policy_exposes_balance_without_summary(base):
    fake = FakeShopee()
    route_ads(fake)
    policy = Policy("multi", endpoints=frozenset({"v2.ads.get_total_balance"}))
    async with multi_service(base, fake, policy=policy) as (service, _, _envs):
        async with Client(service.server) as client:
            names = {tool.name for tool in await all_tools(client)}
            assert names == {"list_connected_shops", "get_ads_balances", "v2_ads_get_total_balance"}
            await assert_rejected(client, "get_ads_summary", {"shops": ["store-a"], "start_date": DAYS[0], "end_date": DAYS[2]})
            assert fake.requests == []
            result = await client.call_tool("get_ads_balances", {"shops": ["store-a"]})
            assert result.structured_content["shops"][0]["ok"] is True
    assert [entry["path"] for entry in fake.requests] == [BALANCE_PATH]


async def test_shopee_permission_error_for_one_shop_does_not_affect_the_other(base):
    fake = FakeShopee()
    route_ads(fake)
    fake.route("store-b", BALANCE_PATH, {"error": "error_permission", "message": "no ads permission for access-b-secret",
                                         "request_id": "perm"})
    async with multi_service(base, fake) as (service, _, _envs):
        async with Client(service.server) as client:
            result = await client.call_tool("get_ads_balances", {"shops": ["store-a", "store-b"]})
    fake.assert_clean()
    assert not result.is_error
    reports = {report["shop"]: report for report in result.structured_content["shops"]}
    assert reports["store-a"]["ok"] is True and reports["store-a"]["total_balance"] == "150000.5"
    assert reports["store-b"] == {"shop": "store-b", "ok": False, "error": "unavailable_or_invalid_response",
                                  "error_code": "error_permission"}
    text = dump(result)
    assert_no_secrets(text, base)
    assert "no ads permission" not in text  # Shopee's free-text message is not surfaced


# ------------------------------------------------------------------- balances

async def test_ads_balances_are_per_shop_decimal_strings_in_requested_order(base):
    fake = FakeShopee()
    route_ads(fake)
    async with multi_service(base, fake) as (service, _, _envs):
        async with Client(service.server) as client:
            result = await client.call_tool("get_ads_balances", {"shops": ["store-b", "store-a"]})
    fake.assert_clean()
    assert not result.is_error
    data = result.structured_content
    assert data["shops"] == [
        {"shop": "store-b", "ok": True, "total_balance": "2500", "data_timestamp": 1790000001, "currency": None},
        {"shop": "store-a", "ok": True, "total_balance": "150000.5", "data_timestamp": 1790000000, "currency": None},
    ]
    assert all(isinstance(report["total_balance"], str) for report in data["shops"])
    assert set(data) == {"shops", "note"} and "no cross-shop sum" in data["note"]
    assert json.loads(result.content[0].text) == data
    assert sorted((entry["shop_id"], entry["path"]) for entry in fake.requests) == [
        ("111", BALANCE_PATH), ("222", BALANCE_PATH)]


@pytest.mark.parametrize("raw, expected", [
    ("150000.50", "150000.50"),     # numeric string keeps its digits
    (0, "0"),
    (0.1, "0.1"),                   # float goes through str(), not binary expansion
    (12345678901234567890, "12345678901234567890"),
])
async def test_ads_balance_total_is_lossless_decimal_string(base, raw, expected):
    fake = FakeShopee()
    route_ads(fake)
    fake.route("store-a", BALANCE_PATH, ok({"total_balance": raw, "data_timestamp": "1790000000"}))
    async with multi_service(base, fake) as (service, _, _envs):
        async with Client(service.server) as client:
            result = await client.call_tool("get_ads_balances", {"shops": ["store-a"]})
    report = result.structured_content["shops"][0]
    assert report["ok"] is True and report["total_balance"] == expected
    assert report["data_timestamp"] == 1790000000


async def test_ads_balance_for_one_shop_never_calls_the_other(base):
    fake = FakeShopee()
    route_ads(fake)
    async with multi_service(base, fake) as (service, registry, _envs):
        async with Client(service.server) as client:
            result = await client.call_tool("get_ads_balances", {"shops": ["store-a"]})
        assert set(registry._transports) == {"store-a"}
    assert [report["shop"] for report in result.structured_content["shops"]] == ["store-a"]
    assert fake.shops_called() == {"111"}
    fake.assert_clean()


@pytest.mark.parametrize("arguments", [
    {}, {"shops": []}, {"shops": "store-a"}, {"shops": ["store-a", "store-a"]},
    {"shops": ["store-a", "store-c"]},          # whole selection validated before any call
    {"shops": ["STORE-A"]}, {"shops": [111]}, {"shops": ["store-a"], "shop": "store-a"},
    {"shops": ["store-a"], "extra": True},
])
async def test_ads_balances_invalid_selection_makes_no_http_call(base, arguments):
    fake = FakeShopee()
    route_ads(fake)
    async with multi_service(base, fake) as (service, _, _envs):
        async with Client(service.server) as client:
            await assert_rejected(client, "get_ads_balances", arguments)
    assert fake.requests == []


@pytest.mark.parametrize("bad_balance", ["abc", None, {"amount": 1}, [1], True, False, "Infinity", "NaN", ""])
async def test_ads_balance_rejects_non_numeric_total_balance(base, bad_balance):
    fake = FakeShopee()
    route_ads(fake)
    fake.route("store-a", BALANCE_PATH, ok({"total_balance": bad_balance, "data_timestamp": 1}))
    async with multi_service(base, fake) as (service, _, _envs):
        async with Client(service.server) as client:
            result = await client.call_tool("get_ads_balances", {"shops": ["store-a", "store-b"]})
    assert not result.is_error
    reports = {report["shop"]: report for report in result.structured_content["shops"]}
    assert reports["store-a"] == {"shop": "store-a", "ok": False, "error": "unavailable_or_invalid_response",
                                  "error_code": None}
    assert reports["store-b"]["ok"] is True


async def test_ads_balance_missing_response_object_is_invalid(base):
    fake = FakeShopee()
    route_ads(fake)
    fake.route("store-a", BALANCE_PATH, {"error": "", "message": "", "request_id": "x"})
    async with multi_service(base, fake) as (service, _, _envs):
        async with Client(service.server) as client:
            result = await client.call_tool("get_ads_balances", {"shops": ["store-a"]})
    assert result.structured_content["shops"][0] == {
        "shop": "store-a", "ok": False, "error": "unavailable_or_invalid_response", "error_code": None}


async def test_ads_balance_nan_from_shopee_does_not_crash_the_tool(base):
    fake = FakeShopee()
    route_ads(fake)
    fake.route("store-a", BALANCE_PATH, httpx.Response(
        200, content=b'{"error":"","message":"","request_id":"n","response":{"total_balance":NaN,"data_timestamp":1}}',
        headers={"Content-Type": "application/json"}))
    async with multi_service(base, fake) as (service, _, _envs):
        async with Client(service.server) as client:
            result = await client.call_tool("get_ads_balances", {"shops": ["store-a", "store-b"]})
    assert not result.is_error
    reports = {report["shop"]: report for report in result.structured_content["shops"]}
    assert reports["store-a"]["ok"] is False and reports["store-b"]["ok"] is True
    assert "NaN" not in result.content[0].text


async def test_ads_balance_error_code_is_sanitized(base):
    """Only Shopee's error code (bounded, secret-redacted) is surfaced; never its message."""
    fake = FakeShopee()
    route_ads(fake)
    long_code = "error_" + "x" * 300
    fake.route("store-a", BALANCE_PATH, {"error": long_code, "message": "secret access-a-secret", "request_id": "1"})
    fake.route("store-b", BALANCE_PATH, {"error": "bad access-b-secret https://evil.test/p?sign=abc&access_token=q",
                                         "message": "m", "request_id": "2"})
    async with multi_service(base, fake) as (service, _, _envs):
        async with Client(service.server) as client:
            result = await client.call_tool("get_ads_balances", {"shops": ["store-a", "store-b"]})
    reports = {report["shop"]: report for report in result.structured_content["shops"]}
    assert reports["store-a"]["ok"] is False and reports["store-a"]["error_code"] == long_code[:128]
    assert len(reports["store-a"]["error_code"]) == 128
    code_b = reports["store-b"]["error_code"]
    assert code_b is not None and len(code_b) <= 128
    assert "access-b-secret" not in code_b and "evil.test" not in code_b and "[REDACTED" in code_b
    text = dump(result)
    assert_no_secrets(text, base)
    assert "secret access" not in text and '"m"' not in text


@pytest.mark.parametrize("code", [0, 1, ["error_x"], {"code": "x"}])
async def test_ads_balance_non_string_error_code_becomes_null(base, code):
    fake = FakeShopee()
    route_ads(fake)
    fake.route("store-a", BALANCE_PATH, {"error": code, "message": "", "request_id": "1",
                                         "response": {"total_balance": 5, "data_timestamp": 1}})
    async with multi_service(base, fake) as (service, _, _envs):
        async with Client(service.server) as client:
            result = await client.call_tool("get_ads_balances", {"shops": ["store-a"]})
    report = result.structured_content["shops"][0]
    if code == 0:
        # A falsy error means success.
        assert report["ok"] is True and report["total_balance"] == "5"
    else:
        assert report == {"shop": "store-a", "ok": False, "error": "unavailable_or_invalid_response", "error_code": None}


async def test_ads_balance_transport_failure_is_generic_and_secret_free(base):
    fake = FakeShopee()
    route_ads(fake)
    fake.route("store-a", BALANCE_PATH, httpx.Response(
        500, text=f"boom access-a-secret {DAILY_PATH}?sign=deadbeef"))
    async with multi_service(base, fake) as (service, _, _envs):
        async with Client(service.server) as client:
            result = await client.call_tool("get_ads_balances", {"shops": ["store-a", "store-b"]})
    reports = {report["shop"]: report for report in result.structured_content["shops"]}
    assert reports["store-a"] == {"shop": "store-a", "ok": False, "error": "request_failed"}
    assert reports["store-b"]["ok"] is True
    assert_no_secrets(dump(result), base)
    assert "boom" not in dump(result)


# -------------------------------------------------------------------- summary

async def test_ads_summary_is_separate_per_shop_with_exact_totals(base):
    fake = FakeShopee()
    route_ads(fake)
    async with multi_service(base, fake) as (service, _, envs):
        before = snapshot_files(envs.values())
        async with Client(service.server) as client:
            result = await client.call_tool("get_ads_summary", {"shops": ["store-b", "store-a"],
                                                               "start_date": DAYS[0], "end_date": DAYS[2]})
            data = await full(client, result)
        assert snapshot_files(envs.values()) == before
    fake.assert_clean()
    assert not result.is_error
    assert set(data) == {"shops", "note"}
    assert [entry["shop"] for entry in data["shops"]] == ["store-b", "store-a"]
    summaries = {entry["shop"]: entry["summary"] for entry in data["shops"]}
    for alias, totals, balance in (("store-a", TOTALS_A, "150000.5"), ("store-b", TOTALS_B, "2500")):
        summary = summaries[alias]
        assert summary["shop_label"] == alias
        assert summary["source"] == "daily"
        assert summary["status"] == "complete" and summary["complete"] is True
        assert summary["requested_dates"] == list(DAYS) == summary["covered_dates"]
        assert summary["missing_dates"] == [] and summary["failed_dates"] == []
        assert summary["totals"] == totals == summary["partial_totals"]
        assert summary["balance"]["ok"] is True and summary["balance"]["total_balance"] == balance
        # Direct and broad attribution stay separate; nothing is summed across them.
        assert "gmv" not in summary["totals"] and "orders" not in summary["totals"]
        # Raw payloads are dropped in the MCP surface.
        assert all(call["raw"] is None for call in summary["api_calls"])
        assert [call["api_name"] for call in summary["api_calls"]] == [
            "v2.ads.get_all_cpc_ads_daily_performance", "v2.ads.get_total_balance"]
        assert summary["api_calls"][0]["params"] == {"start_date": DAYS[0], "end_date": DAYS[2]}
    # No cross-shop totals anywhere.
    assert "totals" not in data and "total_balance" not in data
    # Each shop's daily call carried its own dates and credentials (order may interleave).
    daily = [entry for entry in fake.requests if entry["path"] == DAILY_PATH]
    assert sorted(entry["shop_id"] for entry in daily) == ["111", "222"]
    assert all(entry["params"]["start_date"] == DAYS[0] and entry["params"]["end_date"] == DAYS[2] for entry in daily)
    assert {entry["path"] for entry in fake.requests} == {DAILY_PATH, BALANCE_PATH}
    assert len(fake.requests) == 4


async def test_ads_summary_single_day_uses_hourly_endpoint(base):
    fake = FakeShopee()
    route_ads(fake)
    hours = [{"hour": hour, "date": DAYS[0], "impression": 10, "clicks": 2, "direct_order": 0, "direct_item_sold": 0,
              "broad_order": 0, "broad_item_sold": 0, "expense": 1.5, "direct_gmv": 3, "broad_gmv": 4}
             for hour in range(24)]
    fake.route("store-a", HOURLY_PATH, ok(hours))
    async with multi_service(base, fake) as (service, _, _envs):
        async with Client(service.server) as client:
            result = await client.call_tool("get_ads_summary", {"shops": ["store-a"], "start_date": DAYS[0],
                                                               "end_date": DAYS[0]})
            data = await full(client, result)
    summary = data["shops"][0]["summary"]
    assert summary["source"] == "hourly" and summary["status"] == "complete"
    assert summary["hours_covered"] == list(range(24))
    assert summary["totals"] == {"impression": 240, "clicks": 48, "direct_order": 0, "direct_item_sold": 0,
                                 "broad_order": 0, "broad_item_sold": 0, "expense": "36.0",
                                 "direct_gmv": "72", "broad_gmv": "96"}
    assert [entry["path"] for entry in fake.requests] == [HOURLY_PATH, BALANCE_PATH]
    assert fake.requests[0]["params"]["performance_date"] == DAYS[0]
    assert fake.shops_called() == {"111"}


async def test_ads_summary_failure_in_one_shop_is_explicit_and_isolated(base):
    fake = FakeShopee()
    route_ads(fake)
    fake.route("store-b", DAILY_PATH, {"error": "error_permission",
                                       "message": f"denied for access-b-secret see https://x.test{DAILY_PATH}?sign=abc",
                                       "request_id": "denied"})
    async with multi_service(base, fake) as (service, _, _envs):
        async with Client(service.server) as client:
            result = await client.call_tool("get_ads_summary", {"shops": ["store-a", "store-b"],
                                                               "start_date": DAYS[0], "end_date": DAYS[2]})
            data = await full(client, result)
    summaries = {entry["shop"]: entry["summary"] for entry in data["shops"]}
    assert summaries["store-a"]["status"] == "complete" and summaries["store-a"]["totals"] == TOTALS_A
    failed = summaries["store-b"]
    assert failed["status"] == "failed" and failed["totals"] is None
    assert failed["failed_dates"] == list(DAYS) and failed["partial_totals"] == {}
    assert any(issue["kind"] == "api_error" and issue["detail"].startswith("error_permission")
               for issue in failed["issues"])
    # Token redaction: the Shopee message echoed the access token and a signed URL.
    text = json.dumps(data, ensure_ascii=False) + dump(result)
    assert_no_secrets(text, base)
    assert "[REDACTED" in text
    fake.assert_clean()


async def test_ads_summary_redacts_secrets_from_warnings_and_rows(base):
    fake = FakeShopee()
    route_ads(fake)
    rows = [dict(row, note="access-a-secret") for row in ROWS_A]
    fake.route("store-a", DAILY_PATH, {"error": "", "message": "", "request_id": "w",
                                       "warning": "token access-a-secret refresh-a-secret partner-secret",
                                       "response": rows})
    async with multi_service(base, fake) as (service, _, _envs):
        async with Client(service.server) as client:
            result = await client.call_tool("get_ads_summary", {"shops": ["store-a"], "start_date": DAYS[0],
                                                               "end_date": DAYS[2]})
            data = await full(client, result)
    summary = data["shops"][0]["summary"]
    assert summary["totals"] == TOTALS_A
    assert any(issue["kind"] == "api_warning" for issue in summary["issues"])
    assert_no_secrets(json.dumps(data, ensure_ascii=False) + dump(result), base)


@pytest.mark.parametrize("dates", [
    ("2026-10-01", "03-10-2026"),     # ISO is not accepted
    ("01/10/2026", "03-10-2026"),
    ("31-02-2026", "03-03-2026"),     # not a real date
    ("03-10-2026", "01-10-2026"),     # reversed
    ("01-01-2025", "02-01-2026"),     # 367 days
    ("1-10-2026", "03-10-2026"),
    (20261001, "03-10-2026"),
])
async def test_ads_summary_invalid_dates_make_no_http_call_for_any_shop(base, dates):
    fake = FakeShopee()
    route_ads(fake)
    start, end = dates
    async with multi_service(base, fake) as (service, _, _envs):
        async with Client(service.server) as client:
            await assert_rejected(client, "get_ads_summary", {"shops": ["store-a", "store-b"],
                                                              "start_date": start, "end_date": end})
    assert fake.requests == []


@pytest.mark.parametrize("arguments", [
    {"shops": ["store-a", "store-x"], "start_date": DAYS[0], "end_date": DAYS[2]},
    {"shops": [], "start_date": DAYS[0], "end_date": DAYS[2]},
    {"shops": ["store-a"], "start_date": DAYS[0]},
    {"shops": ["store-a"], "start_date": DAYS[0], "end_date": DAYS[2], "include_raw": True},
    {"shop": "store-a", "start_date": DAYS[0], "end_date": DAYS[2]},
])
async def test_ads_summary_invalid_selection_makes_no_http_call(base, arguments):
    fake = FakeShopee()
    route_ads(fake)
    async with multi_service(base, fake) as (service, _, _envs):
        async with Client(service.server) as client:
            await assert_rejected(client, "get_ads_summary", arguments)
    assert fake.requests == []


async def test_366_day_range_passes_input_validation_without_requiring_calls(base):
    """366 days is the adapter's input maximum. Shopee only documents ~6 months of Ads
    history, so this test only checks the request is accepted (no protocol error) and
    any per-shop outcome is explicit; it does not demand a particular call pattern."""
    fake = FakeShopee()
    route_empty_ads(fake, ("store-a",))
    async with multi_service(base, fake) as (service, _, _envs):
        async with Client(service.server) as client:
            result = await client.call_tool("get_ads_summary", {"shops": ["store-a"], "start_date": "01-01-2024",
                                                               "end_date": "31-12-2024"})
            data = await full(client, result)
    assert not result.is_error
    assert [entry["shop"] for entry in data["shops"]] == ["store-a"]
    entry = data["shops"][0]
    if entry.get("summary") is not None:
        summary = entry["summary"]
        assert len(summary["requested_dates"]) == 366
        assert summary["status"] in {"complete", "partial", "failed"}
        assert summary["totals"] is None or summary["complete"] is True  # never zero-filled
    else:
        assert entry["error"] in {"summary_failed", "shop_timeout"}
    assert fake.shops_called() <= {"111"}
    assert len(fake.requests) <= MAX_SUMMARY_CALLS


# -------------------------------------------------------------- 60-call limit

def boundary_range(shop_count, start=date(2026, 1, 1)):
    """Return (within, over) end dates around the 60-call budget for ``shop_count`` shops."""
    end = start + timedelta(days=1)
    while shop_count * (1 + len(plan_daily_chunks(start, end))) <= MAX_SUMMARY_CALLS:
        end += timedelta(days=1)
    return start, end - timedelta(days=1), end


def fmt(value):
    return value.strftime("%d-%m-%Y")


async def test_ads_summary_over_60_calls_is_refused_before_any_http(base):
    fake = FakeShopee()
    route_empty_ads(fake, FIVE_SHOPS)
    start, _, over = boundary_range(len(FIVE_SHOPS))
    assert len(FIVE_SHOPS) * (1 + len(plan_daily_chunks(start, over))) > MAX_SUMMARY_CALLS
    assert (over - start).days + 1 <= 366  # the date range itself is valid
    async with multi_service(base, fake, aliases=FIVE_SHOPS) as (service, registry, _envs):
        async with Client(service.server) as client:
            result = await client.call_tool("get_ads_summary", {"shops": list(FIVE_SHOPS), "start_date": fmt(start),
                                                               "end_date": fmt(over)})
        assert registry._transports == {}
    assert result.is_error
    assert result.structured_content["error"] == "request_too_large"
    assert "60" in result.structured_content["message"]
    assert fake.requests == []


async def test_ads_summary_at_exactly_60_calls_is_allowed(base):
    fake = FakeShopee()
    route_empty_ads(fake, FIVE_SHOPS)
    start, within, _ = boundary_range(len(FIVE_SHOPS))
    expected_calls = len(FIVE_SHOPS) * (1 + len(plan_daily_chunks(start, within)))
    # Chunk counts grow by at most one per added day, so the last affordable range is exactly 60 calls.
    assert expected_calls == MAX_SUMMARY_CALLS
    async with multi_service(base, fake, aliases=FIVE_SHOPS) as (service, _, _envs):
        async with Client(service.server) as client:
            result = await client.call_tool("get_ads_summary", {"shops": list(FIVE_SHOPS), "start_date": fmt(start),
                                                               "end_date": fmt(within)})
            data = await full(client, result)
    assert not result.is_error
    assert [entry["shop"] for entry in data["shops"]] == list(FIVE_SHOPS)
    assert len(fake.requests) == expected_calls
    assert fake.shops_called() == {str(SHOPS[alias][0]) for alias in FIVE_SHOPS}
    fake.assert_clean()


async def test_call_budget_counts_shops_times_chunks(base):
    """Fewer shops make the same range affordable: the budget is per request, not per range."""
    fake = FakeShopee()
    route_empty_ads(fake, FIVE_SHOPS)
    start, _, over = boundary_range(len(FIVE_SHOPS))
    shops = ["store-a", "store-b"]
    async with multi_service(base, fake, aliases=FIVE_SHOPS) as (service, _, _envs):
        async with Client(service.server) as client:
            result = await client.call_tool("get_ads_summary", {"shops": shops, "start_date": fmt(start),
                                                               "end_date": fmt(over)})
            data = await full(client, result)
    assert not result.is_error
    assert [entry["shop"] for entry in data["shops"]] == shops
    assert fake.shops_called() == {"111", "222"}
    assert len(fake.requests) == len(shops) * (1 + len(plan_daily_chunks(start, over)))


async def test_single_day_budget_is_two_calls_per_shop(base):
    fake = FakeShopee()
    route_empty_ads(fake, FIVE_SHOPS)
    async with multi_service(base, fake, aliases=FIVE_SHOPS) as (service, _, _envs):
        async with Client(service.server) as client:
            result = await client.call_tool("get_ads_summary", {"shops": list(FIVE_SHOPS), "start_date": DAYS[0],
                                                               "end_date": DAYS[0]})
    assert not result.is_error
    assert len(fake.requests) == 2 * len(FIVE_SHOPS)
    assert {entry["path"] for entry in fake.requests} == {HOURLY_PATH, BALANCE_PATH}


# --------------------------------------------------------- oversized artifacts

async def test_oversized_custom_result_becomes_artifact(base):
    fake = FakeShopee()
    route_ads(fake)
    async with multi_service(base, fake, inline_bytes=1) as (service, _, _envs):
        async with Client(service.server) as client:
            result = await client.call_tool("get_ads_summary", {"shops": ["store-a", "store-b"],
                                                               "start_date": DAYS[0], "end_date": DAYS[2]})
            preview = result.structured_content
            assert not result.is_error
            assert is_artifact_preview(preview)
            assert set(preview) == {"partial", "artifact", "shops", "note"}
            # Compact per-shop totals stay visible; daily rows and call logs live only in the artifact.
            assert [entry["shop"] for entry in preview["shops"]] == ["store-a", "store-b"]
            assert preview["shops"][0]["summary"]["totals"] == TOTALS_A
            assert "rows" not in preview["shops"][0]["summary"] and "api_calls" not in preview["shops"][0]["summary"]
            artifact = preview["artifact"]
            assert set(artifact) == {"uri", "size", "mime_type"} and artifact["mime_type"] == "application/json"
            links = [item for item in result.content if getattr(item, "type", None) == "resource_link"]
            assert len(links) == 1 and str(links[0].uri) == artifact["uri"]
            assert links[0].size == artifact["size"]
            contents = await client.read_resource(artifact["uri"])
            text = contents.contents[0].text
    # Inline output carries no shop data; the artifact holds the full, redacted report.
    # Totals intentionally stay visible in the compact preview; daily rows do not.
    assert "300.75" in dump(result) and '"rows"' not in json.dumps(result.structured_content)
    assert len(text.encode("utf-8")) == artifact["size"] > 2048
    data = json.loads(text)
    summaries = {entry["shop"]: entry["summary"] for entry in data["shops"]}
    assert summaries["store-a"]["totals"] == TOTALS_A and summaries["store-b"]["totals"] == TOTALS_B
    assert_no_secrets(text, base)
    assert_no_secrets(dump(result), base)


async def test_small_custom_result_stays_inline_even_with_tiny_inline_bytes(base):
    """The artifact threshold is max(2048, inline_bytes); small results stay inline."""
    fake = FakeShopee()
    route_ads(fake)
    async with multi_service(base, fake, inline_bytes=1) as (service, _, _envs):
        async with Client(service.server) as client:
            balances = await client.call_tool("get_ads_balances", {"shops": ["store-a"]})
            shops = await client.call_tool("list_connected_shops", {})
    assert not is_artifact_preview(balances.structured_content)
    assert balances.structured_content["shops"][0]["total_balance"] == "150000.5"
    assert shops.structured_content["shops"][0]["alias"] == "store-a"


async def test_oversized_catalog_result_uses_delegate_artifact(base):
    fake = FakeShopee()
    fake.route("store-b", SHOP_INFO_PATH, info(shop_name="B" * 5000, region="ID"))
    async with multi_service(base, fake, inline_bytes=100) as (service, _, _envs):
        async with Client(service.server) as client:
            result = await client.call_tool("v2_shop_get_shop_info", {"shop": "store-b", "request": {}})
            envelope = result.structured_content
            assert not result.is_error and envelope["meta"]["partial"] is True
            assert envelope["meta"]["context"] == "store-b"
            artifact = envelope["data"]["artifact"]
            contents = await client.read_resource(artifact["uri"])
            body = json.loads(contents.contents[0].text)
    assert "B" * 5000 not in dump(result)
    assert body["shop_name"] == "B" * 5000
    assert fake.shops_called() == {"222"}


# --------------------------------------------- catalog tool redaction / input

async def test_catalog_tool_redacts_tokens_and_signed_urls(base):
    fake = FakeShopee()

    def echo(request):
        return {"error": "error_auth", "message": f"bad call {request.url} using access-a-secret", "request_id": "e"}
    fake.route("store-a", SHOP_INFO_PATH, echo)
    fake.route("store-b", SHOP_INFO_PATH, info(shop_name="Toko B access-b-secret partner-secret",
                                               access_token="access-b-secret"))
    async with multi_service(base, fake) as (service, _, _envs):
        async with Client(service.server) as client:
            failed = await client.call_tool("v2_shop_get_shop_info", {"shop": "store-a", "request": {}})
            succeeded = await client.call_tool("v2_shop_get_shop_info", {"shop": "store-b", "request": {}})
    assert failed.is_error and failed.structured_content["error"]["kind"] == "shopee_error"
    assert not succeeded.is_error
    for result in (failed, succeeded):
        assert_no_secrets(dump(result), base)
    assert "Toko B" in succeeded.structured_content["data"]["shop_name"]
    assert succeeded.structured_content["data"]["access_token"] == "[REDACTED]"
    fake.assert_clean()


@pytest.mark.parametrize("tool, request_body", [
    ("v2_product_get_item_list", {"page_size": 0}),
    ("v2_product_get_item_list", {"unknown_field": 1}),
    ("v2_ads_get_all_cpc_ads_daily_performance", {"start_date": DAYS[0], "end_date": DAYS[0]}),   # equal dates
    ("v2_ads_get_all_cpc_ads_daily_performance", {"start_date": DAYS[2], "end_date": DAYS[0]}),   # reversed
    ("v2_ads_get_all_cpc_ads_hourly_performance", {"performance_date": "2026-10-01"}),
])
async def test_invalid_catalog_input_returns_invalid_arguments_without_http(base, tool, request_body):
    fake = FakeShopee()
    route_ads(fake)
    async with multi_service(base, fake) as (service, _, envs):
        before = snapshot_files(envs.values())
        async with Client(service.server) as client:
            result = await client.call_tool(tool, {"shop": "store-a", "request": request_body})
        assert snapshot_files(envs.values()) == before
    assert result.is_error
    assert result.structured_content["error"]["kind"] == "invalid_arguments"
    assert result.structured_content["meta"]["context"] == "store-a"
    assert fake.requests == []


async def test_unknown_tool_is_rejected_before_shop_resolution(base):
    fake = FakeShopee()
    async with multi_service(base, fake) as (service, registry, _envs):
        async with Client(service.server) as client:
            for name in ("call_endpoint", "v2_does_not_exist"):
                with pytest.raises(MCPError) as caught:
                    await client.call_tool(name, {"shop": "store-a", "request": {}})
                assert caught.value.error.code == -32602
                await assert_rejected(client, name, {"request": {}})
        assert registry._transports == {}
    assert fake.requests == []


# -------------------------------------------------------------------------- CLI

async def test_cli_shops_file_check_is_offline_and_reports_served_tools(base, capsys):
    config, envs = write_shops_file(base)
    before = snapshot_files([config, *envs.values()])
    assert await run(parser().parse_args(["--shops-file", str(config), "--check"])) == 0
    output = capsys.readouterr().out
    report = json.loads(output)
    assert report["mode"] == "multi-shop-read-only"
    assert report["shops"] == [{"alias": "store-a", "env": "sandbox"}, {"alias": "store-b", "env": "sandbox"}]
    # --check now reports what the server actually serves, custom tools included.
    assert CUSTOM_TOOLS <= set(report["tools"])
    assert report["tools"] == sorted(report["tools"])
    assert set(report["tools"]) - CUSTOM_TOOLS == {tool["name"] for tool in Catalog().tools(Policy("ph-shop"))}
    assert "v2_product_update_stock" not in report["tools"]
    assert_no_secrets(output, base)
    assert "111" not in json.dumps(report["shops"]) and "222" not in json.dumps(report["shops"])
    assert snapshot_files([config, *envs.values()]) == before
    assert not (base / "local-data").exists()


async def test_cli_shops_file_check_respects_module_policy(base, capsys):
    config, _ = write_shops_file(base)
    assert await run(parser().parse_args(["--shops-file", str(config), "--check", "--module", "shop"])) == 0
    tools = set(json.loads(capsys.readouterr().out)["tools"])
    assert "list_connected_shops" in tools
    assert "get_ads_balances" not in tools and "get_ads_summary" not in tools


async def test_cli_legacy_env_file_check_is_unchanged(base, capsys):
    env = write_env(base, "store-a")
    before = env.read_bytes()
    assert await run(parser().parse_args(["--env-file", str(env), "--check", "--context", "legacy"])) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["context"] == "legacy"
    assert "mode" not in report and "shops" not in report
    assert report["tools"] == [tool["name"] for tool in Catalog().tools(Policy("legacy"))]
    assert not set(report["tools"]) & CUSTOM_TOOLS
    assert env.read_bytes() == before


@pytest.mark.parametrize("argv", [
    [],                                                      # one of the two is required
    ["--env-file", "/x/a.env", "--shops-file", "/x/shops.json"],  # mutually exclusive
])
def test_cli_requires_exactly_one_configuration_mode(argv):
    with pytest.raises(SystemExit):
        parser().parse_args(argv)


@pytest.mark.parametrize("allow", ["*", "v2.product.update_stock"])
async def test_cli_shops_file_refuses_allow_write(base, allow):
    config, envs = write_shops_file(base)
    before = snapshot_files(envs.values())
    for extra in ([], ["--check"]):
        with pytest.raises(ValueError, match="read-only"):
            await run(parser().parse_args(["--shops-file", str(config), "--allow-write", allow, *extra]))
    assert snapshot_files(envs.values()) == before


async def test_cli_legacy_env_file_still_accepts_allow_write_in_check(base, capsys):
    env = write_env(base, "store-a")
    assert await run(parser().parse_args(["--env-file", str(env), "--allow-write", "v2.product.update_stock",
                                          "--check", "--context", "legacy"])) == 0
    assert "v2_product_update_stock" in json.loads(capsys.readouterr().out)["tools"]


async def test_cli_shops_file_must_be_absolute_and_owner_only(base, monkeypatch):
    config, _ = write_shops_file(base)
    monkeypatch.chdir(base)
    with pytest.raises(CredentialError):
        await run(parser().parse_args(["--shops-file", config.name, "--check"]))
    config.chmod(0o644)
    with pytest.raises(MultiShopError) as caught:
        await run(parser().parse_args(["--shops-file", str(config), "--check"]))
    assert str(base) not in str(caught.value)


async def test_cli_env_file_cannot_be_given_a_shops_json(base):
    config, _ = write_shops_file(base)
    with pytest.raises(CredentialError):
        await run(parser().parse_args(["--env-file", str(config), "--check"]))


async def test_stdio_shops_file_serves_multi_shop_tools_offline(base):
    """End-to-end over stdio: also catches startup crashes that --check might not exercise."""
    config, envs = write_shops_file(base)
    before = snapshot_files([config, *envs.values()])
    params = StdioServerParameters(command=sys.executable, cwd=str(base),
                                   args=["-m", "shopee_mcp", "--shops-file", str(config), "--context", "offline"])
    async with asyncio.timeout(20):
        async with Client(params) as client:
            tools = await all_tools(client)
            names = {tool.name for tool in tools}
            assert CUSTOM_TOOLS <= names
            assert "v2_product_update_stock" not in names
            shop_info = next(tool for tool in tools if tool.name == "v2_shop_get_shop_info")
            assert shop_info.input_schema["properties"]["shop"]["enum"] == ["store-a", "store-b"]
            assert "context" not in shop_info.input_schema["properties"]
            listed = await client.call_tool("list_connected_shops", {})
            assert [shop["alias"] for shop in listed.structured_content["shops"]] == ["store-a", "store-b"]
            await assert_rejected(client, "v2_shop_get_shop_info", {"request": {}})
            await assert_rejected(client, "v2_shop_get_shop_info", {"shop": "store-a", "context": "offline", "request": {}})
    assert snapshot_files([config, *envs.values()]) == before


async def test_stdio_legacy_env_file_has_no_shop_argument(base):
    env = write_env(base, "store-a")
    params = StdioServerParameters(command=sys.executable, cwd=str(base),
                                   args=["-m", "shopee_mcp", "--env-file", str(env), "--context", "offline"])
    async with asyncio.timeout(20):
        async with Client(params) as client:
            tools = await all_tools(client)
    names = {tool.name for tool in tools}
    assert not names & CUSTOM_TOOLS
    shop_info = next(tool for tool in tools if tool.name == "v2_shop_get_shop_info")
    assert "shop" not in shop_info.input_schema["properties"]
    assert shop_info.input_schema["properties"]["context"]["const"] == "offline"
