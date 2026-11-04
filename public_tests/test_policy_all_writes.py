"""A write wildcard expands consent without overriding catalog or scope gates."""
from contextlib import asynccontextmanager
import json

import httpx
import pytest
from mcp import Client
from mcp.shared.exceptions import MCPError
from mcp.types import CallToolRequestParams

from shopee_mcp.catalog import Catalog
from shopee_mcp.credentials import CredentialStore
from shopee_mcp.policy import Policy
from shopee_mcp.results import ArtifactStore
from shopee_mcp.server import MCPService, parser, run
from shopee_mcp.transport import Transport
from test_credentials import make_env


@pytest.fixture
def catalog():
    return Catalog()


def reject_http(request):
    pytest.fail("policy checks and tool discovery must not send HTTP or refresh")


@asynccontextmanager
async def service_for(tmp_path, catalog, policy, handler=reject_http):
    path = tmp_path / ".env"
    make_env(path, SHOPEE_ACCESS_TOKEN_EXPIRES_AT="5000")
    before = path.read_bytes()
    with httpx.Client(transport=httpx.MockTransport(reject_http)) as refresh_http:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            transport = Transport(CredentialStore(path, clock=lambda: 1000), client=http,
                                  refresh_client=refresh_http, clock=lambda: 1000)
            yield MCPService(catalog, policy, transport, ArtifactStore(tmp_path / "artifacts"))
    assert path.read_bytes() == before


@pytest.mark.parametrize("overrides,permitted", [
    ({}, True),
    ({"effects": "credential"}, True),
    ({"effects": "read"}, True),
    ({"exposure": "enabled"}, True),
    ({"implementation": "partial"}, True),
    ({"review_status": "discovered"}, False),
    ({"implementation": "unimplemented"}, False),
    ({"exposure": "disabled"}, False),
    ({"exposure": "retired"}, False),
])
def test_wildcard_preserves_review_implementation_and_exposure_gates(overrides, permitted):
    endpoint = {"api_name": "v2.shop.update_profile", "module": "shop",
                "review_status": "verified", "implementation": "implemented",
                "exposure": "opt_in", "effects": "write", **overrides}
    assert Policy("test", allow_writes=frozenset({"*"})).permits(endpoint) is permitted


@pytest.mark.asyncio
async def test_wildcard_lists_all_406_active_tools_and_preserves_effect_annotations(tmp_path, catalog):
    async with service_for(tmp_path, catalog, Policy("test", allow_writes=frozenset({"*"}))) as service:
        async with Client(service.server) as client:
            page = await client.list_tools()
    tools = {tool.name: tool for tool in page.tools}
    assert page.next_cursor is None
    assert len(tools) == 406
    assert "v2_product_update_stock" in tools
    assert tools["v2_shop_get_shop_info"].annotations.read_only_hint is True
    assert tools["v2_shop_update_profile"].annotations.read_only_hint is False
    assert tools["v2_public_refresh_access_token"].annotations.read_only_hint is False
    assert not any(name.startswith(("v2_global_product_", "v2_merchant_")) for name in tools)


@pytest.mark.asyncio
@pytest.mark.parametrize("allow_writes,permitted", [
    (frozenset(), False),
    (frozenset({"*"}), True),
    (frozenset({"v2.shop.update_profile"}), True),
    (frozenset({"v2.product.update_stock"}), False),
])
async def test_write_call_requires_wildcard_or_its_exact_api_name(tmp_path, catalog, allow_writes, permitted):
    seen = []

    def update_profile(request):
        seen.append(request)
        assert request.method == "POST"
        assert request.url.path == "/api/v2/shop/update_profile"
        assert json.loads(request.content) == {"description": "fixture description"}
        return httpx.Response(200, json={"error": "", "request_id": "fixture",
                                        "response": {"description": "fixture description"}})

    async with service_for(tmp_path, catalog, Policy("test", allow_writes=allow_writes), update_profile) as service:
        params = CallToolRequestParams(name="v2_shop_update_profile",
                                      arguments={"request": {"description": "fixture description"}})
        if permitted:
            result = await service.call_tool(None, params)
            assert not result.is_error
            assert result.structured_content["data"]["description"] == "fixture description"
            assert len(seen) == 1
        else:
            with pytest.raises(MCPError) as caught:
                await service.call_tool(None, params)
            assert caught.value.error.code == -32602
            assert not seen


@pytest.mark.asyncio
async def test_wildcard_rejects_retired_disabled_and_unimplemented_direct_calls(tmp_path, catalog):
    # Simulate an operator disabling one otherwise executable endpoint.
    catalog.endpoints["v2_shop_update_profile"]["exposure"] = "disabled"
    blocked = {
        "v2_shop_update_profile",
        "v2_merchant_get_merchant_info",
        "v2_global_product_get_global_item_list",
        "v2_payment_get_escrow_detail_batch",
        "v2_logistics_upload_serviceable_polygon",
        "v2_public_get_access_token",
        "v2_public_get_token_by_resend_code",
    }
    async with service_for(tmp_path, catalog, Policy("test", allow_writes=frozenset({"*"}))) as service:
        page = await service.list_tools(None, None)
        assert not blocked.intersection(tool.name for tool in page.tools)
        for name in blocked:
            with pytest.raises(MCPError) as caught:
                await service.call_tool(None, CallToolRequestParams(name=name, arguments={"request": {}}))
            assert caught.value.error.code == -32602


@pytest.mark.asyncio
@pytest.mark.parametrize("modules,endpoints,want", [
    (None, frozenset({"v2.shop.get_shop_info", "v2.shop.update_profile"}),
     {"v2_shop_get_shop_info", "v2_shop_update_profile"}),
    (frozenset({"product"}), frozenset({"v2.shop.update_profile", "v2.product.update_stock"}),
     {"v2_product_update_stock"}),
    (frozenset({"shop"}), frozenset({"v2.product.update_stock"}), set()),
    (None, frozenset(), set()),
    (frozenset(), None, set()),
])
async def test_wildcard_keeps_module_and_endpoint_filter_intersection(tmp_path, catalog, modules, endpoints, want):
    policy = Policy("test", modules=modules, endpoints=endpoints, allow_writes=frozenset({"*"}))
    async with service_for(tmp_path, catalog, policy) as service:
        page = await service.list_tools(None, None)
        assert {tool.name for tool in page.tools} == want
        for name in {"v2_shop_update_profile", "v2_product_update_stock"} - want:
            with pytest.raises(MCPError) as caught:
                await service.call_tool(None, CallToolRequestParams(name=name, arguments={"request": {}}))
            assert caught.value.error.code == -32602


@pytest.mark.asyncio
@pytest.mark.parametrize("allow_names,count", [
    (["*"], 406),
    (["v2.shop.update_profile", "v2.product.update_stock"], 239),
])
async def test_check_accepts_wildcard_or_repeated_exact_write_names_offline(tmp_path, capsys, allow_names, count):
    path = tmp_path / ".env"
    make_env(path)
    before = path.read_bytes()
    flags = [part for name in allow_names for part in ("--allow-write", name)]
    args = parser().parse_args(["--env-file", str(path), "--check", *flags])
    assert await run(args) == 0
    names = json.loads(capsys.readouterr().out)["tools"]
    assert len(names) == count
    assert "v2_shop_update_profile" in names
    assert "v2_product_update_stock" in names
    assert ("v2_public_refresh_access_token" in names) == ("*" in allow_names)
    assert path.read_bytes() == before
    assert not (tmp_path / "local-data").exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("flags", [
    ["--allow-write", "v2.shop.update_profle"],
    ["--allow-write", "*", "--allow-write", "v2.shop.update_profle"],
    ["--endpoint", "*"],
    ["--allow-write", "*", "--endpoint", "*"],
])
async def test_wildcard_is_only_valid_as_allow_write_and_does_not_hide_typos(tmp_path, flags):
    path = tmp_path / ".env"
    make_env(path)
    before = path.read_bytes()
    args = parser().parse_args(["--env-file", str(path), "--check", *flags])
    with pytest.raises(ValueError, match="Unknown endpoint"):
        await run(args)
    assert path.read_bytes() == before
    assert not (tmp_path / "local-data").exists()
