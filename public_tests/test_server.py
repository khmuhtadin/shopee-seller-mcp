import asyncio
import base64
import json
import sys
from pathlib import Path

import httpx
import pytest
from mcp import Client
from mcp.client.stdio import StdioServerParameters
from mcp.shared.exceptions import MCPError
from mcp.types import PaginatedRequestParams

from shopee_mcp.catalog import Catalog
from shopee_mcp.credentials import CredentialStore
from shopee_mcp.policy import Policy
from shopee_mcp.results import ArtifactStore
from shopee_mcp.server import MCPService, parser, run
from shopee_mcp.transport import Transport
from test_credentials import make_env


@pytest.mark.asyncio
@pytest.mark.parametrize("arguments", [
    ["--timeout", "nan"], ["--timeout", "inf"], ["--concurrency", "0"],
    ["--artifact-ttl", "-1"], ["--inline-bytes", "0"], ["--max-response-bytes", "0"],
    ["--upload-root", "/does-not-exist-shopee-fixture"],
])
async def test_check_validates_runtime_limits_without_side_effects(tmp_path, arguments):
    path = tmp_path / ".env"
    make_env(path)
    before = path.read_bytes()
    args = parser().parse_args(["--env-file", str(path), "--check", *arguments])
    with pytest.raises(ValueError):
        await run(args)
    assert path.read_bytes() == before
    assert not (tmp_path / "local-data").exists()


@pytest.mark.asyncio
async def test_real_sdk_discovers_individual_tools_and_invalid_input_never_calls_http(tmp_path):
    path = tmp_path / ".env"
    make_env(path, SHOPEE_ACCESS_TOKEN_EXPIRES_AT="5000")
    def handler(request):
        pytest.fail("invalid input must not call HTTP")
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        transport = Transport(CredentialStore(path, clock=lambda: 1000), client=http, clock=lambda: 1000)
        service = MCPService(Catalog(), Policy("test"), transport, ArtifactStore(tmp_path / "artifacts"), page_size=1)
        async with Client(service.server) as client:
            page = await client.list_tools()
            tools = list(page.tools)
            while page.next_cursor:
                page = await client.list_tools(cursor=page.next_cursor)
                tools.extend(page.tools)
            assert len(tools) >= 3
            names = [tool.name for tool in tools]
            assert names == sorted(names)
            assert "v2_product_get_item_list" in names
            assert "call_endpoint" not in names
            result = await client.call_tool("v2_product_get_item_list", {"request": {"page_size": 0}})
            assert result.is_error
            assert result.structured_content["error"]["kind"] == "invalid_arguments"


@pytest.mark.asyncio
@pytest.mark.parametrize("selection", ["default", "all_opt_in", "shop", "empty"])
async def test_first_tools_list_response_contains_every_permitted_tool(tmp_path, selection):
    catalog = Catalog()
    policy = Policy(
        "test",
        modules=frozenset({"shop"}) if selection == "shop" else None,
        endpoints=frozenset() if selection == "empty" else None,
        allow_writes=frozenset(catalog.name_map) if selection == "all_opt_in" else frozenset(),
    )
    path = tmp_path / ".env"
    make_env(path)
    before = path.read_bytes()
    async with httpx.AsyncClient(transport=httpx.MockTransport(
        lambda request: pytest.fail("tool discovery must not call HTTP or refresh")
    )) as http:
        service = MCPService(catalog, policy, Transport(CredentialStore(path), client=http),
                             ArtifactStore(tmp_path / "artifacts"))
        async with Client(service.server) as client:
            page = await client.list_tools()
            names = [tool.name for tool in page.tools]
            assert page.next_cursor is None
            assert names == [tool["name"] for tool in catalog.tools(policy)]
            assert not any(name.startswith(("v2_global_product_", "v2_merchant_")) for name in names)
            if selection in {"default", "all_opt_in"}:
                assert len(names) > 100
                assert "v2_product_get_item_list" in names
                assert "v2_product_get_item_base_info" in names
                assert ("v2_product_update_stock" in names) == (selection == "all_opt_in")
            elif selection == "shop":
                assert "v2_shop_get_shop_info" in names
                assert all(name.startswith("v2_shop_") for name in names)
            else:
                assert names == []
    assert path.read_bytes() == before


@pytest.mark.asyncio
async def test_real_sdk_advertises_resources_and_lists_dynamic_artifacts(tmp_path):
    path = tmp_path / ".env"
    make_env(path, SHOPEE_ACCESS_TOKEN_EXPIRES_AT="5000")
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: pytest.fail("resource discovery must not call HTTP"))) as http:
        transport = Transport(CredentialStore(path, clock=lambda: 1000), client=http, clock=lambda: 1000)
        service = MCPService(Catalog(), Policy("test"), transport, ArtifactStore(tmp_path / "artifacts"))
        assert service.server.create_initialization_options().capabilities.resources is not None
        async with Client(service.server) as client:
            resources = await client.list_resources()
            assert resources.resources == []


@pytest.mark.asyncio
async def test_unknown_operator_module_fails_check_before_http(tmp_path):
    path = tmp_path / ".env"
    make_env(path, SHOPEE_ACCESS_TOKEN_EXPIRES_AT="5000")
    args = parser().parse_args(["--env-file", str(path), "--module", "prodcut", "--check"])
    with pytest.raises(ValueError, match="Unknown module"):
        await run(args)


@pytest.mark.asyncio
async def test_tools_list_rejects_malformed_cursor_with_invalid_params(tmp_path):
    path = tmp_path / ".env"
    make_env(path, SHOPEE_ACCESS_TOKEN_EXPIRES_AT="5000")
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: pytest.fail("cursor validation must not call HTTP"))) as http:
        transport = Transport(CredentialStore(path, clock=lambda: 1000), client=http, clock=lambda: 1000)
        service = MCPService(Catalog(), Policy("test"), transport, ArtifactStore(tmp_path / "artifacts"))
        with pytest.raises(MCPError) as caught:
            await service.list_tools(None, PaginatedRequestParams(cursor="not-valid-base64%%%"))
        assert caught.value.error.code == -32602


@pytest.mark.asyncio
async def test_tools_list_rejects_oversized_valid_cursor_with_invalid_params(tmp_path):
    path = tmp_path / ".env"
    make_env(path, SHOPEE_ACCESS_TOKEN_EXPIRES_AT="5000")
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: pytest.fail("cursor validation must not call HTTP"))) as http:
        transport = Transport(CredentialStore(path, clock=lambda: 1000), client=http, clock=lambda: 1000)
        service = MCPService(Catalog(), Policy("test"), transport, ArtifactStore(tmp_path / "artifacts"))
        cursor = base64.urlsafe_b64encode(json.dumps({
            "offset": 1, "version": service.cursor_version, "padding": "x" * 100_000,
        }).encode()).decode()
        with pytest.raises(MCPError) as caught:
            await service.list_tools(None, PaginatedRequestParams(cursor=cursor))
        assert caught.value.error.code == -32602


@pytest.mark.asyncio
async def test_real_sdk_call_and_resource_preserve_ids_and_artifact_content(tmp_path):
    path = tmp_path / ".env"
    make_env(path, SHOPEE_ACCESS_TOKEN_EXPIRES_AT="5000")
    def handler(request):
        return httpx.Response(200, json={"error": "", "request_id": "test", "response": {
            "item_list": [{"item_id": 9223372036854775807, "campaign_id": 1, "item_name": "x" * 200}],
            "cursor": "", "has_more": False, "total_count": 1,
        }})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        transport = Transport(CredentialStore(path, clock=lambda: 1000), client=http, clock=lambda: 1000)
        service = MCPService(Catalog(), Policy("test"), transport, ArtifactStore(tmp_path / "artifacts"), inline_bytes=50)
        async with Client(service.server) as client:
            result = await client.call_tool("v2_ams_get_open_campaign_added_product", {"request": {"page_size": 20}})
            assert not result.is_error
            envelope = result.structured_content
            assert envelope["meta"]["partial"]
            artifact = envelope["data"]["artifact"]
            contents = await client.read_resource(artifact["uri"])
            data = json.loads(contents.contents[0].text)
            assert data["item_list"][0]["item_id"] == "9223372036854775807"


@pytest.mark.asyncio
async def test_stdio_subprocess_initializes_outside_repository_without_refresh(tmp_path):
    path = tmp_path / ".env"
    make_env(path)  # Expired by wall clock; startup and tools/list must still be offline.
    before = path.read_bytes()
    params = StdioServerParameters(command=sys.executable, args=["-m", "shopee_mcp", "--env-file", str(path), "--context", "offline"], cwd=str(tmp_path))
    async with asyncio.timeout(15):
        async with Client(params) as client:
            page = await client.list_tools()
            names = [tool.name for tool in page.tools]
            assert page.next_cursor is None
            assert names == [tool["name"] for tool in Catalog().tools(Policy("offline"))]
            assert "v2_product_get_item_list" in names
            assert "v2_product_get_item_base_info" in names
            assert "v2_shop_get_shop_info" in names
            assert "v2_product_update_stock" not in names
    assert path.read_bytes() == before
    assert not (tmp_path / "local-data/shopee-mcp/locks").exists()
