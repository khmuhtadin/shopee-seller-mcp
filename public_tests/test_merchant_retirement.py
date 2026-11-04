"""Retired merchant tools cannot be discovered or called, even by opt-in."""
import json
import subprocess
import sys

import httpx
import pytest
from mcp import Client
from mcp.shared.exceptions import MCPError
from mcp.types import CallToolRequestParams

from shopee_mcp.catalog import Catalog
from shopee_mcp.credentials import CredentialStore
from shopee_mcp.policy import Policy
from shopee_mcp.results import ArtifactStore
from shopee_mcp.server import MCPService
from shopee_mcp.transport import Transport
from test_credentials import make_env


@pytest.mark.asyncio
@pytest.mark.parametrize("selection", ["default", "explicit", "modules"])
async def test_retired_merchant_tools_are_absent_and_direct_calls_never_reach_http(tmp_path, selection):
    # Re-enabling even one retired entry must expose a tool or permit its direct
    # call here. Explicit allowlists must not override the retirement decision.
    catalog = Catalog()
    all_apis = frozenset(entry["api_name"] for entry in catalog.manifest["entries"])
    removed = [entry for entry in catalog.manifest["entries"]
               if entry["api_name"].startswith(("v2.global_product.", "v2.merchant."))]
    assert len(removed) == 40  # 38 removed tools plus two never registered APIs.
    policy = Policy(
        "test",
        endpoints=all_apis if selection == "explicit" else None,
        modules=frozenset({"global_product", "merchant", "shop"}) if selection == "modules" else None,
        allow_writes=all_apis if selection != "default" else frozenset(),
    )
    env = tmp_path / ".env"
    make_env(env)
    before = env.read_bytes()
    def reject_http(request):
        pytest.fail("retired tool lookup must not refresh credentials or send HTTP")
    async with httpx.AsyncClient(transport=httpx.MockTransport(reject_http)) as http:
        service = MCPService(catalog, policy, Transport(CredentialStore(env), client=http),
                             ArtifactStore(tmp_path / "artifacts"))
        async with Client(service.server) as client:
            page = await client.list_tools()
            names = {tool.name for tool in page.tools}
            while page.next_cursor:
                page = await client.list_tools(cursor=page.next_cursor)
                names.update(tool.name for tool in page.tools)
        assert not any(name.startswith(("v2_global_product_", "v2_merchant_")) for name in names)
        assert "v2_shop_get_shop_info" in names
        if selection == "default":
            assert len(names) == 237
            assert "v2_product_update_stock" not in names
        if selection == "explicit":
            assert len(names) == 406
            assert "v2_product_update_stock" in names
        for entry in removed:
            params = CallToolRequestParams(name=catalog.name_map[entry["api_name"]], arguments={"request": {}})
            with pytest.raises(MCPError) as caught:
                await service.call_tool(None, params)
            assert caught.value.error.code == -32602
    assert env.read_bytes() == before


def test_coverage_preserves_discovery_history_but_separates_retired_scope():
    coverage = Catalog().coverage()
    assert coverage["discovered"] == 450
    assert coverage.get("active") == 410
    assert coverage.get("retired") == 40
    assert coverage.get("retired_implemented") == 38
    assert coverage["implemented"] == coverage["contract_tested"] == 406
    assert coverage["unresolved"] == 4
    assert not coverage["all_supported"]


def test_unresolved_cli_reports_only_remaining_in_scope_gaps():
    result = subprocess.run([sys.executable, "-m", "shopee_mcp.catalog", "--unresolved", "--require-all"],
                            capture_output=True, text=True, check=False)
    assert result.returncode == 1
    coverage = json.loads(result.stdout)
    assert set(coverage["unresolved_apis"]) == {
        "v2.payment.get_escrow_detail_batch",
        "v2.logistics.upload_serviceable_polygon",
        "v2.public.get_access_token",
        "v2.public.get_token_by_resend_code",
    }
    assert len(coverage["unresolved_apis"]) == coverage["unresolved"]
