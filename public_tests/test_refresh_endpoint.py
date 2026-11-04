import json

import httpx
import pytest

from shopee_mcp.catalog import Catalog, CatalogError
from shopee_mcp.credentials import CredentialStore
from shopee_mcp.policy import Policy
from shopee_mcp.transport import Transport
from test_credentials import make_env


@pytest.mark.asyncio
@pytest.mark.parametrize("scope,subject", [("shop", 987654), ("merchant", 55)])
async def test_refresh_is_internal_single_use_separate_scopes_and_persisted(tmp_path, scope, subject):
    path = tmp_path / ".env"
    make_env(path, SHOPEE_MERCHANT_ID="55", SHOPEE_MERCHANT_ACCESS_TOKEN="m-access",
             SHOPEE_MERCHANT_REFRESH_TOKEN="m-refresh", SHOPEE_MERCHANT_ACCESS_TOKEN_EXPIRES_AT="1100",
             SHOPEE_MERCHANT_REFRESH_TOKEN_EXPIRES_AT="9000", SHOPEE_MERCHANT_AUTH_EXPIRES_AT="9000")
    seen = []
    def handler(request):
        seen.append(request)
        assert request.url.path == "/api/v2/auth/access_token/get"
        assert "access_token" not in request.url.params and "shop_id" not in request.url.params
        assert json.loads(request.content) == {"partner_id": 123456, scope + "_id": subject,
                                               "refresh_token": "refresh-secret" if scope == "shop" else "m-refresh"}
        return httpx.Response(200, json={"error": "", "access_token": "new-access", "refresh_token": "new-refresh", "expire_in": 14400,
                                        "partner_id": 123456, scope + "_id": subject})
    store = CredentialStore(path, clock=lambda: 1000)
    catalog = Catalog()
    with pytest.raises(CatalogError):
        catalog.get("v2_public_refresh_access_token", Policy("fixture"))
    endpoint = catalog.get("v2_public_refresh_access_token", Policy("fixture", allow_writes=frozenset({"v2.public.refresh_access_token"})))
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        transport = Transport(store, refresh_client=client, clock=lambda: 1000)
        try:
            result = await transport.execute(endpoint, {"scope": scope})
        finally:
            await transport.close()
    assert len(seen) == 1
    assert result["response"] == {"status": "refreshed", "scope": scope, "access_token_expires_at": 15400, "refresh_token_expires_at": 2593000}
    assert "new-refresh" not in json.dumps(result)
    assert store.snapshot(scope).refresh_token == "new-refresh"
