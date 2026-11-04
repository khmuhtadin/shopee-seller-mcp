"""Scope isolation based on public refresh and principal reference contracts."""
import hashlib
import hmac
import json

import httpx
import pytest

from shopee_mcp.credentials import CredentialError, CredentialStore, read_values
from shopee_mcp.catalog import Catalog
from shopee_mcp.policy import Policy
from shopee_mcp.signing import signed_parameters
from shopee_mcp.transport import Transport
from shopee_mcp.validation import validate_arguments
from test_credentials import make_env


SCOPES = ("merchant", "supplier", "user", "principal")


@pytest.mark.parametrize("scope", ("shop",) + SCOPES)
def test_all_documented_refresh_subjects_have_individual_configured_scope_contract(scope):
    item = Catalog().get("v2_public_refresh_access_token", Policy(
        "fixture", allow_writes=frozenset({"v2.public.refresh_access_token"})))
    assert validate_arguments(item, {"request": {"scope": scope}}, "fixture")[0] == {"scope": scope}
    assert item["implementation"] == "implemented"
    assert item["scope_coverage"]["unresolved"] == []


def scope_env(path):
    extra = {}
    for index, scope in enumerate(SCOPES, 1):
        prefix = f"SHOPEE_{scope.upper()}_"
        extra.update({prefix + "ID": str(index),
                      prefix + "ACCESS_TOKEN": scope + "-access",
                      prefix + "REFRESH_TOKEN": scope + "-refresh",
                      prefix + "ACCESS_TOKEN_EXPIRES_AT": "1100",
                      prefix + "REFRESH_TOKEN_EXPIRES_AT": "9000",
                      prefix + "AUTH_EXPIRES_AT": "9999999"})
    make_env(path, **extra)


@pytest.mark.parametrize("scope", SCOPES)
def test_missing_scope_is_local_error_and_never_falls_back_to_shop(tmp_path, scope):
    path = tmp_path / ".env"
    make_env(path)
    store = CredentialStore(path, clock=lambda: 1000)
    with pytest.raises(CredentialError, match=f"SHOPEE_{scope.upper()}_ID"):
        store.snapshot(scope)
    assert store.snapshot("shop").refresh_token == "refresh-secret"


@pytest.mark.parametrize("scope", SCOPES)
def test_named_scopes_have_distinct_bindings_and_secrets(tmp_path, scope):
    path = tmp_path / ".env"
    scope_env(path)
    before = path.read_bytes()
    store = CredentialStore(path, clock=lambda: 1000)
    snapshot = store.snapshot(scope)
    assert snapshot.scope == scope
    assert snapshot.subject_id == SCOPES.index(scope) + 1
    assert snapshot.access_token == scope + "-access"
    assert snapshot.refresh_token == scope + "-refresh"
    assert snapshot.binding != store.snapshot("shop").binding
    assert path.read_bytes() == before


@pytest.mark.parametrize("scope,api_path", [
    ("principal", "/api/v2/principal/get_principal_sales_performance_detail"),
    ("user", "/api/v2/video/get_video_list"),
])
def test_business_signature_uses_documented_subject_sequence(tmp_path, scope, api_path):
    path = tmp_path / ".env"
    scope_env(path)
    store = CredentialStore(path, clock=lambda: 1000)
    subject = SCOPES.index(scope) + 1
    expected = hmac.new(b"partner-secret", f"123456{api_path}1000{scope}-access{subject}".encode(), hashlib.sha256).hexdigest()
    assert signed_parameters(store.snapshot(scope), api_path, 1000, scope) == {
        "partner_id": 123456, "timestamp": 1000, "access_token": scope + "-access",
        scope + "_id": subject, "sign": expected,
    }
    with pytest.raises(CredentialError, match="scope"):
        signed_parameters(store.snapshot("shop"), api_path, 1000, scope)


@pytest.mark.parametrize("scope", ("supplier", "user", "principal"))
def test_refresh_is_public_signed_and_rotates_only_selected_configured_scope(tmp_path, scope):
    path = tmp_path / ".env"
    scope_env(path)
    before = read_values(path)
    store = CredentialStore(path, clock=lambda: 1000)
    snapshot = store.snapshot(scope)
    calls = []

    def handler(request):
        calls.append(request)
        body = json.loads(request.content)
        assert body == {"partner_id": 123456, scope + "_id": snapshot.subject_id,
                        "refresh_token": scope + "-refresh"}
        assert set(request.url.params) == {"partner_id", "timestamp", "sign"}
        expected = hmac.new(b"partner-secret", b"123456/api/v2/auth/access_token/get1000", hashlib.sha256).hexdigest()
        assert request.url.params["sign"] == expected
        return httpx.Response(200, json={"error": "", "access_token": scope + "-new-access",
                                        "refresh_token": scope + "-new-refresh", "expire_in": 14400,
                                        "partner_id": 123456, scope + "_id": snapshot.subject_id})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        transport = Transport(store, refresh_client=client, clock=lambda: 1000)
        try:
            result = store.ensure(transport.refresh, scope=scope, force=True)
        finally:
            import asyncio
            asyncio.run(transport.close())
    assert len(calls) == 1
    assert result.access_token == scope + "-new-access"
    assert result.access_token_expires_at == 15400
    # Principal was added after the published 30-day clause; do not invent an
    # extension. Retain the operator's existing absolute refresh deadline.
    assert result.refresh_token_expires_at == (9000 if scope == "principal" else 2593000)
    after = read_values(path)
    prefix = f"SHOPEE_{scope.upper()}_"
    for key, value in before.items():
        if not key.startswith(prefix):
            assert after[key] == value
    assert after[prefix + "REFRESH_TOKEN"] == scope + "-new-refresh"


@pytest.mark.parametrize("scope", ("supplier",))
def test_unverified_business_signature_is_not_invented_for_refresh_only_scopes(tmp_path, scope):
    path = tmp_path / ".env"
    scope_env(path)
    store = CredentialStore(path, clock=lambda: 1000)
    with pytest.raises(CredentialError, match="Unsupported authentication scope"):
        signed_parameters(store.snapshot(scope), "/api/v2/test/unsupported", 1000, scope)


def test_principal_expired_configured_deadline_does_not_contact_remote(tmp_path):
    path = tmp_path / ".env"
    scope_env(path)
    store = CredentialStore(path, clock=lambda: 9001)
    with pytest.raises(CredentialError, match="expired"):
        store.ensure(lambda _: pytest.fail("expired token cannot be refreshed"), scope="principal")
