"""Offline tests for the remote HTTP mode (bearer tokens, OAuth 2.1, stateless MCP).

The ASGI app runs in-process through ``httpx.ASGITransport``; no socket, no
Shopee request. The MCP service is the real read-only multi-shop service with
local credential files whose transport must never be used.
"""
import contextlib
import html
import json
import logging
import os
import re
import secrets
import stat
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from shopee_mcp.catalog import Catalog
from shopee_mcp.credentials import CredentialStore
from shopee_mcp.http_auth import AuthStore, AuthStoreError, OAuthError, hash_secret, pkce_s256, validate_redirect_uri
from shopee_mcp.http_server import PASSPHRASE_LIMITER, Throttle, create_app, parser, run
from shopee_mcp.multi_server import MultiShopMCPService
from shopee_mcp.multi_shop import MultiShopRegistry
from shopee_mcp.policy import Policy
from shopee_mcp.results import ArtifactStore
from test_credentials import make_env

PUBLIC = "https://mcp.example.com"
RESOURCE = PUBLIC + "/mcp"
PRM = PUBLIC + "/.well-known/oauth-protected-resource/mcp"
REDIRECT = "https://chatgpt.com/connector_platform_oauth_redirect"
PASSPHRASE = "correct horse battery staple"
MCP_HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json",
               "MCP-Protocol-Version": "2025-06-18"}


class Clock:
    def __init__(self, now=1_800_000_000):
        self.now = now

    def __call__(self):
        return self.now


class NeverTransport:
    secrets = frozenset()

    async def execute(self, *_args, **_kwargs):
        raise AssertionError("Shopee must not be called in HTTP tests")

    async def close(self):
        return None


@pytest.fixture
def base(tmp_path):
    tmp_path.chmod(0o700)
    return tmp_path


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def service(base):
    envs = {}
    for alias, shop_id in (("store-a", 111), ("store-b", 222)):
        path = base / f"{alias}.env"
        make_env(path, SHOPEE_SHOP_ID=str(shop_id), SHOPEE_ACCESS_TOKEN=f"access-{alias}",
                 SHOPEE_REFRESH_TOKEN=f"refresh-{alias}", SHOPEE_ACCESS_TOKEN_EXPIRES_AT="5000")
        envs[alias] = path
    registry = MultiShopRegistry(envs, store_factory=lambda path: CredentialStore(path, clock=lambda: 1000),
                                 transport_factory=lambda store, **_: NeverTransport())
    return MultiShopMCPService(Catalog(), Policy("multi"), registry, ArtifactStore(base / "artifacts"))


def new_store(base, clock, **kwargs):
    store = AuthStore(base / "auth.db", create=True, clock=clock, **kwargs)
    if not store.has_admin_passphrase():
        store.set_admin_passphrase(PASSPHRASE)
    return store


@contextlib.asynccontextmanager
async def serving(app, ip="203.0.113.7"):
    async with app.run():
        async with client_for(app, ip) as client:
            yield client


def client_for(app, ip):
    transport = httpx.ASGITransport(app=app, client=(ip, 40000))
    return httpx.AsyncClient(transport=transport, base_url=PUBLIC, follow_redirects=False)


async def rpc(client, token, method, params=None, *, request_id=1, headers=None):
    sent = dict(MCP_HEADERS)
    if token:
        sent["Authorization"] = f"Bearer {token}"
    sent.update(headers or {})
    body = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params or {}}
    return await client.post("/mcp", headers=sent, content=json.dumps(body))


async def tool_names(client, token):
    response = await rpc(client, token, "tools/list")
    assert response.status_code == 200, response.text
    return {tool["name"] for tool in response.json()["result"]["tools"]}


def pkce():
    verifier = secrets.token_urlsafe(48)
    return verifier, pkce_s256(verifier)


async def register(client, redirect=REDIRECT):
    response = await client.post("/register", json={
        "client_name": "Test connector", "redirect_uris": [redirect], "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"]})
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["token_endpoint_auth_method"] == "none" and "client_secret" not in body
    return body["client_id"]


def auth_params(client_id, challenge, redirect=REDIRECT, **extra):
    params = {"response_type": "code", "client_id": client_id, "redirect_uri": redirect, "code_challenge": challenge,
              "code_challenge_method": "S256", "state": "state-123", "resource": RESOURCE, "scope": "mcp"}
    params.update(extra)
    return params


async def consent(client, client_id, challenge, *, passphrase=PASSPHRASE, decision="approve"):
    params = auth_params(client_id, challenge)
    page = await client.get("/authorize", params=params)
    assert page.status_code == 200, page.text
    assert page.headers["cache-control"] == "no-store"
    assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
    csrf = html.unescape(re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1))
    return await client.post("/authorize", data={**params, "csrf_token": csrf, "passphrase": passphrase,
                                                  "decision": decision})


def redirect_query(response):
    assert response.status_code == 303, response.text
    location = response.headers["location"]
    assert location.startswith(REDIRECT + "?")
    return {key: values[0] for key, values in parse_qs(urlsplit(location).query).items()}


async def oauth_tokens(client, *, client_id=None):
    client_id = client_id or await register(client)
    verifier, challenge = pkce()
    query = redirect_query(await consent(client, client_id, challenge))
    assert query["state"] == "state-123" and query["iss"] == PUBLIC
    response = await client.post("/token", data={"grant_type": "authorization_code", "code": query["code"],
                                                  "redirect_uri": REDIRECT, "client_id": client_id,
                                                  "code_verifier": verifier, "resource": RESOURCE})
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    return client_id, response.json()


def db_bytes(base):
    """Database plus WAL contents (recent writes may live only in the WAL)."""
    return b"".join(path.read_bytes() for path in (base / "auth.db", base / "auth.db-wal") if path.exists())


def server_logs(caplog):
    """Log lines produced by the server side (the httpx test client logs its own URLs)."""
    return "\n".join(record.getMessage() for record in caplog.records
                     if not record.name.startswith(("httpx", "httpcore")))


async def refresh(client, client_id, refresh_token):
    return await client.post("/token", data={"grant_type": "refresh_token", "refresh_token": refresh_token,
                                             "client_id": client_id, "resource": RESOURCE})


# ------------------------------------------------------------------ tests

async def test_metadata_endpoints_and_401_challenge(base, clock, service):
    app = create_app(service, new_store(base, clock), PUBLIC, clock=clock)
    async with serving(app) as client:
        for path in ("/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"):
            prm = (await client.get(path)).json()
            assert prm["resource"] == RESOURCE and prm["authorization_servers"] == [PUBLIC]
        meta = (await client.get("/.well-known/oauth-authorization-server")).json()
        assert meta["issuer"] == PUBLIC
        assert meta["authorization_endpoint"] == PUBLIC + "/authorize"
        assert meta["token_endpoint"] == PUBLIC + "/token"
        assert meta["registration_endpoint"] == PUBLIC + "/register"
        assert meta["code_challenge_methods_supported"] == ["S256"]
        assert meta["token_endpoint_auth_methods_supported"] == ["none"]
        assert set(meta["grant_types_supported"]) == {"authorization_code", "refresh_token"}
        unauthenticated = await rpc(client, None, "tools/list")
        assert unauthenticated.status_code == 401
        challenge = unauthenticated.headers["www-authenticate"]
        assert challenge.startswith("Bearer ") and f'resource_metadata="{PRM}"' in challenge
        health = await client.get("/healthz")
        assert health.status_code == 200 and health.json()["status"] == "ok"


async def test_static_bearer_ok_invalid_and_revoked(base, clock, service):
    store = new_store(base, clock)
    token_id, token = store.create_static_token("laptop")
    assert len(token) >= 43
    assert stat.S_IMODE(os.stat(base / "auth.db").st_mode) == 0o600
    assert token.encode() not in db_bytes(base)
    assert hash_secret(token).encode() in db_bytes(base)
    for suffix in ("-wal", "-shm"):
        sidecar = base / f"auth.db{suffix}"
        if sidecar.exists():
            assert stat.S_IMODE(os.stat(sidecar).st_mode) == 0o600
    listed = store.list_static_tokens()
    assert [row["id"] for row in listed] == [token_id] and token not in json.dumps(listed)
    app = create_app(service, store, PUBLIC, clock=clock)
    async with serving(app) as client:
        assert {"list_connected_shops", "get_ads_summary"} <= await tool_names(client, token)
        bad = await rpc(client, token + "x", "tools/list")
        assert bad.status_code == 401 and 'error="invalid_token"' in bad.headers["www-authenticate"]
        basic = await client.post("/mcp", headers={**MCP_HEADERS, "Authorization": f"Basic {token}"}, content="{}")
        assert basic.status_code == 401
        assert store.revoke_static_token(token_id)
        assert (await rpc(client, token, "tools/list")).status_code == 401


async def test_stateless_calls_without_session_id(base, clock, service):
    store = new_store(base, clock)
    _, token = store.create_static_token("cli")
    app = create_app(service, store, PUBLIC, clock=clock)
    async with serving(app) as client:
        init = await rpc(client, token, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                                       "clientInfo": {"name": "test", "version": "1"}})
        assert init.status_code == 200, init.text
        assert "mcp-session-id" not in init.headers
        assert init.headers["content-type"].startswith("application/json")
        # No initialize and no session header on this request: stateless mode must still answer.
        call = await rpc(client, token, "tools/call", {"name": "list_connected_shops", "arguments": {}}, request_id=7)
        assert call.status_code == 200, call.text
        body = call.json()
        assert body["id"] == 7 and "store-a" in json.dumps(body["result"])
        no_header = await rpc(client, token, "tools/list", headers={"MCP-Protocol-Version": "2025-03-26"})
        assert no_header.status_code == 200
        get = await client.get("/mcp", headers={"Authorization": f"Bearer {token}", "Accept": "text/event-stream"})
        assert get.status_code == 405


async def test_oauth_full_flow(base, clock, service, caplog):
    caplog.set_level(logging.DEBUG)
    app = create_app(service, new_store(base, clock), PUBLIC, clock=clock)
    async with serving(app) as client:
        client_id, tokens = await oauth_tokens(client)
        assert tokens["token_type"] == "Bearer" and tokens["expires_in"] == 24 * 3600
        assert "list_connected_shops" in await tool_names(client, tokens["access_token"])
    database = db_bytes(base)
    for secret in (tokens["access_token"], tokens["refresh_token"], PASSPHRASE):
        assert secret.encode() not in database
        assert secret not in server_logs(caplog)
    assert "state-123" not in server_logs(caplog) and "code_challenge" not in server_logs(caplog)
    assert "POST /token 200" in server_logs(caplog)


async def test_pkce_mismatch_and_single_use_code(base, clock, service):
    app = create_app(service, new_store(base, clock), PUBLIC, clock=clock)
    async with serving(app) as client:
        client_id = await register(client)
        verifier, challenge = pkce()
        code = redirect_query(await consent(client, client_id, challenge))["code"]
        wrong = await client.post("/token", data={"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
                                                  "client_id": client_id, "code_verifier": pkce()[0]})
        assert wrong.status_code == 400 and wrong.json()["error"] == "invalid_grant"
        retry = await client.post("/token", data={"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
                                                  "client_id": client_id, "code_verifier": verifier})
        assert retry.status_code == 400 and retry.json()["error"] == "invalid_grant"
        plain = await client.get("/authorize", params=auth_params(client_id, challenge, code_challenge_method="plain"))
        assert redirect_query(plain)["error"] == "invalid_request"


async def test_redirect_uri_rules(base, clock, service):
    app = create_app(service, new_store(base, clock), PUBLIC, clock=clock)
    async with serving(app) as client:
        for evil in ("https://evil.example.com/cb", "http://chatgpt.com/cb", "https://chatgpt.com.evil.example/cb",
                     "https://claude.ai/cb#frag", "javascript:alert(1)"):
            response = await client.post("/register", json={"redirect_uris": [evil]})
            assert response.status_code == 400 and response.json()["error"] == "invalid_redirect_uri", evil
        loopback = await client.post("/register", json={"redirect_uris": ["http://127.0.0.1:33418/callback"]})
        assert loopback.status_code == 201
        client_id = await register(client)
        _, challenge = pkce()
        for redirect in ("https://chatgpt.com/other", REDIRECT + "/", "https://claude.ai/api/mcp/auth_callback"):
            response = await client.get("/authorize", params=auth_params(client_id, challenge, redirect=redirect))
            assert response.status_code == 400 and "location" not in response.headers
        unknown = await client.get("/authorize", params=auth_params("smcp_c_unknown", challenge))
        assert unknown.status_code == 400 and "location" not in unknown.headers


async def test_consent_csrf_deny_and_wrong_passphrase(base, clock, service):
    app = create_app(service, new_store(base, clock), PUBLIC, clock=clock)
    async with serving(app) as client:
        client_id = await register(client)
        _, challenge = pkce()
        forged = await client.post("/authorize", data={**auth_params(client_id, challenge), "passphrase": PASSPHRASE,
                                                       "decision": "approve", "csrf_token": "1.deadbeef"})
        assert forged.status_code == 403 and "location" not in forged.headers
        denied = redirect_query(await consent(client, client_id, challenge, decision="deny"))
        assert denied["error"] == "access_denied" and "code" not in denied
        wrong = await consent(client, client_id, challenge, passphrase="not the passphrase")
        assert wrong.status_code == 403 and "location" not in wrong.headers
        assert "Incorrect passphrase" in wrong.text


async def test_passphrase_throttling_per_ip_and_window(base, clock, service):
    app = create_app(service, new_store(base, clock), PUBLIC, clock=clock)
    async with app.run():
        async with client_for(app, "198.51.100.1") as attacker, client_for(app, "198.51.100.2") as operator:
            client_id = await register(attacker)
            _, challenge = pkce()
            for _ in range(5):
                assert (await consent(attacker, client_id, challenge, passphrase="wrong guess 123")).status_code == 403
            locked = await consent(attacker, client_id, challenge)
            assert locked.status_code == 429 and "location" not in locked.headers
            assert redirect_query(await consent(operator, client_id, challenge))["code"]
            clock.now += 901
            assert redirect_query(await consent(attacker, client_id, challenge))["code"]


def test_throttle_global_lockout():
    clock = Clock()
    throttle = Throttle(per_key=5, global_limit=20, window=900, clock=clock)
    for index in range(20):
        assert throttle.retry_after(f"ip-{index}") == 0
        throttle.failure(f"ip-{index}")
    assert throttle.retry_after("fresh-ip") > 0
    clock.now += 901
    assert throttle.retry_after("fresh-ip") == 0


async def test_refresh_rotation_with_grace(base, clock, service):
    app = create_app(service, new_store(base, clock), PUBLIC, clock=clock)
    async with serving(app) as client:
        client_id, first = await oauth_tokens(client)
        r0 = first["refresh_token"]
        rotated = await refresh(client, client_id, r0)
        assert rotated.status_code == 200, rotated.text
        r1 = rotated.json()["refresh_token"]
        assert r1 != r0 and rotated.headers["cache-control"] == "no-store"
        # The old access token keeps working until it expires.
        assert "list_connected_shops" in await tool_names(client, first["access_token"])
        clock.now += 60
        duplicate = await refresh(client, client_id, r0)  # lost response / retried request
        assert duplicate.status_code == 200, duplicate.text
        r2 = duplicate.json()["refresh_token"]
        # Both the first and the grace-issued successors remain usable.
        r3 = await refresh(client, client_id, r1)
        assert r3.status_code == 200
        r4 = await refresh(client, client_id, r2)
        assert r4.status_code == 200
        # A further replay of r0 (grace already consumed) revokes the whole grant.
        third = await refresh(client, client_id, r0)
        assert third.status_code == 400 and third.json()["error"] == "invalid_grant"
        for successor in (r3, r4):
            assert (await refresh(client, client_id, successor.json()["refresh_token"])).status_code == 400
            assert (await rpc(client, successor.json()["access_token"], "tools/list")).status_code == 401
        assert (await rpc(client, first["access_token"], "tools/list")).status_code == 401


async def test_refresh_reuse_after_grace_revokes_grant(base, clock, service):
    app = create_app(service, new_store(base, clock), PUBLIC, clock=clock)
    async with serving(app) as client:
        client_id, victim = await oauth_tokens(client)
        _, bystander = await oauth_tokens(client, client_id=client_id)
        rotated = await refresh(client, client_id, victim["refresh_token"])
        assert rotated.status_code == 200
        clock.now += 121
        late = await refresh(client, client_id, victim["refresh_token"])
        assert late.status_code == 400 and late.json()["error"] == "invalid_grant"
        assert (await refresh(client, client_id, rotated.json()["refresh_token"])).status_code == 400
        assert (await rpc(client, rotated.json()["access_token"], "tools/list")).status_code == 401
        assert (await rpc(client, victim["access_token"], "tools/list")).status_code == 401
        # Other grants of the same client are untouched; a wrong client_id revokes nothing.
        assert (await refresh(client, "smcp_c_other", bystander["refresh_token"])).status_code == 400
        assert "list_connected_shops" in await tool_names(client, bystander["access_token"])
        assert (await refresh(client, client_id, bystander["refresh_token"])).status_code == 200


async def test_revoke_refresh_token_revokes_grant_and_code_replay(base, clock, service):
    app = create_app(service, new_store(base, clock), PUBLIC, clock=clock)
    async with serving(app) as client:
        client_id, tokens = await oauth_tokens(client)
        assert (await client.post("/revoke", data={"token": tokens["refresh_token"]})).status_code == 200
        assert (await rpc(client, tokens["access_token"], "tools/list")).status_code == 401
        assert (await refresh(client, client_id, tokens["refresh_token"])).status_code == 400
        # Replaying an already exchanged code revokes the tokens issued from it.
        verifier, challenge = pkce()
        code = redirect_query(await consent(client, client_id, challenge))["code"]
        exchange = {"grant_type": "authorization_code", "code": code, "client_id": client_id, "code_verifier": verifier}
        # redirect_uri may be omitted: the client has exactly one registered.
        issued = await client.post("/token", data=exchange)
        assert issued.status_code == 200, issued.text
        assert "list_connected_shops" in await tool_names(client, issued.json()["access_token"])
        replay = await client.post("/token", data={**exchange, "redirect_uri": REDIRECT})
        assert replay.status_code == 400 and replay.json()["error"] == "invalid_grant"
        assert (await rpc(client, issued.json()["access_token"], "tools/list")).status_code == 401
        assert (await refresh(client, client_id, issued.json()["refresh_token"])).status_code == 400


async def test_tokens_survive_restart(base, clock, service):
    store = new_store(base, clock)
    _, static_token = store.create_static_token("ci")
    first_app = create_app(service, store, PUBLIC, clock=clock)
    async with serving(first_app) as client:
        client_id, tokens = await oauth_tokens(client)
    # Simulated restart: fresh store object and fresh app over the same database file.
    clock.now += 3600
    restarted = create_app(service, AuthStore(base / "auth.db", clock=clock), PUBLIC, clock=clock)
    async with serving(restarted) as client:
        assert "list_connected_shops" in await tool_names(client, tokens["access_token"])
        assert "list_connected_shops" in await tool_names(client, static_token)
        renewed = await refresh(client, client_id, tokens["refresh_token"])
        assert renewed.status_code == 200
        assert "list_connected_shops" in await tool_names(client, renewed.json()["access_token"])
    clock.now += 24 * 3600 + 1
    expired_app = create_app(service, AuthStore(base / "auth.db", clock=clock), PUBLIC, clock=clock)
    async with serving(expired_app) as client:
        assert (await rpc(client, tokens["access_token"], "tools/list")).status_code == 401
        assert (await rpc(client, static_token, "tools/list")).status_code == 200


async def test_audience_binding(base, clock, service):
    store = new_store(base, clock)
    app = create_app(service, store, PUBLIC, clock=clock)
    async with serving(app) as client:
        _, tokens = await oauth_tokens(client)
        bad_resource = await client.get("/authorize", params=auth_params(
            (await register(client)), pkce()[1], resource="https://other.example.com/mcp"))
        assert redirect_query(bad_resource)["error"] == "invalid_target"
    other = create_app(service, store, "https://other.example.com", clock=clock)
    async with other.run():
        transport = httpx.ASGITransport(app=other, client=("203.0.113.9", 1))
        async with httpx.AsyncClient(transport=transport, base_url="https://other.example.com") as client:
            response = await rpc(client, tokens["access_token"], "tools/list")
            assert response.status_code == 401


async def test_callback_is_static_and_not_cached(base, clock, service, caplog):
    caplog.set_level(logging.DEBUG)
    app = create_app(service, new_store(base, clock), PUBLIC, clock=clock)
    async with serving(app) as client:
        response = await client.get("/callback", params={"code": "shopee-code-secret", "shop_id": "123"})
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["referrer-policy"] == "no-referrer"
        assert "shopee-code-secret" not in response.text
    assert "shopee-code-secret" not in server_logs(caplog) and "shop_id" not in server_logs(caplog)
    assert "GET /callback 200" in server_logs(caplog)


def test_auth_file_must_be_owner_only(base, clock):
    store = new_store(base, clock)
    assert store.has_admin_passphrase()
    (base / "auth.db").chmod(0o644)
    with pytest.raises(AuthStoreError):
        AuthStore(base / "auth.db", clock=clock)
    with pytest.raises(AuthStoreError):
        AuthStore("relative/auth.db")


def test_http_mode_rejects_allow_write(base):
    args = parser().parse_args(["serve", "--shops-file", str(base / "shops.json"), "--auth-file", str(base / "auth.db"),
                                "--public-url", PUBLIC, "--allow-write", "*"])
    with pytest.raises(ValueError):
        run(args)
    with pytest.raises(ValueError):
        run(parser().parse_args(["serve", "--shops-file", str(base / "shops.json"), "--auth-file", str(base / "auth.db"),
                                 "--public-url", "http://mcp.example.com"]))


# ------------------------------------------------------- security review

async def test_parallel_passphrase_verification_is_capped(base, clock, service):
    app = create_app(service, new_store(base, clock), PUBLIC, clock=clock)
    async with serving(app) as client:
        client_id = await register(client)
        _, challenge = pkce()
        holders = [object(), object()]
        for holder in holders:  # two verifications "in flight"
            PASSPHRASE_LIMITER.acquire_on_behalf_of_nowait(holder)
        try:
            busy = await consent(client, client_id, challenge)
            assert busy.status_code == 429 and "location" not in busy.headers
        finally:
            for holder in holders:
                PASSPHRASE_LIMITER.release_on_behalf_of(holder)
        assert redirect_query(await consent(client, client_id, challenge))["code"]


async def test_consent_form_token_is_single_use(base, clock, service):
    app = create_app(service, new_store(base, clock), PUBLIC, clock=clock)
    async with serving(app) as client:
        client_id = await register(client)
        _, challenge = pkce()
        params = auth_params(client_id, challenge)
        page = await client.get("/authorize", params=params)
        csrf = html.unescape(re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1))
        assert "Only approve if you just clicked Connect in ChatGPT/Claude" in page.text
        assert client_id in page.text and html.escape(REDIRECT) in page.text
        form = {**params, "csrf_token": csrf, "passphrase": "wrong guess 123", "decision": "approve"}
        assert (await client.post("/authorize", data=form)).status_code == 403
        replay = await client.post("/authorize", data={**form, "passphrase": PASSPHRASE})
        assert replay.status_code == 403 and "location" not in replay.headers
        assert "already submitted" in replay.text


async def test_mcp_methods_and_paths_require_auth(base, clock, service):
    app = create_app(service, new_store(base, clock), PUBLIC, clock=clock)
    async with serving(app) as client:
        for method in ("OPTIONS", "HEAD", "GET", "DELETE"):
            response = await client.request(method, "/mcp")
            assert response.status_code == 401, method
            assert "resource_metadata=" in response.headers["www-authenticate"]
        assert (await client.post("/mcp/x", content="{}")).status_code == 404


async def test_client_ip_header_only_trusted_from_loopback(base, clock, service):
    app = create_app(service, new_store(base, clock), PUBLIC, clock=clock, client_ip_header="X-Real-IP")
    headers = [(b"x-real-ip", b"192.0.2.55")]
    assert app.client_ip({"client": ("198.51.100.9", 1), "headers": headers}) == "198.51.100.9"
    assert app.client_ip({"client": ("127.0.0.1", 1), "headers": headers}) == "192.0.2.55"
    plain = create_app(service, AuthStore(base / "auth.db", clock=clock), PUBLIC, clock=clock)
    assert plain.client_ip({"client": ("127.0.0.1", 1), "headers": headers}) == "127.0.0.1"


async def test_spoofed_x_real_ip_does_not_bypass_throttle(base, clock, service):
    app = create_app(service, new_store(base, clock), PUBLIC, clock=clock, client_ip_header="X-Real-IP")
    async with serving(app, ip="198.51.100.20") as client:
        client_id = await register(client)
        _, challenge = pkce()
        for index in range(5):
            client.headers["X-Real-IP"] = f"192.0.2.{index}"
            assert (await consent(client, client_id, challenge, passphrase="wrong guess 123")).status_code == 403
        client.headers["X-Real-IP"] = "192.0.2.200"
        assert (await consent(client, client_id, challenge)).status_code == 429


async def test_malformed_registration_bodies_are_400(base, clock, service):
    app = create_app(service, new_store(base, clock), PUBLIC, clock=clock)
    async with serving(app) as client:
        bodies = [b"not json", b"[]", b"null", b'{"redirect_uris": "x"}', b'{"redirect_uris": [{"a": 1}]}',
                  json.dumps({"redirect_uris": [REDIRECT], "grant_types": [{}]}).encode(),
                  json.dumps({"redirect_uris": [REDIRECT], "response_types": [["code"]]}).encode(),
                  json.dumps({"redirect_uris": [REDIRECT], "token_endpoint_auth_method": {"x": 1}}).encode()]
        for body in bodies:
            response = await client.post("/register", content=body, headers={"Content-Type": "application/json"})
            assert response.status_code == 400, body
            assert response.json()["error"] in {"invalid_client_metadata", "invalid_redirect_uri"}


def test_redirect_path_allowlist():
    allowed = ["https://chatgpt.com/connector_platform_oauth_redirect", "https://chat.openai.com/aip/abc/oauth/callback",
               "https://chatgpt.com/connector/oauth/xyz", "https://claude.ai/api/mcp/auth_callback",
               "https://claude.com/api/mcp/auth_callback", "http://localhost:6274/any/path", "http://127.0.0.1/cb"]
    for uri in allowed:
        assert validate_redirect_uri(uri) == uri
    rejected = ["https://chatgpt.com/", "https://chatgpt.com/other", "https://chatgpt.com/aip/../evil",
                "https://chatgpt.com/aip/%2e%2e/evil", "https://claude.ai/oauth/callback",
                "https://claude.ai/api/mcp/auth_callback/../../x", "https://claude.com/", "https://claude.ai/connector/x"]
    for uri in rejected:
        with pytest.raises(OAuthError):
            validate_redirect_uri(uri)


async def test_ads_summary_total_deadline_returns_partial_results(service, monkeypatch):
    import asyncio

    from mcp.types import CallToolRequestParams

    from shopee_mcp import multi_server

    async def fake_summary(execute, start, end, *, include_raw, shop_label):
        if shop_label == "store-b":
            await asyncio.sleep(30)
        return {"status": "complete", "complete": True}

    monkeypatch.setattr(multi_server, "summarize_ads", fake_summary)
    service.summary_deadline = 0.2
    params = CallToolRequestParams(name="get_ads_summary", arguments={
        "shops": ["store-a", "store-b"], "start_date": "01-10-2026", "end_date": "02-10-2026"})
    async with asyncio.timeout(10):
        result = await service.call_tool(None, params)
    shops = {entry["shop"]: entry for entry in result.structured_content["shops"]}
    assert shops["store-a"]["summary"] == {"status": "complete", "complete": True}
    assert shops["store-b"]["summary"] is None and shops["store-b"]["error"] == "shop_timeout"
