"""Offline tests for web-based shop onboarding (/admin/shops + /callback) and bind rules.

Shopee is never contacted: the token exchange uses an injected opener that
records requests and returns a canned token response.
"""
import html
import io
import json
import logging
import os
import re
import stat
from urllib.parse import parse_qs, urlsplit

import pytest

from shopee_mcp.catalog import Catalog
from shopee_mcp.credentials import CredentialStore
from shopee_mcp.http_server import create_app, parser, validate_serve_args
from shopee_mcp.multi_server import EmptyShopService, MultiShopMCPService
from shopee_mcp.multi_shop import MultiShopRegistry, load_shop_config
from shopee_mcp.policy import Policy
from shopee_mcp.results import ArtifactStore
from shopee_mcp.shop_admin import (PartnerCredentials, ShopAdminError, ShopManager, create_empty_shops_file,
                                   partner_credentials_from_env)
from test_credentials import make_env
from test_http_server import PASSPHRASE, PUBLIC, NeverTransport, client_for, new_store, rpc, server_logs, serving

ADMIN = "/admin/shops"
SHOPEE_CODE = "shopee-auth-code-do-not-log"
PARTNERS = {"sandbox": PartnerCredentials(123456, "partner-secret")}


@pytest.fixture
def base(tmp_path):
    tmp_path.chmod(0o700)
    return tmp_path


@pytest.fixture
def clock():
    from test_http_server import Clock
    return Clock()


_CATALOG = []


def catalog():
    if not _CATALOG:
        _CATALOG.append(Catalog())
    return _CATALOG[0]


def make_factory(base):
    artifacts = ArtifactStore(base / "artifacts")

    def factory(shops):
        if not shops:
            return EmptyShopService(artifacts), None
        registry = MultiShopRegistry(shops, transport_factory=lambda store, **_: NeverTransport())
        return MultiShopMCPService(catalog(), Policy("multi"), registry, artifacts), registry
    return factory


def write_shops(base, shops):
    path = base / "shops.json"
    path.write_text(json.dumps({"shops": {alias: str(p) for alias, p in shops.items()}}))
    path.chmod(0o600)
    return path


def existing_shops(base):
    envs = {}
    for alias, shop_id in (("store-a", 111), ("store-b", 222)):
        path = base / f"{alias}.env"
        make_env(path, SHOPEE_SHOP_ID=str(shop_id), SHOPEE_REFRESH_TOKEN_EXPIRES_AT="4102444800",
                 SHOPEE_AUTH_EXPIRES_AT="4102444800")
        envs[alias] = path
    return envs


class FakeShopee:
    def __init__(self):
        self.calls = []

    def __call__(self, request, timeout=30):
        self.calls.append((request.full_url, json.loads(request.data)))
        return io.BytesIO(json.dumps({"access_token": "new-access-token", "refresh_token": "new-refresh-token",
                                      "expire_in": 14400, "error": "", "request_id": "r1"}).encode())


def build(base, clock, shops, *, partners=PARTNERS, public=PUBLIC):
    shops_file = write_shops(base, shops)
    opener = FakeShopee()
    manager = ShopManager(shops_file, base, public, partners, opener=opener)
    factory = make_factory(base)
    service, registry = factory(load_shop_config(shops_file))
    store = new_store(base, clock)
    app = create_app(service, store, public, clock=clock, shop_manager=manager, service_factory=factory,
                     registry=registry)
    return app, store, manager, opener


def form_token(page_text, action):
    pattern = rf'name="action" value="{action}">\s*(?:<input type="hidden" name="alias" value="[^"]*">)?\s*' \
              r'<input type="hidden" name="csrf_token" value="([^"]+)"'
    return html.unescape(re.search(pattern, page_text).group(1))


async def login(client, passphrase=PASSPHRASE):
    page = await client.get(ADMIN)
    assert page.status_code == 200 and "Operator passphrase" in page.text
    assert page.headers["cache-control"] == "no-store"
    return await client.post(ADMIN, data={"action": "login", "csrf_token": form_token(page.text, "login"),
                                          "passphrase": passphrase})


async def start_add(client, alias="store-c", env="sandbox"):
    page = await client.get(ADMIN)
    assert page.status_code == 200 and "Add shop" in page.text
    response = await client.post(ADMIN, data={"action": "add", "csrf_token": form_token(page.text, "add"),
                                              "alias": alias, "env": env, "days": "365"})
    assert response.status_code == 303, response.text
    location = response.headers["location"]
    assert location.startswith("https://open.sandbox.test-stable.shopee.com/auth?")
    query = {key: values[0] for key, values in parse_qs(urlsplit(location).query).items()}
    assert query["redirect_uri"] == PUBLIC + "/callback" and query["partner_id"] == "123456"
    assert "partner-secret" not in location
    return query["state"]


async def connected_aliases(client, token):
    response = await rpc(client, token, "tools/call", {"name": "list_connected_shops", "arguments": {}})
    assert response.status_code == 200, response.text
    return [shop["alias"] for shop in response.json()["result"]["structuredContent"]["shops"]]


# ------------------------------------------------------------------ tests

async def test_add_shop_end_to_end_hot_reloads(base, clock, caplog):
    caplog.set_level(logging.DEBUG)
    app, store, manager, shopee = build(base, clock, existing_shops(base))
    _, token = store.create_static_token("cli")
    async with serving(app) as client:
        assert await connected_aliases(client, token) == ["store-a", "store-b"]
        assert (await login(client)).status_code == 303
        state = await start_add(client)
        assert not shopee.calls  # nothing is exchanged before the callback
        done = await client.get("/callback", params={"code": SHOPEE_CODE, "shop_id": "333", "state": state})
        assert done.status_code == 200, done.text
        assert "store-c" in done.text and SHOPEE_CODE not in done.text
        # Hot reload: the running server now serves the new shop without a restart.
        assert await connected_aliases(client, token) == ["store-a", "store-b", "store-c"]
        tools = (await rpc(client, token, "tools/list")).json()["result"]["tools"]
        summary = next(tool for tool in tools if tool["name"] == "get_ads_summary")
        assert "store-c" in json.dumps(summary["inputSchema"])
        listing = await client.get(ADMIN)
        assert "store-c" in listing.text and "new-access-token" not in listing.text
        assert "partner-secret" not in listing.text
        # The state is single use.
        replay = await client.get("/callback", params={"code": SHOPEE_CODE, "shop_id": "333", "state": state})
        assert replay.status_code == 200 and "does not process" in replay.text
    assert len(shopee.calls) == 1
    url, body = shopee.calls[0]
    assert "/api/v2/auth/token/get" in url and body == {"code": SHOPEE_CODE, "shop_id": 333, "partner_id": 123456}
    env_file = base / "shops" / "store-c.env"
    assert stat.S_IMODE(os.stat(env_file).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(base / "shops").st_mode) == 0o700
    assert stat.S_IMODE(os.stat(base / "shops.json").st_mode) == 0o600
    assert load_shop_config(base / "shops.json")["store-c"] == env_file
    snapshot = CredentialStore(env_file).snapshot("shop")
    assert snapshot.subject_id == 333 and snapshot.access_token == "new-access-token"
    assert not [p for p in (base / "shops").iterdir() if p.name.startswith(".pending-")]
    logs = server_logs(caplog)
    assert SHOPEE_CODE not in logs and state not in logs and "new-access-token" not in logs


async def test_callback_without_pending_state_exchanges_nothing(base, clock):
    app, _, _, shopee = build(base, clock, existing_shops(base))
    async with serving(app) as client:
        assert (await login(client)).status_code == 303
        for params in ({"code": SHOPEE_CODE, "shop_id": "333"},
                       {"code": SHOPEE_CODE, "shop_id": "333", "state": "forged-state-value"}):
            response = await client.get("/callback", params=params)
            assert response.status_code == 200 and SHOPEE_CODE not in response.text
    assert not shopee.calls
    assert not (base / "shops").exists() or not list((base / "shops").glob("*.env"))


async def test_callback_requires_the_admin_session_that_started_it(base, clock):
    app, _, _, shopee = build(base, clock, existing_shops(base))
    async with app.run():
        async with client_for(app, "198.51.100.5") as operator, client_for(app, "198.51.100.6") as other:
            assert (await login(operator)).status_code == 303
            state = await start_add(operator)
            stolen = await other.get("/callback", params={"code": SHOPEE_CODE, "shop_id": "333", "state": state})
            assert stolen.status_code == 403
            # The state was consumed by the rejected attempt.
            late = await operator.get("/callback", params={"code": SHOPEE_CODE, "shop_id": "333", "state": state})
            assert late.status_code == 200 and "does not process" in late.text
    assert not shopee.calls
    assert "store-c" not in load_shop_config(base / "shops.json")


async def test_duplicate_shop_identity_is_rejected_and_cleaned_up(base, clock):
    app, store, _, shopee = build(base, clock, existing_shops(base))
    _, token = store.create_static_token("cli")
    async with serving(app) as client:
        assert (await login(client)).status_code == 303
        state = await start_add(client)
        response = await client.get("/callback", params={"code": SHOPEE_CODE, "shop_id": "111", "state": state})
        assert response.status_code == 409
        assert await connected_aliases(client, token) == ["store-a", "store-b"]
    assert len(shopee.calls) == 1
    assert sorted(load_shop_config(base / "shops.json")) == ["store-a", "store-b"]
    assert not list((base / "shops").glob("*.env"))


async def test_remove_shop_and_start_from_empty(base, clock):
    app, store, _, _ = build(base, clock, {})
    _, token = store.create_static_token("cli")
    async with serving(app) as client:
        assert await connected_aliases(client, token) == []
        assert (await login(client)).status_code == 303
        state = await start_add(client, alias="store-a")
        assert (await client.get("/callback", params={"code": SHOPEE_CODE, "shop_id": "444", "state": state})).status_code == 200
        assert await connected_aliases(client, token) == ["store-a"]
        page = await client.get(ADMIN)
        removed = await client.post(ADMIN, data={"action": "remove", "alias": "store-a",
                                                 "csrf_token": form_token(page.text, "remove")})
        assert removed.status_code == 303
        assert await connected_aliases(client, token) == []
    assert load_shop_config(base / "shops.json") == {}
    assert not (base / "shops" / "store-a.env").exists()
    await app.aclose()


async def test_admin_actions_need_session_csrf_and_passphrase(base, clock):
    app, _, _, _ = build(base, clock, existing_shops(base))
    async with serving(app, ip="198.51.100.30") as client:
        # No session: actions are refused.
        anonymous = await client.post(ADMIN, data={"action": "add", "alias": "store-c", "env": "sandbox"})
        assert anonymous.status_code == 403 and "location" not in anonymous.headers
        forged = await client.post(ADMIN, data={"action": "login", "csrf_token": "1.x.y", "passphrase": PASSPHRASE})
        assert forged.status_code == 403
        for _ in range(5):
            assert (await login(client, passphrase="wrong guess 123")).status_code == 403
        assert (await login(client)).status_code == 429  # shared throttle with /authorize
        clock.now += 901
        assert (await login(client)).status_code == 303
        page = await client.get(ADMIN)
        bad_csrf = await client.post(ADMIN, data={"action": "add", "alias": "store-c", "env": "sandbox",
                                                  "csrf_token": "1.x.y"})
        assert bad_csrf.status_code == 403
        token = form_token(page.text, "add")
        bad_alias = await client.post(ADMIN, data={"action": "add", "alias": "Bad Alias", "env": "sandbox",
                                                   "csrf_token": token})
        assert bad_alias.status_code == 400
        replay = await client.post(ADMIN, data={"action": "add", "alias": "store-c", "env": "sandbox",
                                                "csrf_token": token})
        assert replay.status_code == 403  # form tokens are single use
        page = await client.get(ADMIN)
        taken = await client.post(ADMIN, data={"action": "add", "alias": "store-a", "env": "sandbox",
                                               "csrf_token": form_token(page.text, "add")})
        assert taken.status_code == 400 and "already in use" in taken.text
        page = await client.get(ADMIN)
        production = await client.post(ADMIN, data={"action": "add", "alias": "store-c", "env": "production",
                                                    "csrf_token": form_token(page.text, "add")})
        assert production.status_code == 400  # no production partner credentials configured


async def test_admin_disabled_without_manager(base, clock):
    factory = make_factory(base)
    service, _ = factory({})
    app = create_app(service, new_store(base, clock), PUBLIC, clock=clock)
    async with serving(app) as client:
        assert (await client.get(ADMIN)).status_code == 404
        static = await client.get("/callback", params={"code": SHOPEE_CODE, "shop_id": "1", "state": "x"})
        assert static.status_code == 200 and SHOPEE_CODE not in static.text


def test_partner_credentials_from_env():
    assert partner_credentials_from_env({}) == {}
    creds = partner_credentials_from_env({"SHOPEE_PARTNER_ID": "123456", "SHOPEE_PARTNER_KEY": "k1"})
    assert set(creds) == {"production", "sandbox"} and creds["sandbox"].partner_id == 123456
    split = partner_credentials_from_env({"SHOPEE_PARTNER_ID": "123456", "SHOPEE_PARTNER_KEY": "k1",
                                          "SHOPEE_SANDBOX_PARTNER_ID": "654321", "SHOPEE_SANDBOX_PARTNER_KEY": "k2"})
    assert split["sandbox"].partner_id == 654321 and split["production"].partner_id == 123456
    assert "k1" not in repr(split)
    for bad in ({"SHOPEE_PARTNER_ID": "123456"}, {"SHOPEE_PARTNER_ID": "abc", "SHOPEE_PARTNER_KEY": "k"}):
        with pytest.raises(ShopAdminError):
            partner_credentials_from_env(bad)


def test_onboarding_needs_https_public_url(base):
    shops_file = write_shops(base, {})
    manager = ShopManager(shops_file, base, "http://127.0.0.1:8091", PARTNERS)
    assert manager.available_environments() == []
    with pytest.raises(ShopAdminError):
        manager.start("store-a", "sandbox", "session")


def test_create_empty_shops_file_is_owner_only_and_idempotent(base):
    path = base / "shops.json"
    create_empty_shops_file(path)
    create_empty_shops_file(path)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert load_shop_config(path) == {}


def test_write_config_is_atomic_and_valid(base):
    envs = existing_shops(base)
    shops_file = write_shops(base, {})
    manager = ShopManager(shops_file, base, PUBLIC, PARTNERS)
    manager.write_config(envs)
    assert load_shop_config(shops_file) == envs
    assert stat.S_IMODE(os.stat(shops_file).st_mode) == 0o600
    assert not [p for p in base.iterdir() if p.name.startswith(".shops.json.")]


def serve_args(*extra, public=PUBLIC):
    return parser().parse_args(["serve", "--shops-file", "/data/shops.json", "--auth-file", "/data/auth.db",
                                "--public-url", public, *extra])


def test_host_option_rules():
    assert serve_args().host == "127.0.0.1"
    validate_serve_args(serve_args())
    validate_serve_args(serve_args("--host", "0.0.0.0"))
    validate_serve_args(serve_args("--host", "0.0.0.0", "--client-ip-header", "X-Forwarded-For",
                                   "--trusted-proxy", "10.0.0.0/8"))
    with pytest.raises(ValueError):
        validate_serve_args(serve_args("--host", "0.0.0.0", public="http://127.0.0.1:8091"))
    with pytest.raises(ValueError):
        validate_serve_args(serve_args("--host", "0.0.0.0", "--client-ip-header", "X-Real-IP"))
    with pytest.raises(ValueError):
        validate_serve_args(serve_args("--trusted-proxy", "not-a-network"))
    validate_serve_args(serve_args("--host", "127.0.0.1", "--client-ip-header", "X-Real-IP",
                                   public="http://127.0.0.1:8091"))


async def test_trusted_proxy_uses_rightmost_untrusted_hop(base, clock):
    factory = make_factory(base)
    service, _ = factory({})
    app = create_app(service, new_store(base, clock), PUBLIC, clock=clock, client_ip_header="X-Forwarded-For",
                     trusted_proxies=["10.0.0.0/8"])
    headers = [(b"x-forwarded-for", b"192.0.2.99, 198.51.100.7, 10.1.2.3")]
    assert app.client_ip({"client": ("10.9.9.9", 1), "headers": headers}) == "198.51.100.7"
    assert app.client_ip({"client": ("203.0.113.5", 1), "headers": headers}) == "203.0.113.5"
    untrusted = create_app(service, new_store(base, clock), PUBLIC, clock=clock, client_ip_header="X-Forwarded-For")
    assert untrusted.client_ip({"client": ("10.9.9.9", 1), "headers": headers}) == "10.9.9.9"
