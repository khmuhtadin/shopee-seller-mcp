"""Offline tests for Shopee *main account* (multi-shop) authorization.

A main-account callback carries ``code`` + ``main_account_id`` instead of
``shop_id``. The server exchanges the code once, lets the operator pick shops
and aliases, then refreshes each chosen shop separately so every shop has its
own token pair. Shopee is never contacted: an injected opener answers.
"""
import html
import io
import json
import re
from urllib.parse import parse_qs, urlsplit

from shopee_mcp import auth_cli
from shopee_mcp.credentials import CredentialStore
from shopee_mcp.http_server import create_app
from shopee_mcp.multi_shop import load_shop_config
from shopee_mcp.shop_admin import ShopManager
from test_admin_shops import (ADMIN, PARTNERS, SHOPEE_CODE, base, clock, connected_aliases, existing_shops,  # noqa: F401
                              login, make_factory, start_add, write_shops)
from test_http_server import PUBLIC, new_store, serving

MAIN_ACCOUNT_ID = "200001"
NAMES = {100001: "Store Alpha", 100002: "Store Beta"}  # 100003 has no fetchable name


class FakeMainShopee:
    def __init__(self, shop_ids=(100001, 100002, 100003), fail_refresh=()):
        self.shop_ids = list(shop_ids)
        self.fail_refresh = set(fail_refresh)
        self.calls = []

    @staticmethod
    def _reply(payload):
        return io.BytesIO(json.dumps({"error": "", "request_id": "r1", **payload}).encode())

    def __call__(self, request, timeout=30):
        parts = urlsplit(request.full_url)
        if request.data is None:
            query = {key: values[0] for key, values in parse_qs(parts.query).items()}
            self.calls.append((parts.path, query))
            name = NAMES.get(int(query["shop_id"]))
            if name is None:
                return self._reply({"error": "error_param", "message": "no name"})
            return self._reply({"shop_name": name})
        body = json.loads(request.data)
        self.calls.append((parts.path, body))
        if parts.path.endswith("/auth/token/get"):
            if "main_account_id" in body:
                return self._reply({"access_token": "shared-access", "refresh_token": "shared-refresh",
                                    "expire_in": 14400, "shop_id_list": self.shop_ids, "merchant_id_list": []})
            return self._reply({"access_token": "single-access", "refresh_token": "single-refresh",
                                "expire_in": 14400})
        if parts.path.endswith("/auth/access_token/get"):
            shop_id = body["shop_id"]
            if shop_id in self.fail_refresh:
                return self._reply({"error": "error_auth", "message": "invalid refresh token"})
            return self._reply({"access_token": f"access-{shop_id}", "refresh_token": f"refresh-{shop_id}",
                                "expire_in": 14400, "shop_id": shop_id})
        raise AssertionError(f"unexpected Shopee call {parts.path}")

    def paths(self, suffix):
        return [body for path, body in self.calls if path.endswith(suffix)]


def build(base, clock, shops, shopee):
    shops_file = write_shops(base, shops)
    manager = ShopManager(shops_file, base, PUBLIC, PARTNERS, opener=shopee)
    factory = make_factory(base)
    service, registry = factory(load_shop_config(shops_file))
    store = new_store(base, clock)
    app = create_app(service, store, PUBLIC, clock=clock, shop_manager=manager, service_factory=factory,
                     registry=registry)
    return app, store, manager


def picker_fields(page_text):
    grant = re.search(r'name="grant" value="([^"]+)"', page_text).group(1)
    token = re.search(r'name="action" value="add-main">\s*<input type="hidden" name="grant" value="[^"]+">\s*'
                      r'<input type="hidden" name="csrf_token" value="([^"]+)"', page_text).group(1)
    return html.unescape(grant), html.unescape(token)


def suggested_alias(page_text, shop_id):
    return html.unescape(re.search(rf'name="alias-{shop_id}" value="([^"]*)"', page_text).group(1))


async def open_picker(client, alias="group"):
    assert (await login(client)).status_code == 303
    state = await start_add(client, alias=alias)
    return await client.get("/callback", params={"code": SHOPEE_CODE, "main_account_id": MAIN_ACCOUNT_ID,
                                                 "state": state})


async def submit(client, page_text, selection):
    grant, token = picker_fields(page_text)
    data = {"action": "add-main", "grant": grant, "csrf_token": token}
    for shop_id, alias in selection.items():
        data[f"select-{shop_id}"] = "on"
        data[f"alias-{shop_id}"] = alias
    return await client.post(ADMIN, data=data)


# ------------------------------------------------------------------ tests

async def test_main_account_callback_picker_and_multi_shop_persistence(base, clock):
    shopee = FakeMainShopee()
    app, store, manager = build(base, clock, existing_shops(base), shopee)
    _, token = store.create_static_token("cli")
    async with serving(app) as client:
        picker = await open_picker(client)
        assert picker.status_code == 200, picker.text
        for shop_id in ("100001", "100002", "100003"):
            assert shop_id in picker.text
        assert "Store Alpha" in picker.text
        assert suggested_alias(picker.text, 100001) == "store-alpha"
        assert suggested_alias(picker.text, 100003) == "group-3"
        for secret in ("shared-access", "shared-refresh", SHOPEE_CODE, "partner-secret"):
            assert secret not in picker.text
        # One exchange with main_account_id; nothing stored before the selection.
        assert shopee.paths("/auth/token/get") == [{"code": SHOPEE_CODE, "main_account_id": 200001,
                                                    "partner_id": 123456}]
        assert not shopee.paths("/auth/access_token/get")
        assert not (base / "shops").exists() or not list((base / "shops").glob("*.env"))

        done = await submit(client, picker.text, {100001: "store-c", 100002: "store-d"})
        assert done.status_code == 200, done.text
        assert "store-c" in done.text and "store-d" in done.text
        assert await connected_aliases(client, token) == ["store-a", "store-b", "store-c", "store-d"]

        # The selection is single use.
        replay = await submit(client, picker.text, {100003: "store-e"})
        assert replay.status_code in (400, 403)
    refreshes = shopee.paths("/auth/access_token/get")
    assert refreshes == [{"partner_id": 123456, "shop_id": 100001, "refresh_token": "shared-refresh"},
                         {"partner_id": 123456, "shop_id": 100002, "refresh_token": "shared-refresh"}]
    config = load_shop_config(base / "shops.json")
    assert "store-e" not in config
    first = CredentialStore(config["store-c"]).snapshot("shop")
    second = CredentialStore(config["store-d"]).snapshot("shop")
    assert (first.subject_id, first.access_token, first.refresh_token) == (100001, "access-100001", "refresh-100001")
    assert (second.subject_id, second.refresh_token) == (100002, "refresh-100002")
    assert not [p for p in (base / "shops").iterdir() if p.name.startswith(".")]


async def test_alias_collision_and_duplicates_rerender_without_refreshing(base, clock):
    shopee = FakeMainShopee()
    app, store, _ = build(base, clock, existing_shops(base), shopee)
    _, token = store.create_static_token("cli")
    async with serving(app) as client:
        picker = await open_picker(client)
        taken = await submit(client, picker.text, {100001: "store-a"})
        assert taken.status_code == 400 and "already in use" in taken.text
        duplicate = await submit(client, taken.text, {100001: "store-x", 100002: "store-x"})
        assert duplicate.status_code == 400 and "different alias" in duplicate.text
        invalid = await submit(client, duplicate.text, {100001: "Bad Alias"})
        assert invalid.status_code == 400
        assert not shopee.paths("/auth/access_token/get")
        # The re-rendered page keeps the grant usable.
        ok = await submit(client, invalid.text, {100001: "store-x"})
        assert ok.status_code == 200, ok.text
        assert await connected_aliases(client, token) == ["store-a", "store-b", "store-x"]


async def test_already_connected_shop_is_rejected(base, clock):
    shopee = FakeMainShopee(shop_ids=(111, 100002))  # 111 is store-a in existing_shops
    app, _, _ = build(base, clock, existing_shops(base), shopee)
    async with serving(app) as client:
        picker = await open_picker(client)
        response = await submit(client, picker.text, {111: "store-c"})
        assert response.status_code == 409 and "already connected" in response.text
    assert not shopee.paths("/auth/access_token/get")


async def test_failed_refresh_skips_only_that_shop(base, clock):
    shopee = FakeMainShopee(fail_refresh={100002})
    app, store, _ = build(base, clock, {}, shopee)
    _, token = store.create_static_token("cli")
    async with serving(app) as client:
        picker = await open_picker(client)
        done = await submit(client, picker.text, {100001: "store-a", 100002: "store-b"})
        assert done.status_code == 200 and "100002" in done.text
        assert await connected_aliases(client, token) == ["store-a"]
    assert not (base / "shops" / "store-b.env").exists()


async def test_later_refresh_is_per_shop_and_independent(base, clock):
    shopee = FakeMainShopee()
    app, _, _ = build(base, clock, {}, shopee)
    async with serving(app) as client:
        picker = await open_picker(client)
        assert (await submit(client, picker.text, {100001: "store-a", 100002: "store-b"})).status_code == 200
    config = load_shop_config(base / "shops.json")
    before = (base / "shops" / "store-b.env").read_text()
    shopee.calls.clear()
    client = auth_cli.ShopeeClient(auth_cli.load_config(config["store-a"]), opener=shopee)
    client.refresh_tokens()
    assert shopee.paths("/auth/access_token/get") == [{"partner_id": 123456, "shop_id": 100001,
                                                       "refresh_token": "refresh-100001"}]
    assert (base / "shops" / "store-b.env").read_text() == before


async def test_plain_shop_flow_still_works_and_mixed_callback_is_rejected(base, clock):
    shopee = FakeMainShopee()
    app, store, _ = build(base, clock, {}, shopee)
    _, token = store.create_static_token("cli")
    async with serving(app) as client:
        assert (await login(client)).status_code == 303
        state = await start_add(client, alias="store-a")
        done = await client.get("/callback", params={"code": SHOPEE_CODE, "shop_id": "100009", "state": state})
        assert done.status_code == 200, done.text
        assert await connected_aliases(client, token) == ["store-a"]
        state = await start_add(client, alias="store-b")
        mixed = await client.get("/callback", params={"code": SHOPEE_CODE, "shop_id": "100010",
                                                      "main_account_id": MAIN_ACCOUNT_ID, "state": state})
        assert mixed.status_code == 400
    assert shopee.paths("/auth/token/get") == [{"code": SHOPEE_CODE, "shop_id": 100009, "partner_id": 123456}]


def test_cli_exchange_main_account_writes_one_file_per_shop(base):
    env_file = base / "partner.env"
    auth_cli.create_production_env(env_file, 123456, "partner-secret", PUBLIC + "/callback")
    auth_cli.update_env_values(env_file, {"SHOPEE_AUTH_STATE": "cli-state"}, failure_message="x")
    shopee = FakeMainShopee(fail_refresh={100003})
    out = io.StringIO()
    url = f"{PUBLIC}/callback?code={SHOPEE_CODE}&main_account_id={MAIN_ACCOUNT_ID}&state=cli-state"
    status = auth_cli.run(["--env-file", str(env_file), "exchange-main-account", "--callback-url-stdin",
                           "--output-dir", str(base / "out")], opener=shopee, stdin=io.StringIO(url + "\n"),
                          stdout=out, stderr=io.StringIO())
    assert status == 0
    result = json.loads(out.getvalue())
    assert [shop["shop_id"] for shop in result["shops"]] == [100001, 100002]
    assert [shop["shop_id"] for shop in result["failed"]] == [100003]
    assert "shared-refresh" not in out.getvalue() and SHOPEE_CODE not in out.getvalue()
    snapshot = CredentialStore(base / "out" / "shop-100001.env").snapshot("shop")
    assert snapshot.subject_id == 100001 and snapshot.refresh_token == "refresh-100001"
    # The saved state is consumed: replaying the callback fails.
    again = auth_cli.run(["--env-file", str(env_file), "exchange-main-account", "--callback-url-stdin",
                          "--output-dir", str(base / "out2")], opener=shopee, stdin=io.StringIO(url),
                         stdout=io.StringIO(), stderr=io.StringIO())
    assert again == 1


def test_cli_main_account_parser_rejects_shop_id_callbacks(base):
    config = auth_cli.PartnerConfig("sandbox", auth_cli.ALLOWED_BASE_URLS["sandbox"], 123456, "partner-secret",
                                    PUBLIC + "/callback", "s1", base / "unused.env")
    parsed = auth_cli.parse_main_account_callback(config, f"{PUBLIC}/callback?code=c&main_account_id=7&state=s1")
    assert parsed == auth_cli.MainAccountCallback("c", 7)
    for bad in ("code=c&main_account_id=7&shop_id=1&state=s1", "code=c&main_account_id=0&state=s1",
                "code=c&main_account_id=7&state=wrong"):
        try:
            auth_cli.parse_main_account_callback(config, f"{PUBLIC}/callback?{bad}")
        except auth_cli.ConfigError:
            continue
        raise AssertionError(bad)
