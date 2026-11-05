"""Offline tests for operator-created invite links (/invite/<token>).

An invite lets a remote seller approve this app on Shopee without the admin
passphrase. The authorization state is bound to the invitee's browser cookie;
authorized shops are added with automatic aliases and the invite is single use.
Shopee is never contacted: an injected opener answers.
"""
import contextlib
import html
import json
import os
import re
import stat
from urllib.parse import parse_qs, urlsplit

from shopee_mcp.credentials import CredentialStore
from shopee_mcp.http_server import create_app
from shopee_mcp.multi_shop import load_shop_config
from shopee_mcp.shop_admin import PartnerCredentials, ShopManager
from test_admin_shops import (ADMIN, PARTNERS, SHOPEE_CODE, base, clock, connected_aliases, existing_shops,  # noqa: F401
                              form_token, login, make_factory, write_shops)
from test_http_server import PUBLIC, client_for, new_store, serving
from test_main_account import MAIN_ACCOUNT_ID, FakeMainShopee

SHOPEE_AUTH = "https://open.sandbox.test-stable.shopee.com/auth?"


def build(base, clock, shops, shopee, partners=PARTNERS):
    shops_file = write_shops(base, shops)
    manager = ShopManager(shops_file, base, PUBLIC, partners, opener=shopee, clock=clock)
    factory = make_factory(base)
    service, registry = factory(load_shop_config(shops_file))
    store = new_store(base, clock)
    app = create_app(service, store, PUBLIC, clock=clock, shop_manager=manager, service_factory=factory,
                     registry=registry)
    return app, store, manager


def invite_token_from(page_text):
    match = re.search(r'<code id="invite-url">([^<]+)</code>', page_text)
    assert match, page_text
    url = html.unescape(match.group(1))
    assert url.startswith(PUBLIC + "/invite/")
    return url[len(PUBLIC):]


async def create_invite(client, *, label="owner a", ttl="24h", env="sandbox"):
    page = await client.get(ADMIN)
    assert "Create invite link" in page.text
    response = await client.post(ADMIN, data={"action": "invite-create",
                                              "csrf_token": form_token(page.text, "invite-create"),
                                              "label": label, "ttl": ttl, "env": env})
    assert response.status_code == 200, response.text
    return invite_token_from(response.text)


async def continue_to_shopee(client, path):
    landing = await client.get(path)
    assert landing.status_code == 200, landing.text
    assert "Continue to Shopee" in landing.text and "Switch to Sub Account" in landing.text
    token = html.unescape(re.search(r'name="csrf_token" value="([^"]+)"', landing.text).group(1))
    response = await client.post(path, data={"csrf_token": token})
    assert response.status_code == 303, response.text
    location = response.headers["location"]
    assert location.startswith(SHOPEE_AUTH)
    query = {key: values[0] for key, values in parse_qs(urlsplit(location).query).items()}
    assert query["redirect_uri"] == PUBLIC + "/callback" and query["partner_id"] == "123456"
    assert "partner-secret" not in location
    return query["state"]


@contextlib.asynccontextmanager
async def clients(app):
    """One lifespan per app (the MCP session manager runs once); separate cookie jars per browser."""
    async with app.run():
        async with client_for(app, "203.0.113.7") as admin, client_for(app, "198.51.100.9") as seller:
            yield admin, seller


async def admin_invite(admin, **kwargs):
    assert (await login(admin)).status_code == 303
    return await create_invite(admin, **kwargs)


# ------------------------------------------------------------------ tests

async def test_create_list_revoke_and_hash_only_storage(base, clock):
    app, _, manager = build(base, clock, {}, FakeMainShopee())
    async with clients(app) as (admin, seller):
        path = await admin_invite(admin, label="owner a")
        token = path.rsplit("/", 1)[1]
        assert len(token) >= 43
        stored = (base / "invites.json").read_text()
        assert token not in stored
        assert stat.S_IMODE(os.stat(base / "invites.json").st_mode) == 0o600
        page = await admin.get(ADMIN)
        assert "owner a" in page.text and "active" in page.text and token not in page.text
        invite_id = json.loads(stored)["invites"][0]["id"]
        csrf = html.unescape(re.search(r'name="action" value="invite-revoke">\s*<input type="hidden" name="invite" '
                                       r'value="[^"]+">\s*<input type="hidden" name="csrf_token" value="([^"]+)"',
                                       page.text).group(1))
        revoked = await admin.post(ADMIN, data={"action": "invite-revoke", "invite": invite_id, "csrf_token": csrf})
        assert revoked.status_code == 303
        assert "revoked" in (await admin.get(ADMIN)).text
        assert (await seller.get(path)).status_code == 404
    assert manager.invites.list_invites()[0]["status"] == "revoked"


async def test_landing_invalid_and_expired(base, clock):
    app, _, _ = build(base, clock, {}, FakeMainShopee())
    async with clients(app) as (admin, seller):
        path = await admin_invite(admin, ttl="1h")
        ok = await seller.get(path)
        assert ok.status_code == 200 and "read-only" in ok.text
        assert any(cookie.startswith("__Host-smcp_invite=") for cookie in ok.headers.get_list("set-cookie"))
        unknown = await seller.get("/invite/" + "x" * 43)
        assert unknown.status_code == 404 and "invalid" in unknown.text
        clock.now += 3601
        assert (await seller.get(path)).status_code == 404


async def test_post_generates_state_without_consuming_invite(base, clock):
    shopee = FakeMainShopee()
    app, _, manager = build(base, clock, {}, shopee)
    async with clients(app) as (admin, seller):
        path = await admin_invite(admin)
        first = await continue_to_shopee(seller, path)
        second = await continue_to_shopee(seller, path)
        assert first != second
        # A POST without the landing page's form token is refused.
        assert (await seller.post(path, data={"csrf_token": "1.bad.bad"})).status_code == 403
    assert manager.invites.list_invites()[0]["status"] == "active"
    assert not shopee.calls


async def test_callback_shop_id_path_adds_shop_with_auto_alias(base, clock):
    shopee = FakeMainShopee()
    app, store, manager = build(base, clock, existing_shops(base), shopee)
    _, bearer = store.create_static_token("cli")
    async with clients(app) as (admin, seller):
        path = await admin_invite(admin)
        state = await continue_to_shopee(seller, path)
        done = await seller.get("/callback", params={"code": SHOPEE_CODE, "shop_id": "100001", "state": state})
        assert done.status_code == 200, done.text
        assert "1 shop(s) connected" in done.text and "Store Alpha" in done.text
        for secret in ("single-access", "single-refresh", SHOPEE_CODE, "partner-secret", "100001"):
            assert secret not in done.text
        assert await connected_aliases(seller, bearer) == ["store-a", "store-alpha", "store-b"]
        # Single use.
        assert (await seller.get(path)).status_code == 404
    config = load_shop_config(base / "shops.json")
    assert CredentialStore(config["store-alpha"]).snapshot("shop").subject_id == 100001
    assert manager.invites.list_invites()[0]["shops"] == ["store-alpha"]
    assert not [p for p in (base / "shops").iterdir() if p.name.startswith(".") or p.name.startswith("invite-")]


async def test_callback_main_account_two_shops(base, clock):
    shopee = FakeMainShopee(shop_ids=(100002, 100003))
    app, store, manager = build(base, clock, {}, shopee)
    _, bearer = store.create_static_token("cli")
    async with clients(app) as (admin, seller):
        path = await admin_invite(admin)
        state = await continue_to_shopee(seller, path)
        done = await seller.get("/callback", params={"code": SHOPEE_CODE, "main_account_id": MAIN_ACCOUNT_ID,
                                                     "state": state})
        assert done.status_code == 200, done.text
        assert "2 shop(s) connected" in done.text
        assert await connected_aliases(seller, bearer) == ["shop-100003", "store-beta"]
    refreshes = shopee.paths("/auth/access_token/get")
    assert [body["shop_id"] for body in refreshes] == [100002, 100003]
    config = load_shop_config(base / "shops.json")
    assert CredentialStore(config["shop-100003"]).snapshot("shop").refresh_token == "refresh-100003"
    assert manager.invites.list_invites()[0]["status"] == "used"


async def test_cookie_mismatch_is_rejected(base, clock):
    shopee = FakeMainShopee()
    app, _, manager = build(base, clock, {}, shopee)
    async with clients(app) as (admin, seller):
        path = await admin_invite(admin)
        state = await continue_to_shopee(seller, path)
        async with client_for(app, "198.51.100.10") as other:  # another browser: no invite cookie
            rejected = await other.get("/callback", params={"code": SHOPEE_CODE, "shop_id": "100001",
                                                            "state": state})
            assert rejected.status_code == 403
    assert not shopee.paths("/auth/token/get")
    assert manager.invites.list_invites()[0]["status"] == "active"


async def test_already_connected_shop_is_skipped(base, clock):
    shopee = FakeMainShopee(shop_ids=(111, 100002))  # 111 is store-a
    app, store, manager = build(base, clock, existing_shops(base), shopee)
    _, bearer = store.create_static_token("cli")
    async with clients(app) as (admin, seller):
        path = await admin_invite(admin)
        state = await continue_to_shopee(seller, path)
        done = await seller.get("/callback", params={"code": SHOPEE_CODE, "main_account_id": MAIN_ACCOUNT_ID,
                                                     "state": state})
        assert done.status_code == 200 and "1 shop(s) were already connected" in done.text
        assert await connected_aliases(seller, bearer) == ["store-a", "store-b", "store-beta"]
    assert [body["shop_id"] for body in shopee.paths("/auth/access_token/get")] == [100002]


async def test_all_failed_keeps_invite_usable(base, clock):
    shopee = FakeMainShopee(shop_ids=(100001, 100002), fail_refresh={100001, 100002})
    app, _, manager = build(base, clock, {}, shopee)
    async with clients(app) as (admin, seller):
        path = await admin_invite(admin)
        state = await continue_to_shopee(seller, path)
        failed = await seller.get("/callback", params={"code": SHOPEE_CODE, "main_account_id": MAIN_ACCOUNT_ID,
                                                       "state": state})
        assert failed.status_code == 502 and "2 shop(s) could not be connected" in failed.text
        assert (await seller.get(path)).status_code == 200
    assert manager.invites.list_invites()[0]["status"] == "active"
    assert load_shop_config(base / "shops.json") == {}


async def test_invites_persist_across_app_instances(base, clock):
    shopee = FakeMainShopee()
    app, _, _ = build(base, clock, {}, shopee)
    async with clients(app) as (admin, _seller):
        path = await admin_invite(admin)
    shops_file = base / "shops.json"
    manager = ShopManager(shops_file, base, PUBLIC, PARTNERS, opener=shopee, clock=clock)
    factory = make_factory(base)
    service, registry = factory(load_shop_config(shops_file))
    restarted = create_app(service, new_store(base, clock), PUBLIC, clock=clock, shop_manager=manager,
                           service_factory=factory, registry=registry)
    async with serving(restarted, ip="198.51.100.9") as seller:
        assert (await seller.get(path)).status_code == 200


async def test_rename_alias_keeps_env_file(base, clock):
    shopee = FakeMainShopee()
    app, store, manager = build(base, clock, {}, shopee)
    _, bearer = store.create_static_token("cli")
    async with clients(app) as (admin, seller):
        path = await admin_invite(admin, label="owner b")
        state = await continue_to_shopee(seller, path)
        assert (await seller.get("/callback", params={"code": SHOPEE_CODE, "shop_id": "100001",
                                                      "state": state})).status_code == 200
        before = load_shop_config(base / "shops.json")["store-alpha"]
        page = await admin.get(ADMIN)
        assert "owner b" in page.text
        bad = await admin.post(ADMIN, data={"action": "rename", "alias": "store-alpha", "new_alias": "Bad Alias",
                                            "csrf_token": form_token(page.text, "rename")})
        assert bad.status_code == 400
        page = await admin.get(ADMIN)
        ok = await admin.post(ADMIN, data={"action": "rename", "alias": "store-alpha", "new_alias": "store-x",
                                           "csrf_token": form_token(page.text, "rename")})
        assert ok.status_code == 303, ok.text
        assert await connected_aliases(admin, bearer) == ["store-x"]
    assert load_shop_config(base / "shops.json") == {"store-x": before}
    assert manager.invites.list_invites()[0]["shops"] == ["store-x"]


async def test_live_environment_is_offered_first(base, clock):
    partners = {"production": PartnerCredentials(654321, "live-secret"),
                "sandbox": PartnerCredentials(123456, "partner-secret")}
    app, _, _ = build(base, clock, {}, FakeMainShopee(), partners=partners)
    async with clients(app) as (admin, _seller):
        assert (await login(admin)).status_code == 303
        page = await admin.get(ADMIN)
        select = re.search(r'<select id="invite-env" name="env">(.*?)</select>', page.text).group(1)
        assert select.index('value="production"') < select.index('value="sandbox"')
        assert ">live<" in select
