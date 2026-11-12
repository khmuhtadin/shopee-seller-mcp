"""Offline tests for the server-to-server dashboard API (/api/dashboard/*).

The API lets an operator dashboard list shops and invites and create or revoke
invite links. It is enabled only with its own bearer token; MCP OAuth/static
tokens never grant access. Invites created with ``return_to_dashboard`` end on
a page that links back to the configured dashboard URL.
Shopee is never contacted: an injected opener answers.
"""
import contextlib
import json

import pytest

from shopee_mcp.http_server import create_app, dashboard_settings_from_env
from shopee_mcp.multi_shop import load_shop_config
from shopee_mcp.shop_admin import PartnerCredentials, ShopManager
from test_admin_shops import (PARTNERS, SHOPEE_CODE, base, clock, existing_shops, make_factory,  # noqa: F401
                              write_shops)
from test_http_server import PUBLIC, client_for, new_store
from test_invites import continue_to_shopee
from test_main_account import MAIN_ACCOUNT_ID, FakeMainShopee

TOKEN = "dash-" + "k" * 40
AUTH = {"Authorization": f"Bearer {TOKEN}"}
DASHBOARD = "https://dashboard.example.com/ads/connections"
SHOPS = "/api/dashboard/shops"
INVITES = "/api/dashboard/invites"


def build(base, clock, shops, shopee=None, *, partners=PARTNERS, token=TOKEN, dashboard_url=DASHBOARD):
    shops_file = write_shops(base, shops)
    manager = ShopManager(shops_file, base, PUBLIC, partners, opener=shopee or FakeMainShopee(), clock=clock)
    factory = make_factory(base)
    service, registry = factory(load_shop_config(shops_file))
    store = new_store(base, clock)
    app = create_app(service, store, PUBLIC, clock=clock, shop_manager=manager, service_factory=factory,
                     registry=registry, dashboard_token=token, dashboard_url=dashboard_url)
    return app, store, manager


@contextlib.asynccontextmanager
async def clients(app):
    async with app.run():
        async with client_for(app, "203.0.113.7") as dashboard, client_for(app, "198.51.100.9") as seller:
            yield dashboard, seller


async def create(client, **body):
    response = await client.post(INVITES, headers=AUTH, json=body)
    assert response.status_code == 201, response.text
    return response.json()


# ------------------------------------------------------------------ auth

async def test_disabled_without_token_returns_404(base, clock):
    app, _, _ = build(base, clock, {}, token=None)
    async with clients(app) as (dashboard, _):
        assert (await dashboard.get(SHOPS, headers=AUTH)).status_code == 404
        assert (await dashboard.post(INVITES, headers=AUTH, json={})).status_code == 404
        assert (await dashboard.delete(INVITES + "/abc", headers=AUTH)).status_code == 404


async def test_wrong_missing_and_mcp_tokens_are_rejected(base, clock):
    app, store, _ = build(base, clock, {})
    _, mcp_token = store.create_static_token("cli")
    async with clients(app) as (dashboard, _):
        for headers in ({}, {"Authorization": "Bearer wrong-token"}, {"Authorization": f"Basic {TOKEN}"},
                        {"Authorization": f"Bearer {mcp_token}"}):
            response = await dashboard.get(SHOPS, headers=headers)
            assert response.status_code == 401
            assert response.json() == {"error": "unauthorized"}
            assert response.headers["cache-control"] == "no-store"
            assert "access-control-allow-origin" not in response.headers
        ok = await dashboard.get(SHOPS, headers=AUTH)
        assert ok.status_code == 200 and ok.headers["cache-control"] == "no-store"
        assert "access-control-allow-origin" not in ok.headers


async def test_failures_are_throttled(base, clock):
    app, _, _ = build(base, clock, {})
    async with clients(app) as (dashboard, _):
        for _ in range(10):
            assert (await dashboard.get(SHOPS, headers={"Authorization": "Bearer nope"})).status_code == 401
        limited = await dashboard.get(SHOPS, headers=AUTH)
        assert limited.status_code == 429 and int(limited.headers["retry-after"]) > 0
        clock.now += 901
        assert (await dashboard.get(SHOPS, headers=AUTH)).status_code == 200


# ------------------------------------------------------------- list/create

async def test_list_shops_and_invites_without_secrets(base, clock):
    app, _, _ = build(base, clock, existing_shops(base))
    async with clients(app) as (dashboard, _):
        created = await create(dashboard, label="owner a")
        response = await dashboard.get(SHOPS, headers=AUTH)
    assert response.status_code == 200
    data = response.json()
    assert data["environments"] == ["sandbox"]
    assert [shop["alias"] for shop in data["shops"]] == ["store-a", "store-b"]
    first = data["shops"][0]
    assert set(first) == {"alias", "env", "shop_id", "shop_name", "status", "auth_expires_at",
                          "refresh_expires_at", "source"}
    assert first["shop_id"] == 111 and first["status"] == "ok" and first["env"] == "sandbox"
    assert first["auth_expires_at"] == 4102444800 and first["refresh_expires_at"] == 4102444800
    assert first["shop_name"] is None and first["source"] is None
    assert data["invites"] == [{"id": created["id"], "label": "owner a", "env": "sandbox", "status": "active",
                                "created_at": clock.now, "expires_at": clock.now + 86400, "aliases": []}]
    text = response.text
    for secret in ("partner-secret", str(base), ".env", created["url"].rsplit("/", 1)[1]):
        assert secret not in text


async def test_create_defaults_and_validation(base, clock):
    app, _, manager = build(base, clock, {})
    async with clients(app) as (dashboard, _):
        created = await create(dashboard)
        assert created["env"] == "sandbox" and created["label"] == ""
        assert created["expires_at"] == clock.now + 86400
        assert created["url"].startswith(PUBLIC + "/invite/") and len(created["url"].rsplit("/", 1)[1]) >= 43
        three_days = await create(dashboard, ttl="3d", label="owner b")
        assert three_days["expires_at"] == clock.now + 3 * 86400
        for body in ({"ttl": "2d"}, {"ttl": 3}, {"env": "live"}, {"env": "mars"}, {"label": 5},
                     {"label": "x" * 41}, {"return_to_dashboard": "yes"}):
            bad = await dashboard.post(INVITES, headers=AUTH, json=body)
            assert bad.status_code == 400, body
            assert isinstance(bad.json()["error"], str)
        not_json = await dashboard.post(INVITES, headers={**AUTH, "Content-Type": "application/json"},
                                        content=b"{not json")
        assert not_json.status_code == 400
        assert (await dashboard.post(INVITES, headers=AUTH, json=[1])).status_code == 400
    stored = (base / "invites.json").read_text()
    assert created["url"].rsplit("/", 1)[1] not in stored
    assert all("return_to_dashboard" not in record for record in json.loads(stored)["invites"])
    assert len(manager.invites.list_invites()) == 2


async def test_live_environment_is_the_default_when_configured(base, clock):
    partners = {**PARTNERS, "production": PartnerCredentials(654321, "live-partner-secret")}
    app, _, manager = build(base, clock, {}, partners=partners)
    async with clients(app) as (dashboard, _):
        created = await create(dashboard)
        sandbox = await create(dashboard, env="sandbox")
        listed = (await dashboard.get(SHOPS, headers=AUTH)).json()
    assert created["env"] == "live" and sandbox["env"] == "sandbox"
    assert listed["environments"] == ["live", "sandbox"]
    assert {record["env"] for record in manager.invites.list_invites()} == {"production", "sandbox"}


async def test_return_to_dashboard_needs_configured_url(base, clock):
    app, _, _ = build(base, clock, {}, dashboard_url=None)
    async with clients(app) as (dashboard, _):
        response = await dashboard.post(INVITES, headers=AUTH, json={"return_to_dashboard": True})
        assert response.status_code == 400 and "SHOPEE_MCP_DASHBOARD_URL" in response.json()["error"]
        assert (await dashboard.post(INVITES, headers=AUTH, json={"return_to_dashboard": False})).status_code == 201


# ------------------------------------------------------------------ revoke

async def test_revoke(base, clock):
    app, _, manager = build(base, clock, {})
    async with clients(app) as (dashboard, seller):
        created = await create(dashboard)
        path = created["url"][len(PUBLIC):]
        assert (await seller.get(path)).status_code == 200
        revoked = await dashboard.delete(f"{INVITES}/{created['id']}", headers=AUTH)
        assert revoked.status_code == 200 and revoked.json() == {"ok": True}
        assert (await dashboard.delete(f"{INVITES}/{created['id']}", headers=AUTH)).status_code == 404
        assert (await dashboard.delete(f"{INVITES}/unknown", headers=AUTH)).status_code == 404
        assert (await dashboard.delete(f"{INVITES}/{created['id']}")).status_code == 401
        assert (await seller.get(path)).status_code == 404
    assert manager.invites.list_invites()[0]["status"] == "revoked"


# --------------------------------------------------------- completion page

async def test_completion_links_back_to_dashboard(base, clock):
    shopee = FakeMainShopee()
    app, _, manager = build(base, clock, existing_shops(base), shopee)
    async with clients(app) as (dashboard, seller):
        created = await create(dashboard, label="owner a", return_to_dashboard=True)
        state = await continue_to_shopee(seller, created["url"][len(PUBLIC):])
        done = await seller.get("/callback", params={"code": SHOPEE_CODE, "shop_id": "100001", "state": state})
        assert done.status_code == 200, done.text
        assert "Back to dashboard" in done.text
        assert f'href="{DASHBOARD}?shopee=connected&amp;added=1&amp;failed=0"' in done.text
        listed = (await dashboard.get(SHOPS, headers=AUTH)).json()
    alpha = next(shop for shop in listed["shops"] if shop["alias"] == "store-alpha")
    assert alpha["shop_name"] == "Store Alpha" and alpha["source"] == "owner a" and alpha["shop_id"] == 100001
    assert listed["invites"][0]["status"] == "used" and listed["invites"][0]["aliases"] == ["store-alpha"]
    assert manager.invites.list_invites()[0]["return_to_dashboard"] is True


async def test_total_failure_links_back_as_failed(base, clock):
    shopee = FakeMainShopee(shop_ids=(100002,), fail_refresh={100002})
    app, _, _ = build(base, clock, {}, shopee)
    async with clients(app) as (dashboard, seller):
        created = await create(dashboard, return_to_dashboard=True)
        state = await continue_to_shopee(seller, created["url"][len(PUBLIC):])
        done = await seller.get("/callback", params={"code": SHOPEE_CODE, "main_account_id": MAIN_ACCOUNT_ID,
                                                     "state": state})
        assert done.status_code == 502
        assert f'href="{DASHBOARD}?shopee=failed"' in done.text


async def test_invites_without_flag_never_link_to_dashboard(base, clock):
    shopee = FakeMainShopee()
    app, _, _ = build(base, clock, {}, shopee)
    async with clients(app) as (dashboard, seller):
        created = await create(dashboard)
        state = await continue_to_shopee(seller, created["url"][len(PUBLIC):])
        done = await seller.get("/callback", params={"code": SHOPEE_CODE, "shop_id": "100001", "state": state})
        assert done.status_code == 200 and "1 shop(s) connected" in done.text
        assert "Back to dashboard" not in done.text and "dashboard.example.com" not in done.text


# ---------------------------------------------------------------- settings

def test_dashboard_settings_from_env(tmp_path):
    assert dashboard_settings_from_env({}) == (None, None)
    assert dashboard_settings_from_env({"SHOPEE_MCP_DASHBOARD_TOKEN": TOKEN}) == (TOKEN, None)
    token_file = tmp_path / "token"
    token_file.write_text(TOKEN + "\n")
    assert dashboard_settings_from_env({"SHOPEE_MCP_DASHBOARD_TOKEN_FILE": str(token_file),
                                        "SHOPEE_MCP_DASHBOARD_URL": DASHBOARD}) == (TOKEN, DASHBOARD)
    assert dashboard_settings_from_env({"SHOPEE_MCP_DASHBOARD_URL": "https://Dashboard.Example.com"}) == (
        None, "https://dashboard.example.com/")
    for environ in ({"SHOPEE_MCP_DASHBOARD_TOKEN": "short"},
                    {"SHOPEE_MCP_DASHBOARD_TOKEN": "has space " + "x" * 40},
                    {"SHOPEE_MCP_DASHBOARD_TOKEN": TOKEN, "SHOPEE_MCP_DASHBOARD_TOKEN_FILE": str(token_file)},
                    {"SHOPEE_MCP_DASHBOARD_TOKEN_FILE": str(tmp_path / "missing")},
                    {"SHOPEE_MCP_DASHBOARD_URL": "http://dashboard.example.com/x"},
                    {"SHOPEE_MCP_DASHBOARD_URL": "https://dashboard.example.com/x?a=1"},
                    {"SHOPEE_MCP_DASHBOARD_URL": "https://user:pw@dashboard.example.com/"},
                    {"SHOPEE_MCP_DASHBOARD_URL": "not a url"}):
        with pytest.raises(ValueError):
            dashboard_settings_from_env(environ)
