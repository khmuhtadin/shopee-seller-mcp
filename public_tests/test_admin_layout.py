"""Structural checks for the CSS-only admin dashboard. No external requests."""
import re
from html.parser import HTMLParser

from shopee_mcp.http_server import _ui_badge
from test_admin_shops import (ADMIN, base, build, clock, existing_shops, form_token, login)  # noqa: F401
from test_http_server import serving


class LayoutParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.stack = []
        self.tables = []
        self.external_assets = []
        self.viewport = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "meta" and attrs.get("name") == "viewport":
            self.viewport = "width=device-width" in attrs.get("content", "")
        if tag in ("script", "link", "iframe"):
            self.external_assets.append(tag)
        if tag == "table":
            self.tables.append(any("table-scroll" in node.get("class", "").split()
                                   for _, node in self.stack))
        if tag not in ("input", "meta", "br", "hr", "img", "link"):
            self.stack.append((tag, attrs))

    def handle_endtag(self, tag):
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index][0] == tag:
                del self.stack[index:]
                break


async def test_login_is_a_self_contained_centered_card(base, clock):
    app, _, _, _ = build(base, clock, {})
    async with serving(app) as client:
        response = await client.get(ADMIN)
        parsed = LayoutParser()
        parsed.feed(response.text)
        assert response.status_code == 200
        assert parsed.viewport and not parsed.external_assets
        assert '<body class="login">' in response.text
        assert 'Operator passphrase' in response.text and 'Sign in' in response.text
        assert form_token(response.text, "login")
        assert response.headers["cache-control"] == "no-store"
        assert "content-security-policy" in response.headers


async def test_dashboard_cards_and_scroll_regions_keep_existing_forms(base, clock):
    app, _, _, _ = build(base, clock, existing_shops(base))
    async with serving(app) as client:
        assert (await login(client)).status_code == 303
        response = await client.get(ADMIN)
        created = await client.post(ADMIN, data={
            "action": "invite-create", "csrf_token": form_token(response.text, "invite-create"),
            "label": "owner a", "ttl": "24h", "env": "sandbox",
        })
        assert created.status_code == 200
        parsed = LayoutParser()
        parsed.feed(created.text)
        assert parsed.viewport and not parsed.external_assets
        assert parsed.tables == [True, True]
        assert '<body class="dashboard">' in created.text
        assert created.text.count('class="stat"') == 3
        assert re.search(r'Connected shops</p><strong class="stat-value">2</strong>', created.text)
        assert re.search(r'Live shops</p><strong class="stat-value">0</strong>', created.text)
        assert re.search(r'Active invites</p><strong class="stat-value">1</strong>', created.text)
        assert 'class="card card-accent"' in created.text
        assert 'id="invite-url"' in created.text
        assert '<summary>Add shop directly</summary>' in created.text
        assert 'aria-label="New alias for store-a"' in created.text
        assert 'class="badge badge-sandbox"' in created.text
        header = created.text.split('</header>', 1)[0]
        assert 'Sign out' in header
        for action in ("add", "remove", "rename", "invite-create", "logout"):
            assert form_token(created.text, action)
        assert "@media(max-width:440px)" in created.text
        assert "overflow-x:auto" in created.text
        assert "overflow-wrap:anywhere" in created.text


def test_badge_runtime_values_are_escaped():
    badge = _ui_badge('<script>alert("x")</script>')
    assert '<script>' not in badge
    assert '&lt;script&gt;' in badge
    assert 'badge-neutral' in badge
