"""Remote Streamable HTTP mode for the read-only multi-shop MCP service.

Serves on 127.0.0.1 by default (put a TLS reverse proxy in front). Binding
another address (``--host``, e.g. inside a container) requires an https public
URL, and a client-IP header is then trusted only from explicitly configured
proxy networks (``--trusted-proxy``).

* ``POST /mcp`` - MCP Streamable HTTP, stateless, JSON responses. Requires
  ``Authorization: Bearer`` with either an operator static token or an OAuth
  access token issued by this server for this resource.
* OAuth 2.1 authorization server for remote connectors: RFC 9728 protected
  resource metadata, RFC 8414 metadata, RFC 7591 dynamic registration (public
  clients), ``/authorize`` (PKCE S256 + operator passphrase consent), ``/token``
  (authorization_code, refresh_token) and RFC 7009 ``/revoke``.
* ``GET/POST /admin/shops`` - operator-only shop onboarding (same passphrase,
  CSRF and throttling as ``/authorize``): list shops, "Add shop" through the
  Shopee seller authorization flow, "Remove shop". Changes are applied without
  a restart.
* ``GET/POST /invite/<token>`` - single-use invite link created by the operator:
  a remote seller approves this app on Shopee without the admin passphrase;
  authorized shops are added with automatic aliases.
* ``GET /callback`` - completes an invite flow (state bound to the invitee's
  browser cookie) or an "Add shop" flow when it carries a pending,
  session-bound state (``shop_id`` callbacks add the shop; ``main_account_id``
  callbacks open a shop picker); otherwise a static page for the
  ``shopee-auth`` CLI flow.
* ``/api/dashboard/*`` - optional server-to-server JSON API for an operator
  dashboard (list shops and invites, create and revoke invite links). Enabled
  only when ``SHOPEE_MCP_DASHBOARD_TOKEN`` (or ``..._FILE``) is set; it uses
  its own bearer token, never an MCP/OAuth token.
* ``GET /healthz``.

No token, code, passphrase or query string is ever logged.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import functools
import getpass
import hashlib
import hmac
import html
import ipaddress
import json
import logging
import math
import os
import secrets
import sqlite3
import sys
import time
from collections import deque
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit, urlunsplit

import anyio
from starlette.applications import Starlette
from starlette.datastructures import Headers
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route

from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.transport_security import RequestBodyLimitMiddleware, TransportSecuritySettings

from . import __version__
from .http_auth import (DEFAULT_SCOPE, LOOPBACK_HOSTS, AuthStore, AuthStoreError, OAuthError, Principal,
                        hash_secret)

logger = logging.getLogger("shopee_mcp.http")

MCP_PATH = "/mcp"
MAX_FORM_BYTES = 64 * 1024
MAX_MCP_BODY_BYTES = 4 * 1024 * 1024
CSRF_TTL = 600
ADMIN_PATH = "/admin/shops"
ADMIN_SESSION_TTL = 3600
INVITE_PATH_PREFIX = "/invite/"
INVITE_COOKIE_TTL = 3600
DASHBOARD_API_PREFIX = "/api/dashboard"
DASHBOARD_SHOPS_PATH = DASHBOARD_API_PREFIX + "/shops"
DASHBOARD_INVITES_PATH = DASHBOARD_API_PREFIX + "/invites"
DASHBOARD_TOKEN_MIN_LENGTH = 32
# The dashboard API speaks "live"/"sandbox"; shop files and invites use "production"/"sandbox".
_DASHBOARD_ENV_NAMES = {"production": "live", "sandbox": "sandbox"}
_DASHBOARD_ENV_INPUT = {"live": "production", "production": "production", "sandbox": "sandbox"}
_DASHBOARD_TTLS = {"1h": "1h", "24h": "24h", "3d": "72h", "72h": "72h", "7d": "7d"}
RETIRED_REGISTRY_GRACE = 300  # seconds an old shop registry stays open for in-flight requests
_INSTRUCTIONS = ("Read-only Shopee seller tools for operator-configured shops. Call list_connected_shops first and "
                 "pass an explicit shop alias. One Shopee API call fetches one data page; use returned cursors.")# At most two scrypt verifications at once (CPU/memory bound); extra attempts get 429 immediately.
PASSPHRASE_LIMITER = anyio.CapacityLimiter(2)
_LOGGED_PATHS = frozenset({
    "/mcp", "/mcp/", "/authorize", "/token", "/register", "/revoke", "/callback", "/healthz", ADMIN_PATH,
    DASHBOARD_SHOPS_PATH, DASHBOARD_INVITES_PATH,
    "/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp",
    "/.well-known/oauth-authorization-server", "/.well-known/oauth-authorization-server/mcp",
})
_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
}
_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}
_HTML_CSP = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'"


# ------------------------------------------------------------------ helpers

def normalize_public_url(value: str) -> str:
    """``https://host[:port]`` without path/query/fragment (loopback http allowed for testing)."""
    try:
        parts = urlsplit(value.strip())
        host = (parts.hostname or "").lower()
        parts.port  # noqa: B018 - validates the port
    except (ValueError, AttributeError):
        raise ValueError("public URL is invalid") from None
    if parts.scheme not in ("https", "http") or not host:
        raise ValueError("public URL must be an absolute https URL")
    if parts.scheme == "http" and host not in LOOPBACK_HOSTS:
        raise ValueError("public URL must use https (http is allowed only for loopback testing)")
    if parts.path not in ("", "/") or parts.query or parts.fragment or parts.username or parts.password:
        raise ValueError("public URL must not contain a path, query, fragment or credentials")
    return urlunsplit((parts.scheme, parts.netloc.lower(), "", "", ""))


def normalize_dashboard_url(value: str) -> str:
    """Absolute https URL of the operator dashboard page (path allowed; no query, fragment or credentials)."""
    try:
        parts = urlsplit(value.strip())
        host = (parts.hostname or "").lower()
        parts.port  # noqa: B018 - validates the port
    except (ValueError, AttributeError):
        raise ValueError("SHOPEE_MCP_DASHBOARD_URL is invalid") from None
    if parts.scheme != "https" or not host:
        raise ValueError("SHOPEE_MCP_DASHBOARD_URL must be an absolute https URL")
    if parts.query or parts.fragment or parts.username or parts.password or not value.strip().isprintable():
        raise ValueError("SHOPEE_MCP_DASHBOARD_URL must not contain a query, fragment or credentials")
    return urlunsplit(("https", parts.netloc.lower(), parts.path or "/", "", ""))


def dashboard_settings_from_env(environ: dict | None = None) -> tuple[str | None, str | None]:
    """``(token, url)`` for the dashboard API from the environment; ``(None, None)`` when not configured.

    ``SHOPEE_MCP_DASHBOARD_TOKEN`` (or ``SHOPEE_MCP_DASHBOARD_TOKEN_FILE``, a file
    holding the token) enables ``/api/dashboard/*``. ``SHOPEE_MCP_DASHBOARD_URL``
    is the page invitees are sent back to after an invite created with
    ``return_to_dashboard``.
    """
    environ = os.environ if environ is None else environ
    token = environ.get("SHOPEE_MCP_DASHBOARD_TOKEN") or None
    token_file = environ.get("SHOPEE_MCP_DASHBOARD_TOKEN_FILE") or None
    if token and token_file:
        raise ValueError("set only one of SHOPEE_MCP_DASHBOARD_TOKEN and SHOPEE_MCP_DASHBOARD_TOKEN_FILE")
    if token_file:
        try:
            token = Path(token_file).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            raise ValueError("SHOPEE_MCP_DASHBOARD_TOKEN_FILE could not be read") from None
    if token is not None:
        token = token.strip()
        if (len(token) < DASHBOARD_TOKEN_MIN_LENGTH or len(token) > 512 or not token.isascii()
                or not token.isprintable() or " " in token):
            raise ValueError(f"the dashboard token must be {DASHBOARD_TOKEN_MIN_LENGTH}-512 printable ASCII "
                             "characters without spaces")
    url = environ.get("SHOPEE_MCP_DASHBOARD_URL") or None
    return token, normalize_dashboard_url(url) if url else None


class Throttle:
    """In-memory sliding-window failure counter: per key plus a global lockout."""

    def __init__(self, *, per_key: int, global_limit: int, window: float, clock: Callable[[], float] = time.time,
                 max_keys: int = 10_000):
        self.per_key, self.global_limit, self.window, self.clock, self.max_keys = per_key, global_limit, window, clock, max_keys
        self._keys: dict[str, deque] = {}
        self._global: deque = deque()

    def _trim(self, events: deque, now: float) -> None:
        while events and events[0] <= now - self.window:
            events.popleft()

    def retry_after(self, key: str) -> int:
        """Seconds until another attempt is allowed (0 = allowed)."""
        now = self.clock()
        self._trim(self._global, now)
        waits = [0.0]
        if len(self._global) >= self.global_limit:
            waits.append(self._global[-self.global_limit] + self.window - now)
        events = self._keys.get(key)
        if events is not None:
            self._trim(events, now)
            if len(events) >= self.per_key:
                waits.append(events[-self.per_key] + self.window - now)
        return int(math.ceil(max(waits)))

    def failure(self, key: str) -> float:
        """Record an attempt (call BEFORE verifying); returns its stamp for ``success``."""
        now = self.clock()
        if key not in self._keys and len(self._keys) >= self.max_keys:
            for stale in [k for k, v in self._keys.items() if not v or v[-1] <= now - self.window]:
                del self._keys[stale]
            if len(self._keys) >= self.max_keys:
                self._keys.pop(next(iter(self._keys)))
        self._keys.setdefault(key, deque()).append(now)
        self._global.append(now)
        return now

    def success(self, key: str, stamp: float) -> None:
        """Forget the key's history and the pre-recorded global entry of this attempt."""
        self._keys.pop(key, None)
        with contextlib.suppress(ValueError):
            self._global.remove(stamp)

    def reset(self, key: str) -> None:
        self._keys.pop(key, None)


def _single_values(pairs: list[tuple[str, str]]) -> dict[str, str]:
    """OAuth parameters must not repeat (RFC 6749 section 3.1)."""
    result: dict[str, str] = {}
    for key, value in pairs:
        if key in result:
            raise OAuthError("invalid_request", "repeated parameter")
        result[key] = value
    return result


def _add_query(uri: str, params: dict[str, str]) -> str:
    parts = urlsplit(uri)
    query = parts.query + ("&" if parts.query else "") + urlencode(params)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))


def _oauth_json_error(error: OAuthError) -> JSONResponse:
    body = {"error": error.error}
    if error.description:
        body["error_description"] = error.description
    return JSONResponse(body, status_code=error.status, headers=_NO_STORE)


def _ui_badge(value: str) -> str:
    classes = {"production": "live", "live": "live", "sandbox": "sandbox", "ok": "ok",
               "active": "active", "expired": "expired", "revoked": "revoked"}
    kind = classes.get(value, "neutral")
    label = "live" if value == "production" else value
    return f'<span class="badge badge-{kind}">{html.escape(label)}</span>'


def _html_page(title: str, body: str, status: int = 200, headers: dict | None = None, *,
               layout: str = "default", header_actions: str = "") -> HTMLResponse:
    css = """
:root{font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#243247;background:#f5f7fa;font-synthesis:none}
*{box-sizing:border-box}body{margin:0;font-size:14px;line-height:1.55}a{color:#bd4b18}h1,h2,h3,p{margin:0}h1{font-size:25px;line-height:1.25;letter-spacing:-.6px;color:#182438}h2{font-size:18px;letter-spacing:-.3px;color:#182438}h3{font-size:15px}.shell{width:min(100% - 48px,720px);margin:48px auto}.dashboard .shell{width:min(100% - 48px,1180px);margin:32px auto}.page-header{display:flex;align-items:center;justify-content:space-between;gap:20px;margin-bottom:26px}.eyebrow{text-transform:uppercase;letter-spacing:1.8px;font-size:10px;font-weight:750;color:#bf531f;margin-bottom:9px}.subtitle,.muted{color:#748094}.subtitle{margin-top:7px}.content{min-width:0}.content>p,.content>form,.content>.box{margin-bottom:18px}.card,.box{background:#fff;border:1px solid #e2e7ee;border-radius:14px;padding:24px;min-width:0}.card{margin-bottom:22px}.card-heading{margin-bottom:20px}.card-heading p{color:#748094;margin-top:5px}.card-accent{border-top:3px solid #e97942}.card p+p{margin-top:10px}.stats{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px;margin:0 0 24px}.stat{background:#fff;border:1px solid #e2e7ee;border-radius:12px;padding:19px 22px}.stat-label{font-size:12px;color:#748094}.stat-value{display:block;font-size:30px;letter-spacing:-1px;font-weight:650;margin-top:3px;color:#182438}.stat-note{font-size:11px;color:#929aab}.table-scroll{max-width:100%;overflow-x:auto;overscroll-behavior-x:contain}.table-scroll table{min-width:780px}table{border-collapse:collapse;width:100%;font-size:12px}th{text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:.7px;color:#8590a0;font-weight:650;background:#f8fafc}td,th{padding:13px 12px;border-bottom:1px solid #edf0f4;vertical-align:middle}tbody tr:last-child td{border-bottom:0}.date{white-space:nowrap;font-size:11px;color:#748094}code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:.9em;overflow-wrap:anywhere;word-break:break-word}table code{font-weight:650;color:#33445b}.badge{display:inline-flex;align-items:center;border-radius:5px;padding:3px 8px;font-size:10px;font-weight:650;background:#eef2f6;color:#69778c;white-space:nowrap}.badge-live,.badge-ok,.badge-active{background:#ecf7f0;color:#2f7c50}.badge-sandbox{background:#fff4e7;color:#ad6d22}.badge-expired,.badge-revoked{background:#f4f5f7;color:#8b95a4}.badge-error{background:#fff0ee;color:#b34a3e}form{margin:0}label{display:inline-block;font-size:12px;font-weight:600;color:#4f5e72;margin-bottom:6px}input,select,button{font:inherit}input:not([type=hidden]),select{border:1px solid #dbe1e9;border-radius:7px;background:#fff;color:#33445b;max-width:100%;padding:10px 11px;min-height:40px}input:focus,select:focus,button:focus-visible,summary:focus-visible{outline:3px solid #fbd9c5;outline-offset:2px;border-color:#e97942}input[type=password]{width:100%}button{border:1px solid transparent;border-radius:7px;background:#df6a32;color:#fff;font-weight:600;font-size:12px;padding:10px 15px;min-height:40px;cursor:pointer;white-space:nowrap}button:hover{background:#c95c29}.button-secondary{background:#fff;color:#56647a;border-color:#dde3eb}.button-secondary:hover{background:#f6f8fb}.button-danger{background:transparent;color:#a66863;padding:7px 10px;font-weight:500}.button-danger:hover{background:#fff0ee;color:#a43f35}.inline-form{display:flex;align-items:center;gap:7px}.inline-form input{width:122px;min-height:32px;padding:6px 8px;font-size:12px}.inline-form button{min-height:32px;padding:6px 10px;font-size:11px}.form-grid{display:grid;grid-template-columns:minmax(180px,2fr) minmax(120px,1fr) minmax(120px,1fr) auto;gap:15px;align-items:end;margin:18px 0}.form-grid p{min-width:0}.form-grid p+p{margin:0}.form-grid input,.form-grid select{width:100%}.help{font-size:12px;color:#7c8797;max-width:760px;margin:12px 0 20px;overflow-wrap:anywhere}.notice{background:#edf7f0;border:1px solid #d7ebdd;border-radius:8px;padding:11px 15px;margin-bottom:20px;color:#39774f}.err{color:#ab3b31;background:#fff1ee;border-radius:8px;padding:12px 15px;margin-bottom:18px}.empty{padding:28px;text-align:center;color:#8590a0;background:#f9fafc;border-radius:8px}.invite-url{border:1px solid #f2cfb9;background:#fff9f4;border-radius:9px;padding:15px;margin:16px 0;overflow-wrap:anywhere}.invite-url p{font-size:12px;color:#976243}.invite-url code{display:block;margin-top:9px;color:#ab4a1b}.invites-history{margin-top:22px}.section-details>summary{cursor:pointer;font-size:16px;font-weight:650;color:#46556a}.section-details[open]>summary{margin-bottom:20px}.section-details>h2{display:none}.login .shell{max-width:430px;margin:clamp(30px,12vh,110px) auto}.login .page-header{display:block;margin-bottom:28px}.login .content{padding:27px;background:#fff;border:1px solid #e2e7ee;border-radius:14px}.login form p+p{margin-top:20px}.login form button{width:100%}.login .content>form{margin:0}.login .subtitle{max-width:360px}.default .content form p{margin-bottom:15px}.default .content label{margin-top:5px}.default .content input{max-width:100%}.button-link{display:inline-block;border-radius:7px;background:#df6a32;color:#fff;font-weight:600;font-size:13px;padding:11px 18px;text-decoration:none}.button-link:hover{background:#c95c29}.dashboard-back{margin-top:22px}hr{border:0;border-top:1px solid #e2e7ee;margin:24px 0}
@media(max-width:760px){.shell,.dashboard .shell{width:calc(100% - 32px);margin:24px auto}.page-header{align-items:flex-start;gap:12px}h1{font-size:22px}.subtitle{font-size:12px}.stats{gap:10px}.stat{padding:15px}.stat-value{font-size:26px}.card{padding:18px}.form-grid{grid-template-columns:1fr 1fr}.form-grid p:first-of-type{grid-column:1/-1}.form-grid .form-submit{grid-column:1/-1}.form-submit button{width:100%}.login .shell{margin-top:36px}}
@media(max-width:440px){.stats{grid-template-columns:1fr}.stat{display:grid;grid-template-columns:1fr auto;align-items:center;padding:12px 16px}.stat-value{grid-column:2;grid-row:1/3;font-size:27px;margin:0}.stat-note{grid-column:1}.form-grid{grid-template-columns:1fr}.form-grid p{grid-column:1!important}.page-header .button-secondary{padding:8px 11px;min-height:35px}.card{padding:17px}.login .content{padding:22px}.eyebrow{font-size:9px}.card-heading{margin-bottom:15px}}
"""
    subtitle = {"dashboard": "Manage connected shops and authorization invites.",
                "login": "Sign in to manage your shops and invitation links."}.get(layout, "")
    page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex"><title>{html.escape(title)}</title>
<style>{css}</style></head><body class="{html.escape(layout)}"><main class="shell">
<header class="page-header"><div><p class="eyebrow">Seller MCP</p><h1>{html.escape(title)}</h1>
{f'<p class="subtitle">{html.escape(subtitle)}</p>' if subtitle else ''}</div>{header_actions}</header>
<div class="content">{body}</div></main></body></html>"""
    merged = {**_NO_STORE, "Content-Security-Policy": _HTML_CSP, "X-Robots-Tag": "noindex"}
    merged.update(headers or {})
    return HTMLResponse(page, status_code=status, headers=merged)


# ---------------------------------------------------------------------- app

class ShopeeHTTPApp:
    """Top-level ASGI app. ``/mcp`` is authenticated before the MCP SDK sees the request."""

    def __init__(self, service: Any, store: AuthStore, public_url: str, *, client_ip_header: str | None = None,
                 clock: Callable[[], float] = time.time, register_limit_per_hour: int = 60,
                 trusted_proxies: list[str] | None = None, shop_manager: Any = None,
                 service_factory: Callable[[dict], tuple[Any, Any]] | None = None, registry: Any = None,
                 dashboard_token: str | None = None, dashboard_url: str | None = None):
        # ``service`` is swapped atomically when shops are added/removed; the MCP
        # server below always dispatches to the current one, so no restart is needed.
        self.service = service
        self.registry = registry if registry is not None else getattr(service, "registry", None)
        self.shop_manager = shop_manager
        self.service_factory = service_factory
        self._retired: list[tuple[float, Any]] = []
        self._shops_lock = asyncio.Lock()  # serializes shop add/remove (one event loop)
        self._admin_sessions: dict[str, float] = {}  # sha256(session cookie) -> expiry
        self.trusted_proxies = [ipaddress.ip_network(value, strict=False) for value in (trusted_proxies or [])]
        self.store = store
        self.clock = clock
        self.issuer = normalize_public_url(public_url)
        self.resource = self.issuer + MCP_PATH
        self.prm_url = self.issuer + "/.well-known/oauth-protected-resource" + MCP_PATH
        self.secure_cookies = self.issuer.startswith("https://")
        self.csrf_cookie = "__Host-smcp_csrf" if self.secure_cookies else "smcp_csrf"
        self.admin_cookie = "__Host-smcp_admin" if self.secure_cookies else "smcp_admin"
        self.invite_cookie = "__Host-smcp_invite" if self.secure_cookies else "smcp_invite"
        self.client_ip_header = client_ip_header.lower() if client_ip_header else None
        self.passphrase_throttle = Throttle(per_key=5, global_limit=20, window=900, clock=clock)
        self.register_throttle = Throttle(per_key=register_limit_per_hour, global_limit=register_limit_per_hour,
                                          window=3600, clock=clock)
        # Every /invite request counts (valid or not): 20 per client and 300 overall per 15 minutes.
        self.invite_throttle = Throttle(per_key=20, global_limit=300, window=900, clock=clock)
        # Dashboard API: only the sha256 of its token is kept; failed attempts are throttled.
        self._dashboard_token_hash = hash_secret(dashboard_token) if dashboard_token else None
        self.dashboard_url = normalize_dashboard_url(dashboard_url) if dashboard_url else None
        self.dashboard_throttle = Throttle(per_key=10, global_limit=100, window=900, clock=clock)
        self._used_nonces: dict[str, float] = {}  # single-use consent form tokens, until expiry
        # Stateless + JSON: every POST is self-contained (no Mcp-Session-Id, no
        # long-lived SSE), so proxies with idle timeouts and server restarts
        # never break a client. Host/Origin checks are not used: authentication is
        # an explicit bearer header (no ambient cookies), and the server binds to
        # loopback behind the operator's reverse proxy.
        self.server = Server("shopee", version=__version__, instructions=_INSTRUCTIONS,
                             on_list_tools=self._list_tools, on_call_tool=self._call_tool,
                             on_list_resources=self._list_resources, on_read_resource=self._read_resource)
        self.manager = StreamableHTTPSessionManager(
            app=self.server, json_response=True, stateless=True,
            security_settings=TransportSecuritySettings(enable_dns_rebinding_protection=False),
            max_request_body_size=MAX_MCP_BODY_BYTES)
        routes = [
            Route("/.well-known/oauth-protected-resource", self.protected_resource_metadata, methods=["GET", "OPTIONS"]),
            Route("/.well-known/oauth-protected-resource/mcp", self.protected_resource_metadata, methods=["GET", "OPTIONS"]),
            Route("/.well-known/oauth-authorization-server", self.authorization_server_metadata, methods=["GET", "OPTIONS"]),
            Route("/.well-known/oauth-authorization-server/mcp", self.authorization_server_metadata, methods=["GET", "OPTIONS"]),
            Route("/register", self.register, methods=["POST"]),
            Route("/authorize", self.authorize, methods=["GET", "POST"]),
            Route("/token", self.token, methods=["POST"]),
            Route("/revoke", self.revoke, methods=["POST"]),
            Route("/callback", self.callback, methods=["GET"]),
            Route(ADMIN_PATH, self.admin_shops, methods=["GET", "POST"]),
            Route(INVITE_PATH_PREFIX + "{token}", self.invite, methods=["GET", "POST"]),
            Route(DASHBOARD_SHOPS_PATH, self.dashboard_shops, methods=["GET"]),
            Route(DASHBOARD_INVITES_PATH, self.dashboard_create_invite, methods=["POST"]),
            Route(DASHBOARD_INVITES_PATH + "/{invite_id}", self.dashboard_revoke_invite, methods=["DELETE"]),
            Route("/healthz", self.healthz, methods=["GET"]),
        ]
        self.web = RequestBodyLimitMiddleware(Starlette(routes=routes, lifespan=lambda _app: self.run()), MAX_FORM_BYTES)

    @contextlib.asynccontextmanager
    async def run(self):
        """Run the MCP session manager (used as the ASGI lifespan; callable directly in tests)."""
        async with self.manager.run():
            yield

    async def aclose(self) -> None:
        """Close the current and all retired shop registries (idempotent)."""
        registries = [registry for _, registry in self._retired]
        self._retired = []
        if self.registry is not None:
            registries.append(self.registry)
        for registry in registries:
            with contextlib.suppress(Exception):
                await registry.close()

    # ------------------------------------------------------ MCP dispatch

    async def _list_tools(self, context, params):
        return await self.service.list_tools(context, params)

    async def _call_tool(self, context, params):
        return await self.service.call_tool(context, params)

    async def _list_resources(self, context, params):
        return await self.service.list_resources(context, params)

    async def _read_resource(self, context, params):
        return await self.service.read_resource(context, params)

    # ------------------------------------------------------------- ASGI

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.web(scope, receive, send)
            return
        started = time.monotonic()
        status_holder = {"status": 0}

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                status_holder["status"] = message["status"]
                headers = list(message.get("headers", []))
                present = {name.lower() for name, _ in headers}
                for name, value in _SECURITY_HEADERS.items():
                    if name.lower().encode() not in present:
                        headers.append((name.lower().encode(), value.encode()))
                message = {**message, "headers": headers}
            await send(message)

        try:
            if scope["path"] in (MCP_PATH, MCP_PATH + "/"):
                await self._mcp(scope, receive, send_with_headers)
            else:
                await self.web(scope, receive, send_with_headers)
        finally:
            if scope["path"] in _LOGGED_PATHS:
                path = scope["path"]
            elif scope["path"].startswith(INVITE_PATH_PREFIX):
                path = INVITE_PATH_PREFIX + "(redacted)"   # the path carries the invite token
            elif scope["path"].startswith(DASHBOARD_INVITES_PATH + "/"):
                path = DASHBOARD_INVITES_PATH + "/(id)"
            else:
                path = "(other)"
            logger.info("%s %s %s %.0fms", scope.get("method", "-"), path, status_holder["status"],
                        (time.monotonic() - started) * 1000)

    def _trusted_peer(self, address: str) -> bool:
        if address in LOOPBACK_HOSTS:
            return True
        if not self.trusted_proxies:
            return False
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False
        return any(ip in network for network in self.trusted_proxies)

    def client_ip(self, scope) -> str:
        """Peer address. The configured proxy header is honoured only from a loopback peer or a
        ``--trusted-proxy`` network; the right-most hop that is not a trusted proxy wins, so
        client-supplied values prepended to a list header cannot choose the throttle key."""
        peer = (scope.get("client") or ("unknown", 0))[0]
        if not self.client_ip_header or not self._trusted_peer(peer):
            return peer
        value = Headers(scope=scope).get(self.client_ip_header)
        hops = [hop.strip()[:64] for hop in (value or "").split(",") if hop.strip()]
        for hop in reversed(hops):
            if not self._trusted_peer(hop):
                return hop
        return hops[0] if hops else peer

    async def _db(self, function, *args):
        """Every SQLite call runs in a worker thread, never on the event loop."""
        return await anyio.to_thread.run_sync(functools.partial(function, *args))

    async def authenticate(self, authorization: str | None) -> Principal | None:
        if not authorization:
            return None
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer":
            return None
        return await self._db(self.store.verify_bearer, token.strip(), self.resource)

    def _unauthorized(self, error: str | None, description: str) -> Response:
        parts = [f'resource_metadata="{self.prm_url}"', f'scope="{DEFAULT_SCOPE}"']
        body = {"error": "unauthorized", "error_description": description}
        if error:
            parts.append(f'error="{error}"')
            parts.append(f'error_description="{description}"')
            body["error"] = error
        return JSONResponse(body, status_code=401, headers={"WWW-Authenticate": "Bearer " + ", ".join(parts), **_NO_STORE})

    async def _mcp(self, scope, receive, send):
        authorization = Headers(scope=scope).get("authorization")
        try:
            principal = await self.authenticate(authorization)
        except Exception:
            logger.error("authentication backend failure (details suppressed)")
            await _unavailable()(scope, receive, send)
            return
        if principal is None:
            response = (self._unauthorized("invalid_token", "The access token is invalid, expired or revoked")
                        if authorization else self._unauthorized(None, "Bearer token required"))
            await response(scope, receive, send)
            return
        if scope["method"] != "POST":
            # Stateless JSON mode: no standalone SSE stream and no sessions to delete.
            await Response(status_code=405, headers={"Allow": "POST"})(scope, receive, send)
            return
        if scope["path"] != MCP_PATH:
            scope = {**scope, "path": MCP_PATH, "raw_path": MCP_PATH.encode()}
        await self.manager.handle_request(scope, receive, send)

    # --------------------------------------------------------- metadata

    def _cors_json(self, request: Request, body: dict) -> Response:
        headers = {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET, OPTIONS",
                   "Access-Control-Allow-Headers": "mcp-protocol-version", "Cache-Control": "public, max-age=300"}
        if request.method == "OPTIONS":
            return Response(status_code=204, headers=headers)
        return JSONResponse(body, headers=headers)

    async def protected_resource_metadata(self, request: Request) -> Response:
        return self._cors_json(request, {
            "resource": self.resource,
            "authorization_servers": [self.issuer],
            "scopes_supported": [DEFAULT_SCOPE],
            "bearer_methods_supported": ["header"],
            "resource_name": "Shopee seller MCP (read-only)",
        })

    async def authorization_server_metadata(self, request: Request) -> Response:
        return self._cors_json(request, {
            "issuer": self.issuer,
            "authorization_endpoint": self.issuer + "/authorize",
            "token_endpoint": self.issuer + "/token",
            "registration_endpoint": self.issuer + "/register",
            "revocation_endpoint": self.issuer + "/revoke",
            "scopes_supported": [DEFAULT_SCOPE],
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_methods_supported": ["none"],
            "revocation_endpoint_auth_methods_supported": ["none"],
            "code_challenge_methods_supported": ["S256"],
            "authorization_response_iss_parameter_supported": True,
        })

    # ------------------------------------------------------ registration

    async def register(self, request: Request) -> Response:
        # Global cap only: a per-IP key would be meaningless for spoofable/shared addresses.
        if self.register_throttle.retry_after("register"):
            return JSONResponse({"error": "invalid_client_metadata", "error_description": "too many registrations"},
                                status_code=429, headers=_NO_STORE)
        self.register_throttle.failure("register")  # counts every registration attempt
        try:
            metadata = json.loads(await request.body())
            client = await self._db(self.store.register_client, metadata)
        except OAuthError as error:
            return _oauth_json_error(error)
        except sqlite3.Error:
            return _unavailable()
        except (ValueError, TypeError, RecursionError):
            return _oauth_json_error(OAuthError("invalid_client_metadata", "body must be a valid JSON object"))
        logger.info("registered OAuth client %s", client["client_name"][:40].encode("ascii", "replace").decode())
        return JSONResponse(client, status_code=201, headers=_NO_STORE)

    # -------------------------------------------------------- authorize

    def _canonical_resource(self, value: str | None) -> str:
        if value is None or value == "":
            return self.resource
        if value.rstrip("/") in (self.resource, self.issuer):
            return self.resource
        raise OAuthError("invalid_target", "unknown resource")

    async def _validate_authorization(self, params: dict[str, str]):
        """Return (client, request dict) or raise. ``_PageError`` must not redirect."""
        client = await self._db(self.store.get_client, params.get("client_id"))
        if client is None:
            raise _PageError("Unknown or revoked client. Remove and re-add the connector.")
        redirect_uri = params.get("redirect_uri")
        if redirect_uri is None or redirect_uri not in client["redirect_uris"]:
            raise _PageError("The redirect URI does not exactly match a registered redirect URI.")
        state = params.get("state")
        if state is not None and len(state) > 2000:
            raise _PageError("The state parameter is too long.")
        request = {"client_id": client["client_id"], "redirect_uri": redirect_uri, "state": state}
        try:
            if params.get("response_type") != "code":
                raise OAuthError("unsupported_response_type", "response_type must be code")
            if params.get("code_challenge_method") != "S256":
                raise OAuthError("invalid_request", "PKCE with code_challenge_method=S256 is required")
            challenge = params.get("code_challenge", "")
            if len(challenge) != 43 or not all(ch.isascii() and (ch.isalnum() or ch in "-_") for ch in challenge):
                raise OAuthError("invalid_request", "invalid code_challenge")
            scope = params.get("scope")
            if scope is not None and len(scope) > 500:
                raise OAuthError("invalid_scope", "scope too long")
            request.update(code_challenge=challenge, resource=self._canonical_resource(params.get("resource")),
                           scope=DEFAULT_SCOPE, requested_scope=scope)
        except OAuthError as error:
            raise _RedirectError(error, request) from None
        return client, request

    def _redirect_error(self, error: OAuthError, request: dict) -> Response:
        params = {"error": error.error, "error_description": error.description, "iss": self.issuer}
        if request.get("state") is not None:
            params["state"] = request["state"]
        return RedirectResponse(_add_query(request["redirect_uri"], params), status_code=303, headers=_NO_STORE)

    def _csrf_mac(self, cookie: str, request: dict, issued: int, nonce: str) -> str:
        bound = json.dumps([request["client_id"], request["redirect_uri"], request.get("state"),
                            request["code_challenge"], request["resource"], cookie, issued, nonce], separators=(",", ":"))
        return hmac.new(self.store.server_secret(), b"csrf\x00" + bound.encode(), hashlib.sha256).hexdigest()

    def _csrf_token(self, cookie: str, request: dict) -> str:
        issued, nonce = int(self.clock()), secrets.token_urlsafe(12)
        return f"{issued}.{nonce}.{self._csrf_mac(cookie, request, issued, nonce)}"

    def _csrf_consume(self, token: str | None, cookie: str | None, request: dict) -> bool:
        """Valid, unexpired and never used before; a token is accepted only once."""
        if not token or not cookie or len(token) > 200 or len(cookie) > 100:
            return False
        issued_text, _, rest = token.partition(".")
        nonce, _, mac = rest.partition(".")
        if not issued_text.isdigit() or not nonce or not mac:
            return False
        issued, now = int(issued_text), self.clock()
        if not 0 <= now - issued <= CSRF_TTL:
            return False
        if not hmac.compare_digest(mac, self._csrf_mac(cookie, request, issued, nonce)):
            return False
        return self._use_nonce(nonce, issued + CSRF_TTL, now)

    def _use_nonce(self, nonce: str, expiry: float, now: float) -> bool:
        for stale in [key for key, until in self._used_nonces.items() if until < now]:
            del self._used_nonces[stale]
        if nonce in self._used_nonces or len(self._used_nonces) >= 50_000:
            return False
        self._used_nonces[nonce] = expiry
        return True

    async def _consent_page(self, request_obj: Request, client: dict, request: dict, *, error: str | None = None,
                            status: int = 200) -> Response:
        cookie = request_obj.cookies.get(self.csrf_cookie)
        if not cookie or len(cookie) > 100:
            cookie = secrets.token_urlsafe(24)
        hidden = {"response_type": "code", "client_id": request["client_id"], "redirect_uri": request["redirect_uri"],
                  "code_challenge": request["code_challenge"], "code_challenge_method": "S256",
                  "resource": request["resource"], "csrf_token": self._csrf_token(cookie, request)}
        if request.get("state") is not None:
            hidden["state"] = request["state"]
        if request.get("requested_scope") is not None:
            hidden["scope"] = request["requested_scope"]
        fields = "".join(f'<input type="hidden" name="{html.escape(k)}" value="{html.escape(v)}">' for k, v in hidden.items())
        notice = f'<p class="err" role="alert">{html.escape(error)}</p>' if error else ""
        configured = "" if await self._db(self.store.has_admin_passphrase) else (
            '<p class="err">No admin passphrase is configured on the server; run '
            '<code>shopee-mcp-http admin set-passphrase</code> first.</p>')
        body = f"""<p class="err"><strong>Only approve if you just clicked Connect in ChatGPT/Claude.</strong></p>
<div class="box"><p><strong>{html.escape(client["client_name"])}</strong> wants read-only access to
<code>{html.escape(self.resource)}</code>.</p>
<p>Client ID: <code>{html.escape(client["client_id"])}</code><br>
Registered: {html.escape(_age(self.clock() - client["created_at"]))}<br>
Redirects to: <code>{html.escape(request["redirect_uri"])}</code></p></div>{configured}{notice}
<form method="post" action="/authorize" autocomplete="off">{fields}
<p><label for="passphrase">Operator passphrase</label><br>
<input id="passphrase" name="passphrase" type="password" autocomplete="current-password" required autofocus></p>
<p><button type="submit" name="decision" value="approve">Approve</button>
<button type="submit" name="decision" value="deny" formnovalidate>Deny</button></p></form>"""
        response = _html_page("Authorize MCP connector", body, status=status)
        response.set_cookie(self.csrf_cookie, cookie, max_age=CSRF_TTL * 2, path="/", secure=self.secure_cookies,
                            httponly=True, samesite="strict")
        return response

    async def authorize(self, request: Request) -> Response:
        try:
            return await self._authorize(request)
        except sqlite3.Error:
            logger.error("auth store unavailable during authorization")
            return _html_page("Temporarily unavailable", "<p>Please try again in a moment.</p>", status=503)

    async def _authorize(self, request: Request) -> Response:
        try:
            if request.method == "GET":
                params = _single_values(list(request.query_params.multi_items()))
            else:
                params = _single_values(parse_qsl((await request.body()).decode("utf-8"), keep_blank_values=True))
        except (OAuthError, UnicodeDecodeError):
            return _html_page("Authorization failed", "<p>Malformed authorization request.</p>", status=400)
        try:
            client, auth_request = await self._validate_authorization(params)
        except _PageError as error:
            return _html_page("Authorization failed", f"<p>{html.escape(str(error))}</p>", status=400)
        except _RedirectError as error:
            return self._redirect_error(error.error, error.request)
        if request.method == "GET":
            return await self._consent_page(request, client, auth_request)

        if not self._csrf_consume(params.get("csrf_token"), request.cookies.get(self.csrf_cookie), auth_request):
            return await self._consent_page(request, client, auth_request, status=403,
                                            error="This form expired, was already submitted, or was not submitted from this page. Please try again.")
        if params.get("decision") == "deny":
            return self._redirect_error(OAuthError("access_denied", "the operator denied the request"), auth_request)
        if params.get("decision") != "approve":
            return await self._consent_page(request, client, auth_request, status=400, error="Choose Approve or Deny.")
        key = self.client_ip(request.scope)
        wait = self.passphrase_throttle.retry_after(key)
        if wait:
            minutes = max(1, math.ceil(wait / 60))
            return await self._consent_page(request, client, auth_request, status=429,
                                            error=f"Too many failed attempts. Try again in about {minutes} minute(s).")
        borrower = object()
        try:
            PASSPHRASE_LIMITER.acquire_on_behalf_of_nowait(borrower)
        except anyio.WouldBlock:
            return await self._consent_page(request, client, auth_request, status=429,
                                            error="The server is busy verifying another attempt. Try again shortly.")
        try:
            # Counted before verifying so parallel guesses cannot outrun the limit.
            stamp = self.passphrase_throttle.failure(key)
            valid = await self._db(self.store.verify_admin_passphrase, params.get("passphrase", ""))
        finally:
            PASSPHRASE_LIMITER.release_on_behalf_of(borrower)
        if not valid:
            logger.warning("rejected consent passphrase")
            return await self._consent_page(request, client, auth_request, status=403, error="Incorrect passphrase.")
        self.passphrase_throttle.success(key, stamp)
        code = await self._db(self.store.create_code, auth_request["client_id"], auth_request["redirect_uri"],
                              auth_request["code_challenge"], auth_request["resource"], auth_request["scope"])
        params_out = {"code": code, "iss": self.issuer}
        if auth_request.get("state") is not None:
            params_out["state"] = auth_request["state"]
        logger.info("authorization approved for OAuth client")
        return RedirectResponse(_add_query(auth_request["redirect_uri"], params_out), status_code=303, headers=_NO_STORE)

    # ------------------------------------------------------------ token

    def _basic_client_id(self, request: Request) -> str | None:
        header = request.headers.get("authorization", "")
        scheme, _, value = header.partition(" ")
        if scheme.lower() != "basic" or not value:
            return None
        try:
            decoded = base64.b64decode(value.strip(), validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return None
        return unquote(decoded.partition(":")[0]) or None

    async def token(self, request: Request) -> Response:
        try:
            form = _single_values(parse_qsl((await request.body()).decode("utf-8"), keep_blank_values=True))
            client_id = form.get("client_id") or self._basic_client_id(request)
            resource = form.get("resource")
            resource = None if resource is None else self._canonical_resource(resource)
            grant_type = form.get("grant_type")
            if grant_type == "authorization_code":
                result = await self._db(self.store.exchange_code, form.get("code"), client_id, form.get("redirect_uri"),
                                        form.get("code_verifier"), resource)
            elif grant_type == "refresh_token":
                result = await self._db(self.store.refresh, form.get("refresh_token"), client_id, resource)
            else:
                raise OAuthError("unsupported_grant_type", "grant_type must be authorization_code or refresh_token")
        except OAuthError as error:
            logger.info("token request rejected: %s", error.error)
            return _oauth_json_error(error)
        except sqlite3.Error:
            logger.error("auth store unavailable during token request")
            return _unavailable()
        except UnicodeDecodeError:
            return _oauth_json_error(OAuthError("invalid_request", "malformed body"))
        with contextlib.suppress(Exception):
            await self._db(self.store.prune)
        return JSONResponse(result, headers=_NO_STORE)

    async def revoke(self, request: Request) -> Response:
        try:
            form = _single_values(parse_qsl((await request.body()).decode("utf-8"), keep_blank_values=True))
        except (OAuthError, UnicodeDecodeError):
            return _oauth_json_error(OAuthError("invalid_request", "malformed body"))
        try:
            await self._db(self.store.revoke_token, form.get("token"))
        except sqlite3.Error:
            return _unavailable()
        return Response(status_code=200, headers=_NO_STORE)

    # ------------------------------------------------------------- misc

    async def callback(self, request: Request) -> Response:
        pending = None
        states = request.query_params.getlist("state")
        if self.shop_manager is not None and len(states) == 1:
            # Consumed here: a pending state can be presented exactly once.
            pending = self.shop_manager.take_pending(states[0])
        if pending is None:
            body = ("<p>The Shopee authorization redirect was received. This page does not process or store anything.</p>"
                    "<p>Copy the complete URL from the address bar and paste it into the <code>shopee-auth</code> command "
                    "that is waiting for it. Do not share this URL with anyone else.</p>")
            return _html_page("Shopee authorization received", body)
        if pending.invite:
            return await self._invite_callback(request, pending, states[0])
        back = f'<p><a href="{ADMIN_PATH}">Back to shops</a></p>'
        session = self._admin_session(request)
        if session is None or not hmac.compare_digest(session, pending.session):
            logger.warning("shop authorization callback rejected: not the admin session that started it")
            return _html_page("Shop authorization failed", "<p class=\"err\">This authorization was not started from "
                              "your current admin session (or the session expired). Nothing was saved. Sign in and "
                              "start <em>Add shop</em> again.</p>" + back, status=403)
        codes, shop_ids = request.query_params.getlist("code"), request.query_params.getlist("shop_id")
        accounts = request.query_params.getlist("main_account_id")
        from .shop_admin import ShopAdminError
        if len(codes) == 1 and codes[0] and not shop_ids and len(accounts) == 1 and accounts[0]:
            try:
                grant = await anyio.to_thread.run_sync(functools.partial(
                    self.shop_manager.complete_main_account, pending, codes[0], accounts[0]))
            except ShopAdminError as error:
                logger.warning("main account authorization failed (details suppressed)")
                return _html_page("Shop authorization failed", f'<p class="err">{html.escape(str(error))}</p>' + back,
                                  status=error.status)
            logger.info("main account authorization exchanged; awaiting shop selection")
            return self._main_account_page(session, grant)
        if len(codes) != 1 or len(shop_ids) != 1 or not codes[0] or not shop_ids[0] or accounts:
            return _html_page("Shop authorization failed", "<p class=\"err\">Shopee did not return a shop or main "
                              "account authorization. Start <em>Add shop</em> again.</p>" + back, status=400)
        try:
            async with self._shops_lock:
                await self._add_shop(pending, codes[0], shop_ids[0], states[0])
        except ShopAdminError as error:
            logger.warning("shop authorization failed (details suppressed)")
            return _html_page("Shop authorization failed", f'<p class="err">{html.escape(str(error))}</p>' + back,
                              status=error.status)
        logger.info("shop added through admin onboarding")
        return _html_page("Shop connected", f"<p>Shop <strong>{html.escape(pending.alias)}</strong> "
                          f"({html.escape(pending.env)}) is connected and available to MCP clients now.</p>" + back)


    # ------------------------------------------------------------ invites

    def _invite_gone(self, status: int = 404) -> Response:
        return _html_page("Link not available", "<p>This link is invalid, has expired or was already used. "
                          "Ask the person who sent it for a new one.</p>", status=status)

    def _invite_binding(self, invite_id: str, cookie: str) -> str:
        return f"{invite_id}:{hash_secret(cookie)}"

    def _set_invite_cookie(self, response: Response, value: str) -> None:
        # Lax: the Shopee redirect back to /callback is a cross-site top-level GET.
        response.set_cookie(self.invite_cookie, value, max_age=INVITE_COOKIE_TTL, path="/",
                            secure=self.secure_cookies, httponly=True, samesite="lax")

    def _invite_landing(self, request: Request, record: dict, cookie: str, *, error: str | None = None,
                        status: int = 200) -> Response:
        notice = f'<p class="err" role="alert">{html.escape(error)}</p>' if error else ""
        env_note = " (sandbox test environment)" if record["env"] == "sandbox" else ""
        token = self._form_token("invite", self._invite_binding(record["id"], cookie))
        body = f"""{notice}<p>You were invited to connect your Shopee shop(s){env_note} to a reporting server.
You will be sent to Shopee to sign in and approve <strong>read-only</strong> access for this server's app.
Nothing is changed in your shop.</p>
<ul><li>Use a <strong>main account</strong> to approve several shops at once: on the Shopee login page choose
<em>Switch to Sub Account</em> and sign in with the main account, then select the shops.</li>
<li>Or sign in with a <strong>shop account</strong> to approve that one shop.</li>
<li>A sub account cannot approve access.</li></ul>
<form method="post" action="{html.escape(request.url.path)}" autocomplete="off">
<input type="hidden" name="csrf_token" value="{html.escape(token)}">
<p><button type="submit">Continue to Shopee</button></p></form>
<p>After approving you are sent back here. Complete it within 15 minutes, in this browser.</p>"""
        response = _html_page("Connect your Shopee shop", body, status=status)
        self._set_invite_cookie(response, cookie)
        return response

    async def invite(self, request: Request) -> Response:
        from .shop_admin import ShopAdminError
        if self.shop_manager is None:
            return self._invite_gone()
        key = self.client_ip(request.scope)
        wait = self.invite_throttle.retry_after(key)
        if wait:
            return _html_page("Too many requests", "<p>Please try again later.</p>", status=429,
                              headers={"Retry-After": str(wait)})
        self.invite_throttle.failure(key)
        try:
            record = await anyio.to_thread.run_sync(self.shop_manager.invites.find_active,
                                                    request.path_params.get("token"))
        except ShopAdminError:
            logger.error("invites file unavailable")
            return _html_page("Temporarily unavailable", "<p>Please try again in a moment.</p>", status=503)
        if record is None or record["env"] not in self.shop_manager.available_environments():
            return self._invite_gone()
        cookie = request.cookies.get(self.invite_cookie)
        valid_cookie = bool(cookie) and len(cookie) <= 100
        if request.method == "GET":
            return self._invite_landing(request, record, cookie if valid_cookie else secrets.token_urlsafe(32))
        try:
            form = _single_values(parse_qsl((await request.body()).decode("utf-8"), keep_blank_values=True))
        except (OAuthError, UnicodeDecodeError):
            return _html_page("Bad request", "<p>Malformed form.</p>", status=400)
        expired = "This page expired or was already submitted. Please press the button again."
        if not valid_cookie or not self._form_consume(form.get("csrf_token"), "invite",
                                                      self._invite_binding(record["id"], cookie)):
            return self._invite_landing(request, record, cookie if valid_cookie else secrets.token_urlsafe(32),
                                        error=expired, status=403)
        try:
            url = self.shop_manager.start_invite(record["id"], record["env"], hash_secret(cookie))
        except ShopAdminError as error:
            return self._invite_landing(request, record, cookie, error=str(error), status=error.status)
        logger.info("invite authorization started")
        response = RedirectResponse(url, status_code=303, headers=_NO_STORE)
        self._set_invite_cookie(response, cookie)
        return response

    async def _invite_callback(self, request: Request, pending, state: str) -> Response:
        from .shop_admin import ShopAdminError
        retry = "<p>Open the invite link again to retry.</p>"
        cookie = request.cookies.get(self.invite_cookie)
        if not cookie or len(cookie) > 100 or not hmac.compare_digest(hash_secret(cookie), pending.session):
            logger.warning("invite callback rejected: different browser")
            return _html_page("Authorization failed", "<p class=\"err\">This approval was not started from this "
                              "browser (or the page expired). Nothing was saved.</p>" + retry, status=403)
        try:
            record = await anyio.to_thread.run_sync(self.shop_manager.invites.get, pending.invite)
        except ShopAdminError:
            record = None
        if record is None or record["status"] in ("used", "revoked"):
            return self._invite_gone(status=410)
        codes, shop_ids = request.query_params.getlist("code"), request.query_params.getlist("shop_id")
        accounts = request.query_params.getlist("main_account_id")
        if len(codes) != 1 or not codes[0] or len(shop_ids) + len(accounts) != 1 or not (shop_ids or accounts)[0]:
            return _html_page("Authorization failed", "<p class=\"err\">Shopee did not return a shop or main "
                              "account approval.</p>" + retry, status=400)
        async with self._shops_lock:
            try:
                result = await anyio.to_thread.run_sync(functools.partial(
                    self.shop_manager.complete_invite, pending, codes[0], state,
                    shop_id=shop_ids[0] if shop_ids else None, main_account_id=accounts[0] if accounts else None))
            except ShopAdminError as error:
                logger.warning("invite authorization failed (details suppressed)")
                return _html_page("Authorization failed", f'<p class="err">{html.escape(str(error))}</p>' + retry
                                  + self._dashboard_back(record, failed=True), status=error.status)
            if result.added:
                try:
                    try:
                        shops = await anyio.to_thread.run_sync(self.shop_manager.read_config)
                    except Exception:
                        raise ShopAdminError("The server cannot accept shops right now.", status=500) from None
                    if set(result.added) & set(shops):
                        raise ShopAdminError("Please try again.", status=409)
                    await self._apply_shops({**shops, **result.added})
                except BaseException as error:
                    for path in result.added.values():
                        await anyio.to_thread.run_sync(self.shop_manager.delete_env_file, path)
                    if isinstance(error, ShopAdminError):
                        return _html_page("Authorization failed", "<p class=\"err\">The shops could not be saved. "
                                          "Nothing was changed.</p>" + retry + self._dashboard_back(record, failed=True),
                                          status=error.status)
                    raise
                try:
                    await anyio.to_thread.run_sync(self.shop_manager.invites.mark_used, pending.invite,
                                                   sorted(result.added), dict(result.names))
                except ShopAdminError:
                    logger.error("invite could not be marked as used; revoke it in the admin page")
        logger.info("invite onboarding: %d shop(s) added, %d already connected, %d failed",
                    len(result.added), result.already_connected, result.failed)
        parts = []
        if result.added:
            names = []
            for alias in sorted(result.added):
                name = result.names.get(alias)
                names.append(f"<li>{html.escape(name)}</li>" if name else f"<li><code>{html.escape(alias)}</code></li>")
            parts.append(f"<p>{len(result.added)} shop(s) connected. Thank you, you can close this page.</p>"
                         f"<ul>{''.join(names)}</ul>")
        if result.already_connected:
            parts.append(f"<p>{result.already_connected} shop(s) were already connected.</p>")
        if result.failed:
            parts.append(f'<p class="err">{result.failed} shop(s) could not be connected.'
                         + (" Ask the person who invited you for a new link.</p>" if result.added else
                            " Open the invite link again to retry.</p>"))
        if not parts:
            parts.append("<p>No shops were returned by Shopee.</p>" + retry)
        nothing_new = bool(result.already_connected) and not result.failed
        title = "Shops connected" if result.added else ("Nothing new to connect" if nothing_new
                                                        else "Authorization failed")
        status = 200 if result.added or nothing_new else 502
        parts.append(self._dashboard_back(record, failed=status != 200, added=len(result.added),
                                          not_added=result.failed))
        return _html_page(title, "".join(parts), status=status)

    def _dashboard_back(self, record: dict | None, *, failed: bool, added: int = 0, not_added: int = 0) -> str:
        """Link back to the dashboard, only for invites created with ``return_to_dashboard``."""
        if not self.dashboard_url or not record or record.get("return_to_dashboard") is not True:
            return ""
        query = ({"shopee": "failed"} if failed else
                 {"shopee": "connected", "added": str(added), "failed": str(not_added)})
        url = self.dashboard_url + "?" + urlencode(query)
        return (f'<p class="dashboard-back"><a class="button-link" href="{html.escape(url)}">Back to dashboard</a></p>')

    async def _rename_shop(self, old: str, new: str) -> None:
        from .shop_admin import ShopAdminError
        shops = await anyio.to_thread.run_sync(self.shop_manager.renamed_config, old, new)
        await self._apply_shops(shops)
        try:
            await anyio.to_thread.run_sync(self.shop_manager.invites.rename_alias, old, new)
        except ShopAdminError:
            logger.warning("invite records could not be updated after a rename")

    # ------------------------------------------------------ admin: shops

    async def _add_shop(self, pending, code: str, shop_id: str, state: str) -> None:
        from .shop_admin import ShopAdminError
        path = await anyio.to_thread.run_sync(functools.partial(self.shop_manager.complete, pending, code, shop_id, state))
        try:
            try:
                shops = await anyio.to_thread.run_sync(self.shop_manager.read_config)
            except Exception:
                raise ShopAdminError("The shops file is invalid; nothing was changed.", status=500) from None
            if pending.alias in shops:
                raise ShopAdminError("That alias was added meanwhile; nothing was changed.", status=409)
            await self._apply_shops({**shops, pending.alias: path})
        except BaseException:
            await anyio.to_thread.run_sync(self.shop_manager.delete_env_file, path)
            raise

    async def _remove_shop(self, alias: str) -> None:
        from .shop_admin import ShopAdminError
        try:
            shops = await anyio.to_thread.run_sync(self.shop_manager.read_config)
        except Exception:
            raise ShopAdminError("The shops file is invalid; nothing was changed.", status=500) from None
        if alias not in shops:
            raise ShopAdminError("Unknown shop alias.", status=404)
        path = shops.pop(alias)
        await self._apply_shops(shops)
        await anyio.to_thread.run_sync(self.shop_manager.delete_env_file, path)

    async def _apply_shops(self, shops: dict) -> None:
        """Build the new service first (validates every shop), then persist, then swap."""
        from .credentials import CredentialError
        from .shop_admin import ShopAdminError
        if self.service_factory is None:
            raise ShopAdminError("Shop changes are not supported by this server configuration.", status=500)
        try:
            service, registry = await anyio.to_thread.run_sync(self.service_factory, shops)
        except CredentialError:
            raise ShopAdminError("The shop credentials were rejected; this shop may already be connected under "
                                 "another alias. Nothing was changed.", status=409) from None
        try:
            await anyio.to_thread.run_sync(self.shop_manager.write_config, shops)
        except BaseException:
            if registry is not None:
                with contextlib.suppress(Exception):
                    await registry.close()
            raise
        old, self.service, self.registry = self.registry, service, registry
        now = self.clock()
        if old is not None:
            self._retired.append((now, old))
        keep = []
        for retired_at, retired in self._retired:
            if now - retired_at >= RETIRED_REGISTRY_GRACE:
                with contextlib.suppress(Exception):
                    await retired.close()
            else:
                keep.append((retired_at, retired))
        self._retired = keep
        logger.info("shop configuration reloaded (%d shops)", len(shops))

    def _main_account_page(self, session: str, grant, *, error: str | None = None,
                           entered: dict | None = None, status: int = 200) -> Response:
        """Shop picker after a main-account authorization. Shows ids and names only, never tokens."""
        suggested = self.shop_manager.suggest_aliases(grant)
        rows = []
        for shop_id in grant.shop_ids:
            name = grant.names.get(shop_id) or ""
            if entered is not None:
                checked = " checked" if shop_id in entered else ""
                alias = entered.get(shop_id, suggested[shop_id])
            else:
                checked, alias = " checked", suggested[shop_id]
            rows.append(f'<tr><td><input type="checkbox" name="select-{shop_id}" id="select-{shop_id}"{checked}></td>'
                        f'<td><label for="select-{shop_id}">{shop_id}</label></td><td>{html.escape(name)}</td>'
                        f'<td><input name="alias-{shop_id}" value="{html.escape(alias)}" maxlength="32" '
                        f'pattern="[a-z0-9][a-z0-9_\\-]{{0,31}}" aria-label="Alias for shop {shop_id}"></td></tr>')
        notice = f'<p class="err" role="alert">{html.escape(error)}</p>' if error else ""
        body = f"""{notice}<p>The main account authorized {len(grant.shop_ids)} shop(s) ({html.escape(grant.env)}).
Choose the shops to add and an alias for each. Unselected shops are not stored.</p>
<form method="post" action="{ADMIN_PATH}" autocomplete="off">
<input type="hidden" name="action" value="add-main">
<input type="hidden" name="grant" value="{html.escape(grant.grant_id)}">
<input type="hidden" name="csrf_token" value="{html.escape(self._form_token('add-main', session))}">
<table><thead><tr><th>Add</th><th>Shop ID</th><th>Name</th><th>Alias</th></tr></thead><tbody>{''.join(rows)}</tbody></table>
<p><button type="submit">Add selected shops</button></p></form>
<p>This selection expires in 15 minutes. <a href="{ADMIN_PATH}">Cancel</a></p>"""
        return _html_page("Choose shops", body, status=status)

    async def _add_main_account(self, request: Request, session: str, form: dict) -> Response:
        from .shop_admin import ShopAdminError
        grant = self.shop_manager.peek_grant(form.get("grant"), session)
        if grant is None:
            return await self._admin_dashboard(request, session, status=400, error=(
                "This shop selection expired or was already used. Start Add shop again."))
        selection = {shop_id: form.get(f"alias-{shop_id}", "").strip()
                     for shop_id in grant.shop_ids if form.get(f"select-{shop_id}") == "on"}
        async with self._shops_lock:
            try:
                await anyio.to_thread.run_sync(self.shop_manager.validate_selection, grant, selection)
            except ShopAdminError as error:
                return self._main_account_page(session, grant, error=str(error), entered=selection,
                                               status=error.status)
            added, failed = await anyio.to_thread.run_sync(self.shop_manager.add_main_account_shops, grant, selection)
            if added:
                try:
                    try:
                        shops = await anyio.to_thread.run_sync(self.shop_manager.read_config)
                    except Exception:
                        raise ShopAdminError("The shops file is invalid; nothing was changed.", status=500) from None
                    if set(added) & set(shops):
                        raise ShopAdminError("An alias was added meanwhile; nothing was changed.", status=409)
                    await self._apply_shops({**shops, **added})
                except ShopAdminError as error:
                    for path in added.values():
                        await anyio.to_thread.run_sync(self.shop_manager.delete_env_file, path)
                    return await self._admin_dashboard(request, session, error=str(error), status=error.status)
                except BaseException:
                    for path in added.values():
                        await anyio.to_thread.run_sync(self.shop_manager.delete_env_file, path)
                    raise
        logger.info("main account onboarding: %d shop(s) added, %d failed", len(added), len(failed))
        parts = []
        if added:
            parts.append("<p>Connected and available to MCP clients now: " + ", ".join(
                f"<strong>{html.escape(alias)}</strong>" for alias in sorted(added)) + ".</p>")
        if failed:
            parts.append('<p class="err">Shopee did not issue a token for shop(s) ' + ", ".join(
                str(shop_id) for shop_id in failed) + ". Authorize them again with Add shop.</p>")
        return _html_page("Shops connected" if added else "Shop authorization failed",
                          "".join(parts) + f'<p><a href="{ADMIN_PATH}">Back to shops</a></p>',
                          status=200 if added else 502)

    def _admin_session(self, request: Request) -> str | None:
        value = request.cookies.get(self.admin_cookie)
        if not value or len(value) > 100:
            return None
        key = hash_secret(value)
        expiry = self._admin_sessions.get(key)
        if expiry is None or expiry <= self.clock():
            self._admin_sessions.pop(key, None)
            return None
        return key

    def _form_mac(self, purpose: str, binding: str, issued: int, nonce: str) -> str:
        bound = json.dumps([purpose, binding, issued, nonce], separators=(",", ":"))
        return hmac.new(self.store.server_secret(), b"admin\x00" + bound.encode(), hashlib.sha256).hexdigest()

    def _form_token(self, purpose: str, binding: str) -> str:
        issued, nonce = int(self.clock()), secrets.token_urlsafe(12)
        return f"{issued}.{nonce}.{self._form_mac(purpose, binding, issued, nonce)}"

    def _form_consume(self, token: str | None, purpose: str, binding: str | None) -> bool:
        if not token or not binding or len(token) > 200 or len(binding) > 100:
            return False
        issued_text, _, rest = token.partition(".")
        nonce, _, mac = rest.partition(".")
        if not issued_text.isdigit() or not nonce or not mac:
            return False
        issued, now = int(issued_text), self.clock()
        if not 0 <= now - issued <= CSRF_TTL:
            return False
        if not hmac.compare_digest(mac, self._form_mac(purpose, binding, issued, nonce)):
            return False
        return self._use_nonce(nonce, issued + CSRF_TTL, now)

    async def _verify_operator(self, request: Request, passphrase: str) -> tuple[int, str] | None:
        """Same throttle, concurrency cap and verification as the OAuth consent form."""
        key = self.client_ip(request.scope)
        wait = self.passphrase_throttle.retry_after(key)
        if wait:
            return 429, f"Too many failed attempts. Try again in about {max(1, math.ceil(wait / 60))} minute(s)."
        borrower = object()
        try:
            PASSPHRASE_LIMITER.acquire_on_behalf_of_nowait(borrower)
        except anyio.WouldBlock:
            return 429, "The server is busy verifying another attempt. Try again shortly."
        try:
            stamp = self.passphrase_throttle.failure(key)
            valid = await self._db(self.store.verify_admin_passphrase, passphrase)
        finally:
            PASSPHRASE_LIMITER.release_on_behalf_of(borrower)
        if not valid:
            logger.warning("rejected admin passphrase")
            return 403, "Incorrect passphrase."
        self.passphrase_throttle.success(key, stamp)
        return None

    async def _admin_login_page(self, request: Request, *, error: str | None = None, status: int = 200) -> Response:
        cookie = request.cookies.get(self.csrf_cookie)
        if not cookie or len(cookie) > 100:
            cookie = secrets.token_urlsafe(24)
        notice = f'<p class="err" role="alert">{html.escape(error)}</p>' if error else ""
        configured = "" if await self._db(self.store.has_admin_passphrase) else (
            '<p class="err">No admin passphrase is configured on the server; run '
            '<code>shopee-mcp-http admin set-passphrase</code> (or set SHOPEE_MCP_ADMIN_PASSPHRASE in a container) first.</p>')
        body = f"""{configured}{notice}<form method="post" action="{ADMIN_PATH}" autocomplete="off">
<input type="hidden" name="action" value="login">
<input type="hidden" name="csrf_token" value="{html.escape(self._form_token('login', cookie))}">
<p><label for="passphrase">Operator passphrase</label><br>
<input id="passphrase" name="passphrase" type="password" autocomplete="current-password" required autofocus></p>
<p><button type="submit">Sign in</button></p></form>"""
        response = _html_page("Shop administration", body, status=status, layout="login")
        response.set_cookie(self.csrf_cookie, cookie, max_age=CSRF_TTL * 2, path="/", secure=self.secure_cookies,
                            httponly=True, samesite="strict")
        return response

    async def _admin_dashboard(self, request: Request, session: str, *, error: str | None = None,
                               status: int = 200, invite_url: str | None = None) -> Response:
        from .shop_admin import AUTHORIZATION_DAYS, DEFAULT_AUTHORIZATION_DAYS, ShopAdminError
        messages = {"removed": "Shop removed.", "signed-in": "Signed in.", "renamed": "Shop renamed.",
                    "invite-revoked": "Invite link revoked."}
        flash = messages.get(request.query_params.get("msg", ""))
        notice = f'<p class="err" role="alert">{html.escape(error)}</p>' if error else ""
        if flash and not error:
            notice = f'<p class="notice" role="status">{html.escape(flash)}</p>'
        try:
            rows = await anyio.to_thread.run_sync(self.shop_manager.describe)
        except Exception:
            rows = None
        try:
            invites = await anyio.to_thread.run_sync(self.shop_manager.invites.list_invites)
        except ShopAdminError:
            invites = None
        sources: dict[str, str] = {}
        for record in reversed(invites or []):
            for alias in record["shops"]:
                sources[alias] = record["label"] or "(invite)"
        if rows is None:
            table = '<p class="err">The shops file could not be read.</p>'
        elif not rows:
            table = '<p class="empty">No shops connected yet. Create an invite below to get started.</p>'
        else:
            lines = []
            for row in rows:
                expires = _format_time(row["expires_at"]) or "-"
                remove = (f'<form method="post" action="{ADMIN_PATH}" style="margin:0">'
                          f'<input type="hidden" name="action" value="remove">'
                          f'<input type="hidden" name="alias" value="{html.escape(row["alias"])}">'
                          f'<input type="hidden" name="csrf_token" value="{html.escape(self._form_token("remove", session))}">'
                          f'<button type="submit" class="button-danger">Remove</button></form>')
                rename = (f'<form method="post" action="{ADMIN_PATH}" class="inline-form">'
                          f'<input type="hidden" name="action" value="rename">'
                          f'<input type="hidden" name="alias" value="{html.escape(row["alias"])}">'
                          f'<input type="hidden" name="csrf_token" value="{html.escape(self._form_token("rename", session))}">'
                          f'<input name="new_alias" required maxlength="32" size="12" pattern="[a-z0-9][a-z0-9_\\-]{{0,31}}" '
                          f'aria-label="New alias for {html.escape(row["alias"])}" placeholder="New alias"> <button type="submit" class="button-secondary">Rename</button></form>')
                source = sources.get(row["alias"], "")
                lines.append(f"<tr><td><code>{html.escape(row['alias'])}</code></td><td>{_ui_badge(row['env'])}</td>"
                             f'<td class="date">{html.escape(expires)}</td><td>{_ui_badge(row["status"])}</td>'
                             f"<td>{html.escape(source)}</td><td>{rename}</td><td>{remove}</td></tr>")
            table = ('<div class="table-scroll" role="region" aria-label="Connected shops table" tabindex="0"><table><thead><tr><th>Alias</th><th>Env</th><th>Authorization expires (UTC)</th><th>Status</th>'
                     "<th>Invite</th><th>Rename alias</th><th></th></tr></thead><tbody>" + "".join(lines) + "</tbody></table></div>")
        environments = self.shop_manager.available_environments()
        if environments:
            env_options = "".join(f'<option value="{env}">{env}</option>' for env in environments)
            day_options = "".join(f'<option value="{days}"{" selected" if days == DEFAULT_AUTHORIZATION_DAYS else ""}>'
                                  f"{days} days</option>" for days in AUTHORIZATION_DAYS)
            add = f"""<h2>Add shop</h2><p class="help">Connect a shop yourself when the owner is with you.</p><form method="post" action="{ADMIN_PATH}" class="form-grid" autocomplete="off">
<input type="hidden" name="action" value="add">
<input type="hidden" name="csrf_token" value="{html.escape(self._form_token('add', session))}">
<p><label for="alias">Alias</label><br><input id="alias" name="alias" required maxlength="32"
 pattern="[a-z0-9][a-z0-9_\\-]{{0,31}}" placeholder="store-a"></p>
<p><label for="env">Environment</label><br><select id="env" name="env">{env_options}</select></p>
<p><label for="days">Authorization period</label><br><select id="days" name="days">{day_options}</select></p>
<p class="form-submit"><button type="submit">Continue to Shopee</button></p></form>
<p class="help">You will sign in to Shopee as the seller and approve this app. With a main account you can approve
several shops at once; the alias then becomes the default prefix and you pick shops and aliases next.
Shopee then redirects back to
<code>{html.escape(self.shop_manager.redirect_url or "")}</code>.</p>"""
        elif self.shop_manager.redirect_url is None:
            add = '<p class="err">Adding shops needs an https public URL.</p>'
        else:
            add = ('<p class="err">Adding shops needs partner credentials in the server environment '
                   '(SHOPEE_PARTNER_ID and SHOPEE_PARTNER_KEY, optionally SHOPEE_SANDBOX_PARTNER_ID and '
                   'SHOPEE_SANDBOX_PARTNER_KEY).</p>')
        invite_section = self._invites_section(session, environments, invites, invite_url)
        logout = (f'<form method="post" action="{ADMIN_PATH}"><input type="hidden" name="action" value="logout">'
                  f'<input type="hidden" name="csrf_token" value="{html.escape(self._form_token("logout", session))}">'
                  f'<button type="submit" class="button-secondary">Sign out</button></form>')
        connected = len(rows or [])
        live = sum(row["env"] in ("production", "live") for row in (rows or []))
        active = sum(record["status"] == "active" for record in (invites or []))
        stats = (f'<section class="stats" aria-label="Overview">'
                 f'<div class="stat"><p class="stat-label">Connected shops</p><strong class="stat-value">{connected}</strong>'
                 '<span class="stat-note">All environments</span></div>'
                 f'<div class="stat"><p class="stat-label">Live shops</p><strong class="stat-value">{live}</strong>'
                 '<span class="stat-note">Production access</span></div>'
                 f'<div class="stat"><p class="stat-label">Active invites</p><strong class="stat-value">{active}</strong>'
                 '<span class="stat-note">Ready to share</span></div></section>')
        shops_card = ('<section class="card"><div class="card-heading"><h2>Connected shops</h2>'
                      '<p>Manage aliases and check authorization status.</p></div>' + table + '</section>')
        add_card = '<details class="card section-details"><summary>Add shop directly</summary>' + add + '</details>'
        body = f"{notice}{stats}{shops_card}{invite_section}{add_card}"
        return _html_page("Shop administration", body, status=status, layout="dashboard", header_actions=logout)

    def _invites_section(self, session: str, environments: list[str], invites: list | None,
                         invite_url: str | None) -> str:
        from .shop_admin import DEFAULT_INVITE_TTL, INVITE_TTLS
        parts = ['<section class="card card-accent"><div class="card-heading"><h2>Invite links</h2><p>Let the shop owner connect securely, without your admin passphrase.</p></div>']
        if invite_url:
            parts.append('<div class="invite-url" role="status"><p><strong>New invite link</strong> (shown only once; copy it '
                         'now and send it to the shop owner):</p>'
                         f'<p><code id="invite-url">{html.escape(invite_url)}</code></p></div>')
        if environments:
            ordered = [env for env in ("production", "sandbox") if env in environments]
            env_options = "".join(f'<option value="{env}">{"live" if env == "production" else env}</option>'
                                  for env in ordered)
            ttl_options = "".join(f'<option value="{key}"{" selected" if key == DEFAULT_INVITE_TTL else ""}>{key}</option>'
                                  for key in INVITE_TTLS)
            parts.append(f"""<form method="post" action="{ADMIN_PATH}" class="form-grid" autocomplete="off">
<input type="hidden" name="action" value="invite-create">
<input type="hidden" name="csrf_token" value="{html.escape(self._form_token('invite-create', session))}">
<p><label for="invite-label">Label (optional)</label><br><input id="invite-label" name="label" maxlength="40"
 placeholder="owner of store-a"></p>
<p><label for="invite-env">Environment</label><br><select id="invite-env" name="env">{env_options}</select></p>
<p><label for="invite-ttl">Expires after</label><br><select id="invite-ttl" name="ttl">{ttl_options}</select></p>
<p class="form-submit"><button type="submit">Create invite link</button></p></form>
<p class="help">Send the link to a seller who holds a main account or a shop account. They approve on Shopee without the
admin passphrase; their shops are added with automatic aliases you can rename above. Each link works once.</p>""")
        if invites is None:
            parts.append('<p class="err">The invites file could not be read.</p>')
        elif invites:
            lines = []
            for record in invites:
                action = ""
                if record["status"] == "active":
                    action = (f'<form method="post" action="{ADMIN_PATH}" style="margin:0">'
                              f'<input type="hidden" name="action" value="invite-revoke">'
                              f'<input type="hidden" name="invite" value="{html.escape(record["id"])}">'
                              f'<input type="hidden" name="csrf_token" value="{html.escape(self._form_token("invite-revoke", session))}">'
                              f'<button type="submit" class="button-danger">Revoke</button></form>')
                env = "live" if record["env"] == "production" else record["env"]
                lines.append(f"<tr><td>{html.escape(record['label'] or '-')}</td><td>{_ui_badge(env)}</td>"
                             f'<td class="date">{html.escape(_format_time(record["created_at"]) or "-")}</td>'
                             f'<td class="date">{html.escape(_format_time(record["expires_at"]) or "-")}</td>'
                             f"<td>{_ui_badge(record['status'])}</td>"
                             f"<td>{html.escape(', '.join(record['shops']))}</td><td>{action}</td></tr>")
            parts.append('<div class="table-scroll invites-history" role="region" aria-label="Invite history table" tabindex="0"><table><thead><tr><th>Label</th><th>Env</th><th>Created (UTC)</th><th>Expires (UTC)</th>'
                         "<th>Status</th><th>Shops</th><th></th></tr></thead><tbody>" + "".join(lines) + "</tbody></table></div>")
        parts.append("</section>")
        return "".join(parts)

    async def admin_shops(self, request: Request) -> Response:
        if self.shop_manager is None:
            return _html_page("Not available", "<p>Shop administration is disabled on this server.</p>", status=404)
        try:
            return await self._admin_shops(request)
        except sqlite3.Error:
            logger.error("auth store unavailable during shop administration")
            return _html_page("Temporarily unavailable", "<p>Please try again in a moment.</p>", status=503)

    async def _admin_shops(self, request: Request) -> Response:
        from .shop_admin import ShopAdminError
        session = self._admin_session(request)
        if request.method == "GET":
            if session is None:
                return await self._admin_login_page(request)
            return await self._admin_dashboard(request, session)
        try:
            form = _single_values(parse_qsl((await request.body()).decode("utf-8"), keep_blank_values=True))
        except (OAuthError, UnicodeDecodeError):
            return _html_page("Bad request", "<p>Malformed form.</p>", status=400)
        action = form.get("action")
        expired = "This form expired, was already submitted, or was not submitted from this page. Please try again."
        if action == "login":
            if not self._form_consume(form.get("csrf_token"), "login", request.cookies.get(self.csrf_cookie)):
                return await self._admin_login_page(request, error=expired, status=403)
            failure = await self._verify_operator(request, form.get("passphrase", ""))
            if failure is not None:
                return await self._admin_login_page(request, error=failure[1], status=failure[0])
            value = secrets.token_urlsafe(32)
            now = self.clock()
            for stale in [key for key, expiry in self._admin_sessions.items() if expiry <= now]:
                del self._admin_sessions[stale]
            if len(self._admin_sessions) >= 100:
                self._admin_sessions.pop(next(iter(self._admin_sessions)))
            self._admin_sessions[hash_secret(value)] = now + ADMIN_SESSION_TTL
            logger.info("admin signed in")
            response = RedirectResponse(ADMIN_PATH + "?msg=signed-in", status_code=303, headers=_NO_STORE)
            # Lax (not Strict): the Shopee redirect to /callback is a cross-site top-level
            # GET and must carry the session that started the flow. Every state-changing
            # admin POST additionally requires a session-bound, single-use form token.
            response.set_cookie(self.admin_cookie, value, max_age=ADMIN_SESSION_TTL, path="/",
                                secure=self.secure_cookies, httponly=True, samesite="lax")
            return response
        if session is None:
            return await self._admin_login_page(request, error="Please sign in.", status=403)
        if action not in ("add", "add-main", "remove", "logout", "rename", "invite-create",
                          "invite-revoke") or not self._form_consume(
                form.get("csrf_token"), action, session):
            return await self._admin_dashboard(request, session, error=expired, status=403)
        if action == "logout":
            self._admin_sessions.pop(session, None)
            response = RedirectResponse(ADMIN_PATH, status_code=303, headers=_NO_STORE)
            response.delete_cookie(self.admin_cookie, path="/", secure=self.secure_cookies, httponly=True, samesite="lax")
            return response
        if action == "add-main":
            return await self._add_main_account(request, session, form)
        try:
            if action == "invite-create":
                env = form.get("env", "")
                if env not in self.shop_manager.available_environments():
                    raise ShopAdminError("That environment is not configured on the server.")
                token, _record = await anyio.to_thread.run_sync(self.shop_manager.invites.create, env,
                                                                form.get("ttl", ""), form.get("label", ""))
                logger.info("invite link created")
                return await self._admin_dashboard(request, session,
                                                   invite_url=self.issuer + INVITE_PATH_PREFIX + token)
            if action == "invite-revoke":
                if not await anyio.to_thread.run_sync(self.shop_manager.invites.revoke, form.get("invite")):
                    raise ShopAdminError("That invite link is not active.", status=404)
                logger.info("invite link revoked")
                return RedirectResponse(ADMIN_PATH + "?msg=invite-revoked", status_code=303, headers=_NO_STORE)
            if action == "rename":
                async with self._shops_lock:
                    await self._rename_shop(form.get("alias", ""), form.get("new_alias", "").strip())
                logger.info("shop renamed through admin page")
                return RedirectResponse(ADMIN_PATH + "?msg=renamed", status_code=303, headers=_NO_STORE)
            if action == "add":
                days_text = form.get("days", "365")
                days = int(days_text) if days_text.isascii() and days_text.isdecimal() and len(days_text) < 5 else 0
                url = self.shop_manager.start(form.get("alias", ""), form.get("env", ""), session, days)
                logger.info("shop authorization started")
                return RedirectResponse(url, status_code=303, headers=_NO_STORE)
            async with self._shops_lock:
                await self._remove_shop(form.get("alias", ""))
            logger.info("shop removed through admin page")
            return RedirectResponse(ADMIN_PATH + "?msg=removed", status_code=303, headers=_NO_STORE)
        except ShopAdminError as error:
            return await self._admin_dashboard(request, session, error=str(error), status=error.status)

    # ------------------------------------------------------ dashboard API

    def _dashboard_json(self, body: dict, status: int = 200, headers: dict | None = None) -> Response:
        return JSONResponse(body, status_code=status, headers={**_NO_STORE, **(headers or {})})

    def _dashboard_guard(self, request: Request) -> Response | None:
        """``None`` when the request carries the dashboard token; otherwise the error response.

        Only ``SHOPEE_MCP_DASHBOARD_TOKEN`` is accepted: MCP OAuth and static
        tokens live in the auth store and are never consulted here.
        """
        if self._dashboard_token_hash is None:
            return self._dashboard_json({"error": "not_found"}, 404)
        key = self.client_ip(request.scope)
        wait = self.dashboard_throttle.retry_after(key)
        if wait:
            return self._dashboard_json({"error": "too_many_requests"}, 429, {"Retry-After": str(wait)})
        stamp = self.dashboard_throttle.failure(key)
        scheme, _, presented = (request.headers.get("authorization") or "").partition(" ")
        presented = presented.strip()
        if (scheme.lower() != "bearer" or not presented or len(presented) > 512
                or not hmac.compare_digest(hash_secret(presented), self._dashboard_token_hash)):
            logger.warning("dashboard API request rejected: invalid token")
            return self._dashboard_json({"error": "unauthorized"}, 401)
        self.dashboard_throttle.success(key, stamp)
        if self.shop_manager is None:
            return self._dashboard_json({"error": "shop administration is disabled on this server"}, 503)
        return None

    def _dashboard_envs(self) -> list[str]:
        available = self.shop_manager.available_environments()
        return [_DASHBOARD_ENV_NAMES[env] for env in ("production", "sandbox") if env in available]

    async def dashboard_shops(self, request: Request) -> Response:
        from .credentials import CredentialError
        from .shop_admin import ShopAdminError
        denied = self._dashboard_guard(request)
        if denied is not None:
            return denied
        try:
            rows = await anyio.to_thread.run_sync(self.shop_manager.describe_detailed)
        except (CredentialError, ShopAdminError, OSError):
            return self._dashboard_json({"error": "The shops file could not be read."}, 500)
        try:
            invites = await anyio.to_thread.run_sync(self.shop_manager.invites.list_invites)
        except ShopAdminError:
            return self._dashboard_json({"error": "The invites file could not be read."}, 500)
        sources: dict[str, str] = {}
        names: dict[str, str | None] = {}
        for record in reversed(invites):   # oldest first, so the newest invite wins
            for alias in record["shops"]:
                sources[alias] = record["label"] or None
                if alias in record["names"]:
                    names[alias] = record["names"][alias]
        shops = [{"alias": row["alias"], "env": _DASHBOARD_ENV_NAMES.get(row["env"], row["env"]),
                  "shop_id": row["shop_id"], "shop_name": names.get(row["alias"]), "status": row["status"],
                  "auth_expires_at": row["auth_expires_at"], "refresh_expires_at": row["refresh_expires_at"],
                  "source": sources.get(row["alias"])} for row in rows]
        listed = [{"id": record["id"], "label": record["label"],
                   "env": _DASHBOARD_ENV_NAMES.get(record["env"], record["env"]), "status": record["status"],
                   "created_at": record["created_at"], "expires_at": record["expires_at"],
                   "aliases": list(record["shops"])} for record in invites]
        return self._dashboard_json({"shops": shops, "invites": listed, "environments": self._dashboard_envs()})

    async def dashboard_create_invite(self, request: Request) -> Response:
        from .shop_admin import DEFAULT_INVITE_TTL, ShopAdminError
        denied = self._dashboard_guard(request)
        if denied is not None:
            return denied
        try:
            body = json.loads((await request.body()) or b"{}")
        except (ValueError, UnicodeDecodeError):
            return self._dashboard_json({"error": "The request body must be a JSON object."}, 400)
        if not isinstance(body, dict):
            return self._dashboard_json({"error": "The request body must be a JSON object."}, 400)
        label, ttl = body.get("label"), body.get("ttl", DEFAULT_INVITE_TTL)
        env, back = body.get("env"), body.get("return_to_dashboard", False)
        if label is not None and not isinstance(label, str):
            return self._dashboard_json({"error": "label must be a string."}, 400)
        if not isinstance(ttl, str) or ttl not in _DASHBOARD_TTLS:
            return self._dashboard_json({"error": "ttl must be one of 1h, 24h, 3d, 7d."}, 400)
        if not isinstance(back, bool):
            return self._dashboard_json({"error": "return_to_dashboard must be a boolean."}, 400)
        if back and not self.dashboard_url:
            return self._dashboard_json({"error": "SHOPEE_MCP_DASHBOARD_URL is not configured on the server."}, 400)
        available = self.shop_manager.available_environments()
        if env is None:
            internal = next((name for name in ("production", "sandbox") if name in available), None)
            if internal is None:
                return self._dashboard_json({"error": "No Shopee environment is configured on the server."}, 400)
        elif not isinstance(env, str) or _DASHBOARD_ENV_INPUT.get(env) not in available:
            return self._dashboard_json({"error": "That environment is not configured on the server."}, 400)
        else:
            internal = _DASHBOARD_ENV_INPUT[env]
        try:
            token, record = await anyio.to_thread.run_sync(functools.partial(
                self.shop_manager.invites.create, internal, _DASHBOARD_TTLS[ttl], label,
                return_to_dashboard=back))
        except ShopAdminError as error:
            return self._dashboard_json({"error": str(error)}, error.status)
        logger.info("invite link created through the dashboard API")
        return self._dashboard_json({"id": record["id"], "url": self.issuer + INVITE_PATH_PREFIX + token,
                                     "expires_at": record["expires_at"], "env": _DASHBOARD_ENV_NAMES[internal],
                                     "label": record["label"]}, 201)

    async def dashboard_revoke_invite(self, request: Request) -> Response:
        from .shop_admin import ShopAdminError
        denied = self._dashboard_guard(request)
        if denied is not None:
            return denied
        try:
            revoked = await anyio.to_thread.run_sync(self.shop_manager.invites.revoke,
                                                     request.path_params.get("invite_id"))
        except ShopAdminError as error:
            return self._dashboard_json({"error": str(error)}, error.status)
        if not revoked:
            return self._dashboard_json({"error": "not_found"}, 404)
        logger.info("invite link revoked through the dashboard API")
        return self._dashboard_json({"ok": True})

    async def healthz(self, request: Request) -> Response:
        return JSONResponse({"status": "ok", "version": __version__}, headers={"Cache-Control": "no-store"})


def _unavailable() -> JSONResponse:
    return JSONResponse({"error": "temporarily_unavailable"}, status_code=503, headers=_NO_STORE)


def _age(seconds: float) -> str:
    seconds = max(0, int(seconds))
    for unit, size in (("day", 86400), ("hour", 3600), ("minute", 60)):
        if seconds >= size:
            count = seconds // size
            return f"{count} {unit}{'s' if count != 1 else ''} ago"
    return "just now"


class _PageError(Exception):
    """Invalid client or redirect URI: show an error page, never redirect."""


class _RedirectError(Exception):
    def __init__(self, error: OAuthError, request: dict):
        super().__init__(error.error)
        self.error, self.request = error, request


def create_app(service: Any, store: AuthStore, public_url: str, **kwargs) -> ShopeeHTTPApp:
    return ShopeeHTTPApp(service, store, public_url, **kwargs)


# ---------------------------------------------------------------------- CLI

def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="shopee-mcp-http", description="Remote HTTP mode for the read-only multi-shop Shopee MCP server")
    commands = result.add_subparsers(dest="command", required=True)

    serve = commands.add_parser("serve", help="Serve MCP over Streamable HTTP (127.0.0.1 unless --host is given)")
    serve.add_argument("--shops-file", type=Path, required=True, help="Owner-only multi-shop alias config (absolute path)")
    serve.add_argument("--auth-file", type=Path, required=True, help="Owner-only SQLite auth database (absolute path; created if missing)")
    serve.add_argument("--public-url", required=True, help="Public base URL, e.g. https://mcp.example.com")
    serve.add_argument("--host", default="127.0.0.1",
                       help="Bind address (default 127.0.0.1). A non-loopback address requires an https --public-url")
    serve.add_argument("--port", type=int, default=8091)
    serve.add_argument("--data-dir", type=Path, default=None,
                       help="Directory for shop credential files created by /admin/shops (default: the shops file's directory)")
    serve.add_argument("--disable-admin", action="store_true", help="Do not serve the /admin/shops onboarding pages")
    serve.add_argument("--client-ip-header", default=None,
                       help="Header set by your reverse proxy with the real client IP (e.g. X-Real-IP); only used for "
                            "throttling and only from loopback peers or --trusted-proxy networks")
    serve.add_argument("--trusted-proxy", action="append", default=[], metavar="CIDR",
                       help="Network of a reverse proxy allowed to set --client-ip-header (repeatable). Required for "
                            "--client-ip-header when --host is not loopback")
    serve.add_argument("--access-token-ttl", type=int, default=24 * 3600)
    serve.add_argument("--refresh-token-ttl", type=int, default=90 * 24 * 3600)
    serve.add_argument("--refresh-grace", type=int, default=120)
    serve.add_argument("--context", default="multi")
    serve.add_argument("--catalog", type=Path)
    serve.add_argument("--module", action="append")
    serve.add_argument("--endpoint", action="append")
    serve.add_argument("--artifact-dir", type=Path)
    serve.add_argument("--timeout", type=float, default=30.0)
    serve.add_argument("--concurrency", type=int, default=4)
    serve.add_argument("--max-response-bytes", type=int, default=8_000_000)
    serve.add_argument("--inline-bytes", type=int, default=24_000)
    serve.add_argument("--artifact-ttl", type=int, default=3600)
    serve.add_argument("--log-level", default="info", choices=["debug", "info", "warning", "error"])
    serve.add_argument("--allow-write", action="append", default=[], help=argparse.SUPPRESS)

    def auth_file(sub):
        sub.add_argument("--auth-file", type=Path, required=True, help="Owner-only SQLite auth database (absolute path)")
        return sub

    token = commands.add_parser("token", help="Manage static bearer tokens").add_subparsers(dest="action", required=True)
    auth_file(token.add_parser("create", help="Create a token (printed once)")).add_argument("--label", required=True)
    auth_file(token.add_parser("list", help="List tokens (no secrets)"))
    auth_file(token.add_parser("revoke", help="Revoke a token by id")).add_argument("token_id")

    admin = commands.add_parser("admin", help="Operator settings").add_subparsers(dest="action", required=True)
    set_passphrase = auth_file(admin.add_parser("set-passphrase", help="Set the operator passphrase (read from TTY or stdin)"))
    set_passphrase.add_argument("--if-unset", action="store_true", help="Do nothing when a passphrase is already set")

    oauth = commands.add_parser("oauth", help="Inspect OAuth clients").add_subparsers(dest="action", required=True)
    auth_file(oauth.add_parser("list", help="List registered OAuth clients"))
    auth_file(oauth.add_parser("revoke", help="Revoke a client and all its tokens")).add_argument("client_id")

    from .agent_connect import add_connect_parser
    add_connect_parser(commands)
    return result


def _read_passphrase() -> str:
    if sys.stdin.isatty():
        first = getpass.getpass("New admin passphrase: ")
        if getpass.getpass("Repeat passphrase: ") != first:
            raise AuthStoreError("passphrases do not match")
        return first
    line = sys.stdin.readline(2048)
    return line.rstrip("\r\n")


def _format_time(value) -> str | None:
    return None if value is None else time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(value))


def is_loopback_host(host: str) -> bool:
    if host in LOOPBACK_HOSTS:
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def _normalized_dir(path: Path, option: str) -> Path:
    raw = os.fspath(path)
    if not os.path.isabs(raw) or os.path.normpath(raw) != raw:
        raise ValueError(f"{option} must be an absolute, normalized path")
    return Path(raw)


def _build_service(args, **registry_overrides):
    """Return ``(factory, artifacts)``; ``factory(shops) -> (service, registry_or_None)``.

    The factory is used at start-up and again by /admin/shops to rebuild the
    service after a shop is added or removed. Zero shops yield a service that only
    offers ``list_connected_shops`` so a fresh deployment can start empty.
    """
    from .catalog import Catalog
    from .multi_server import EmptyShopService, MultiShopMCPService
    from .multi_shop import MultiShopRegistry
    from .policy import Policy
    from .results import ArtifactStore

    if not args.shops_file.is_absolute():
        raise AuthStoreError("--shops-file must be an absolute path")
    if not math.isfinite(args.timeout) or args.timeout <= 0 or any(
            limit <= 0 for limit in (args.concurrency, args.max_response_bytes, args.inline_bytes, args.artifact_ttl)):
        raise ValueError("Runtime limits must be positive and finite")
    catalog = Catalog(args.catalog)
    known_modules = {name.split(".", 2)[1] for name in catalog.name_map if name.count(".") >= 2}
    if set(args.module or []) - known_modules:
        raise ValueError("Unknown module in operator configuration")
    if set(args.endpoint or []) - set(catalog.name_map):
        raise ValueError("Unknown endpoint in operator configuration")
    policy = Policy(args.context, frozenset(args.module) if args.module is not None else None,
                    frozenset(args.endpoint) if args.endpoint is not None else None, frozenset())
    artifacts = ArtifactStore(args.artifact_dir or args.shops_file.parent / "local-data/shopee-mcp/artifacts", ttl=args.artifact_ttl)
    registry_kwargs = dict(timeout=args.timeout, concurrency=args.concurrency,
                           max_response_bytes=args.max_response_bytes, upload_roots=[])
    registry_kwargs.update(registry_overrides)

    def factory(shops):
        if not shops:
            return EmptyShopService(artifacts), None
        registry = MultiShopRegistry(shops, **registry_kwargs)
        return MultiShopMCPService(catalog, policy, registry, artifacts, inline_bytes=args.inline_bytes), registry

    return factory, artifacts


async def _serve(args) -> int:
    import uvicorn

    from .multi_shop import load_shop_config

    store = AuthStore(args.auth_file, create=True, access_ttl=args.access_token_ttl,
                      refresh_ttl=args.refresh_token_ttl, refresh_grace=args.refresh_grace)
    if not store.has_admin_passphrase():
        print("warning: no admin passphrase set; OAuth consent and /admin/shops will fail until "
              "'shopee-mcp-http admin set-passphrase' is run", file=sys.stderr)
    factory, artifacts = _build_service(args)
    shop_manager = None
    if not args.disable_admin:
        from .shop_admin import ShopManager, partner_credentials_from_env
        data_dir = _normalized_dir(args.data_dir or args.shops_file.parent, "--data-dir")
        shop_manager = ShopManager(args.shops_file, data_dir, normalize_public_url(args.public_url),
                                   partner_credentials_from_env())
        if not shop_manager.available_environments():
            print("note: /admin/shops can list and remove shops, but adding needs an https public URL and "
                  "SHOPEE_PARTNER_ID/SHOPEE_PARTNER_KEY in the environment", file=sys.stderr)
    service, registry = factory(load_shop_config(args.shops_file))
    dashboard_token, dashboard_url = dashboard_settings_from_env()
    if dashboard_token and shop_manager is None:
        print("note: the dashboard API is enabled but --disable-admin is set; it will answer 503", file=sys.stderr)
    app = create_app(service, store, args.public_url, client_ip_header=args.client_ip_header,
                     trusted_proxies=args.trusted_proxy, shop_manager=shop_manager, service_factory=factory,
                     registry=registry, dashboard_token=dashboard_token, dashboard_url=dashboard_url)
    try:
        config = uvicorn.Config(app, host=args.host, port=args.port, lifespan="on", access_log=False,
                                proxy_headers=False, server_header=False, log_level=args.log_level,
                                timeout_keep_alive=75, timeout_graceful_shutdown=20)
        await uvicorn.Server(config).serve()
    finally:
        await app.aclose()
        artifacts.cleanup(all_records=True)
    return 0


def validate_serve_args(args) -> None:
    if args.allow_write:
        raise ValueError("The HTTP mode is read-only; --allow-write is not allowed")
    if not 1 <= args.port <= 65535:
        raise ValueError("--port must be 1-65535")
    public = normalize_public_url(args.public_url)
    if args.client_ip_header and not all(ch.isalnum() or ch == "-" for ch in args.client_ip_header):
        raise ValueError("--client-ip-header must be a header name")
    host = args.host.strip()
    if not host or any(ch.isspace() or ch in "/@?#" for ch in host):
        raise ValueError("--host must be an IP address or host name")
    for value in args.trusted_proxy:
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError:
            raise ValueError("--trusted-proxy must be an IP network, e.g. 10.0.0.0/8") from None
    if not is_loopback_host(host):
        if not public.startswith("https://"):
            raise ValueError("a non-loopback --host requires an https --public-url")
        if args.client_ip_header and not args.trusted_proxy:
            raise ValueError("--client-ip-header on a non-loopback --host requires --trusted-proxy "
                             "(the network of the proxy that sets the header)")
    if args.data_dir is not None:
        _normalized_dir(args.data_dir, "--data-dir")


def run(args) -> int:
    if args.command == "connect":
        from .agent_connect import run_connect
        return run_connect(args)
    if args.command == "serve":
        validate_serve_args(args)
        dashboard_settings_from_env()   # fail fast on an invalid dashboard token or URL
        logging.basicConfig(level=getattr(logging, args.log_level.upper()), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
        # httpx logs full request URLs (including Shopee access tokens) at INFO.
        logging.getLogger("httpx").setLevel(logging.WARNING)
        logging.getLogger("httpcore").setLevel(logging.WARNING)
        return asyncio.run(_serve(args))

    store = AuthStore(args.auth_file, create=True)
    if args.command == "token":
        if args.action == "create":
            token_id, token = store.create_static_token(args.label)
            print(f"id: {token_id}", file=sys.stderr)
            print("Store this token now; it cannot be shown again.", file=sys.stderr)
            print(token)
        elif args.action == "list":
            rows = [{"id": row["id"], "label": row["label"], "created_at": _format_time(row["created_at"]),
                     "last_used_at": _format_time(row["last_used_at"]), "revoked_at": _format_time(row["revoked_at"])}
                    for row in store.list_static_tokens()]
            print(json.dumps(rows, indent=2))
        elif args.action == "revoke":
            if not store.revoke_static_token(args.token_id):
                print("No active token with that id", file=sys.stderr)
                return 1
            print("revoked", file=sys.stderr)
    elif args.command == "admin":
        if getattr(args, "if_unset", False) and store.has_admin_passphrase():
            print("admin passphrase already set; unchanged", file=sys.stderr)
            return 0
        store.set_admin_passphrase(_read_passphrase())
        print("admin passphrase updated", file=sys.stderr)
    elif args.command == "oauth":
        if args.action == "list":
            rows = [{**row, "created_at": _format_time(row["created_at"]), "revoked_at": _format_time(row["revoked_at"])}
                    for row in store.list_clients()]
            print(json.dumps(rows, indent=2))
        elif args.action == "revoke":
            if not store.revoke_client(args.client_id):
                print("No active client with that id", file=sys.stderr)
                return 1
            print("revoked", file=sys.stderr)
    return 0


def main() -> int:
    os.umask(0o077)
    args = parser().parse_args()
    try:
        return run(args)
    except KeyboardInterrupt:
        return 130
    except (AuthStoreError, ValueError) as error:
        print(f"shopee-mcp-http: {error}", file=sys.stderr)
        return 1
    except Exception as error:
        from .credentials import CredentialError
        if isinstance(error, CredentialError):
            print(f"shopee-mcp-http configuration error: {error}", file=sys.stderr)
        else:
            print("shopee-mcp-http stopped: startup or protocol failure (secret details suppressed)", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
