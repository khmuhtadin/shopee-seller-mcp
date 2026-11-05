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
* ``GET /callback`` - completes an "Add shop" flow when it carries a pending,
  session-bound state (``shop_id`` callbacks add the shop; ``main_account_id``
  callbacks open a shop picker); otherwise a static page for the
  ``shopee-auth`` CLI flow.
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
RETIRED_REGISTRY_GRACE = 300  # seconds an old shop registry stays open for in-flight requests
_INSTRUCTIONS = ("Read-only Shopee seller tools for operator-configured shops. Call list_connected_shops first and "
                 "pass an explicit shop alias. One Shopee API call fetches one data page; use returned cursors.")# At most two scrypt verifications at once (CPU/memory bound); extra attempts get 429 immediately.
PASSPHRASE_LIMITER = anyio.CapacityLimiter(2)
_LOGGED_PATHS = frozenset({
    "/mcp", "/mcp/", "/authorize", "/token", "/register", "/revoke", "/callback", "/healthz", ADMIN_PATH,
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


def _html_page(title: str, body: str, status: int = 200, headers: dict | None = None) -> HTMLResponse:
    page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex"><title>{html.escape(title)}</title>
<style>body{{font-family:system-ui,sans-serif;max-width:44rem;margin:3rem auto;padding:0 1rem;line-height:1.5;color:#222}}
.box{{border:1px solid #ccc;border-radius:8px;padding:1rem 1.25rem}}.err{{color:#a00}}code{{word-break:break-all}}
input[type=password]{{width:100%;padding:.5rem;font-size:1rem;box-sizing:border-box}}button{{padding:.5rem 1rem;font-size:1rem;margin-right:.5rem}}
table{{border-collapse:collapse;width:100%}}td,th{{padding:.3rem .5rem;border-bottom:1px solid #ddd;text-align:left}}
input,select{{padding:.4rem;font-size:1rem}}</style>
</head><body><h1>{html.escape(title)}</h1>{body}</body></html>"""
    merged = {**_NO_STORE, "Content-Security-Policy": _HTML_CSP, "X-Robots-Tag": "noindex"}
    merged.update(headers or {})
    return HTMLResponse(page, status_code=status, headers=merged)


# ---------------------------------------------------------------------- app

class ShopeeHTTPApp:
    """Top-level ASGI app. ``/mcp`` is authenticated before the MCP SDK sees the request."""

    def __init__(self, service: Any, store: AuthStore, public_url: str, *, client_ip_header: str | None = None,
                 clock: Callable[[], float] = time.time, register_limit_per_hour: int = 60,
                 trusted_proxies: list[str] | None = None, shop_manager: Any = None,
                 service_factory: Callable[[dict], tuple[Any, Any]] | None = None, registry: Any = None):
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
        self.client_ip_header = client_ip_header.lower() if client_ip_header else None
        self.passphrase_throttle = Throttle(per_key=5, global_limit=20, window=900, clock=clock)
        self.register_throttle = Throttle(per_key=register_limit_per_hour, global_limit=register_limit_per_hour,
                                          window=3600, clock=clock)
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
            path = scope["path"] if scope["path"] in _LOGGED_PATHS else "(other)"
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
        response = _html_page("Shop administration", body, status=status)
        response.set_cookie(self.csrf_cookie, cookie, max_age=CSRF_TTL * 2, path="/", secure=self.secure_cookies,
                            httponly=True, samesite="strict")
        return response

    async def _admin_dashboard(self, request: Request, session: str, *, error: str | None = None,
                               status: int = 200) -> Response:
        from .shop_admin import AUTHORIZATION_DAYS, DEFAULT_AUTHORIZATION_DAYS
        messages = {"removed": "Shop removed.", "signed-in": "Signed in."}
        flash = messages.get(request.query_params.get("msg", ""))
        notice = f'<p class="err" role="alert">{html.escape(error)}</p>' if error else ""
        if flash and not error:
            notice = f"<p>{html.escape(flash)}</p>"
        try:
            rows = await anyio.to_thread.run_sync(self.shop_manager.describe)
        except Exception:
            rows = None
        if rows is None:
            table = '<p class="err">The shops file could not be read.</p>'
        elif not rows:
            table = "<p>No shops connected yet.</p>"
        else:
            lines = []
            for row in rows:
                expires = _format_time(row["expires_at"]) or "-"
                remove = (f'<form method="post" action="{ADMIN_PATH}" style="margin:0">'
                          f'<input type="hidden" name="action" value="remove">'
                          f'<input type="hidden" name="alias" value="{html.escape(row["alias"])}">'
                          f'<input type="hidden" name="csrf_token" value="{html.escape(self._form_token("remove", session))}">'
                          f'<button type="submit">Remove</button></form>')
                lines.append(f"<tr><td><code>{html.escape(row['alias'])}</code></td><td>{html.escape(row['env'])}</td>"
                             f"<td>{html.escape(expires)}</td><td>{html.escape(row['status'])}</td><td>{remove}</td></tr>")
            table = ("<table><thead><tr><th>Alias</th><th>Env</th><th>Authorization expires (UTC)</th><th>Status</th>"
                     "<th></th></tr></thead><tbody>" + "".join(lines) + "</tbody></table>")
        environments = self.shop_manager.available_environments()
        if environments:
            env_options = "".join(f'<option value="{env}">{env}</option>' for env in environments)
            day_options = "".join(f'<option value="{days}"{" selected" if days == DEFAULT_AUTHORIZATION_DAYS else ""}>'
                                  f"{days} days</option>" for days in AUTHORIZATION_DAYS)
            add = f"""<h2>Add shop</h2><form method="post" action="{ADMIN_PATH}" autocomplete="off">
<input type="hidden" name="action" value="add">
<input type="hidden" name="csrf_token" value="{html.escape(self._form_token('add', session))}">
<p><label for="alias">Alias</label><br><input id="alias" name="alias" required maxlength="32"
 pattern="[a-z0-9][a-z0-9_\\-]{{0,31}}" placeholder="store-a"></p>
<p><label for="env">Environment</label><br><select id="env" name="env">{env_options}</select></p>
<p><label for="days">Authorization period</label><br><select id="days" name="days">{day_options}</select></p>
<p><button type="submit">Continue to Shopee</button></p></form>
<p>You will sign in to Shopee as the seller and approve this app. With a main account you can approve
several shops at once; the alias then becomes the default prefix and you pick shops and aliases next.
Shopee then redirects back to
<code>{html.escape(self.shop_manager.redirect_url or "")}</code>.</p>"""
        elif self.shop_manager.redirect_url is None:
            add = '<p class="err">Adding shops needs an https public URL.</p>'
        else:
            add = ('<p class="err">Adding shops needs partner credentials in the server environment '
                   '(SHOPEE_PARTNER_ID and SHOPEE_PARTNER_KEY, optionally SHOPEE_SANDBOX_PARTNER_ID and '
                   'SHOPEE_SANDBOX_PARTNER_KEY).</p>')
        logout = (f'<form method="post" action="{ADMIN_PATH}"><input type="hidden" name="action" value="logout">'
                  f'<input type="hidden" name="csrf_token" value="{html.escape(self._form_token("logout", session))}">'
                  f'<button type="submit">Sign out</button></form>')
        return _html_page("Shop administration", f"{notice}<h2>Shops</h2>{table}{add}<hr>{logout}", status=status)

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
        if action not in ("add", "add-main", "remove", "logout") or not self._form_consume(
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
    app = create_app(service, store, args.public_url, client_ip_header=args.client_ip_header,
                     trusted_proxies=args.trusted_proxy, shop_manager=shop_manager, service_factory=factory,
                     registry=registry)
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
