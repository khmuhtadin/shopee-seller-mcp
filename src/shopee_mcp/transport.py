"""Bounded HTTP execution with catalog-driven encoding; no business policy."""
from __future__ import annotations

import asyncio
import contextlib
import json
import math
import re
import time
from pathlib import Path

import httpx

from .credentials import CredentialStore, RefreshNotSent, TokenUpdate
from .file_transport import download_contains_secrets, freeze_uploads
from .signing import signed_parameters
from .validation import InputError, RESERVED, parameter_aliases, to_wire


class TransportError(RuntimeError):
    def __init__(self, kind, *, status=None, retryable=False):
        self.kind, self.status, self.retryable = kind, status, retryable
        super().__init__(kind)


class APIResponse(dict):
    """Carry per-call redaction values without sharing mutable request state."""
    def __init__(self, payload, secrets=()):
        super().__init__(payload)
        self.secrets = frozenset(secrets)


def _access_token_rejected(payload):
    """Only an explicit, top-level token rejection permits auth replay.

    A generic error_auth can also mean permissions or signature problems.
    Never infer rejection from HTTP status alone or replay a partial result.
    """
    if not isinstance(payload, dict) or not isinstance(payload.get("error"), str):
        return False
    if payload.get("response") not in (None, {}) or set(payload) - {"error", "message", "request_id", "response", "warning"}:
        return False
    message = payload.get("message")
    if not isinstance(message, str):
        return False
    # Exact pairs from the official common errors / response examples; the
    # double-e spelling in invalid_acceess_token is Shopee's published code.
    return (payload["error"], message.strip()) in {
        ("error_auth", "Invalid access_token."),
        ("error_auth", "Invalid access_token"),
        ("common.error_auth", "Invalid access_token."),
        ("invalid_acceess_token", "Invalid access_token, please have a check."),
    }


def _download_policy(endpoint):
    if endpoint.get("download_mime_policy") == "opaque":
        return "opaque", None
    allowed = endpoint.get("download_mime_types")
    if not isinstance(allowed, list) or not allowed or any(
            not isinstance(mime, str) or not re.fullmatch(r"[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*", mime)
            for mime in allowed):
        raise InputError("Download requires explicit allowed MIME types")
    return "allowlist", frozenset(allowed)


def _scalar(value):
    if value is None:
        raise InputError("null query values require an endpoint-specific serializer")
    if type(value) is bool:
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        raise InputError("Nested query values require an explicit serializer")
    return str(value)


def serialize_request(endpoint, request):
    if RESERVED.intersection(request):
        raise InputError("Authentication parameters cannot be overridden")
    aliases = parameter_aliases(endpoint)
    wire = {aliases.get(key, key): value for key, value in to_wire(request, endpoint["input_schema"]).items()}
    encoding = endpoint["encoding"]
    if encoding == "binary":
        # Catalog validation requires this for reviewed endpoints. The default
        # preserves compatibility for transport-only callers and fixtures.
        encoding = endpoint.get("binary_request_encoding", "json")
        if encoding not in {"json", "query"}:
            raise InputError("Binary request encoding must be query or json")
    if encoding == "json":
        return {"json": wire}
    if encoding == "multipart":
        return {"data": wire}
    if encoding != "query":
        raise InputError("Unsupported serialization")
    pairs = []
    for key, value in wire.items():
        if isinstance(value, list):
            mode = endpoint.get("query_arrays", {}).get(key)
            if mode == "repeat":
                pairs.extend((key, _scalar(item)) for item in value)
            elif mode == "csv":
                pairs.append((key, ",".join(_scalar(item) for item in value)))
            elif mode == "json":
                pairs.append((key, json.dumps(value, separators=(",", ":"), ensure_ascii=False)))
            else:
                raise InputError("Array query serialization is not defined")
        else:
            pairs.append((key, _scalar(value)))
    return {"params": pairs}


class Transport:
    def __init__(self, store: CredentialStore, *, client=None, refresh_client=None, clock=time.time,
                 sleep=asyncio.sleep, timeout=30.0, max_response_bytes=8_000_000,
                 concurrency=4, upload_roots=(), max_upload_bytes=10_000_000):
        if (type(timeout) not in {int, float} or not math.isfinite(timeout) or timeout <= 0
                or any(type(limit) is not int or limit <= 0
                       for limit in (max_response_bytes, concurrency, max_upload_bytes))):
            raise ValueError("Transport limits must be finite and positive; byte and concurrency limits must be integers")
        self.store, self.clock, self.sleep = store, clock, sleep
        self.timeout, self.max_response_bytes = timeout, max_response_bytes
        self.client = client or httpx.AsyncClient(timeout=timeout, follow_redirects=False, trust_env=False)
        self.owns_client = client is None
        self.refresh_client = refresh_client
        self.semaphore = asyncio.Semaphore(concurrency)
        self.upload_roots = tuple(Path(path).resolve(strict=True) for path in upload_roots)
        self.max_upload_bytes = max_upload_bytes
        self.secrets = set()

    async def close(self):
        if self.owns_client:
            await self.client.aclose()

    def refresh(self, snapshot):
        """One attempt inside the store's locked worker thread.

        Only failures establishing/acquiring a connection are known unsent.
        Reading, writing, parsing and closing failures may follow rotation.

        The official 30-day clause covers shop, merchant, supplier and user.
        Principal's lifetime is not included in that clause: preserve its
        configured absolute deadline rather than infer an extension.
        """
        path = "/api/v2/auth/access_token/get"
        now = int(self.clock())
        params = signed_parameters(snapshot, path, now, "public")
        body = {"partner_id": snapshot.partner_id, snapshot.scope + "_id": snapshot.subject_id,
                "refresh_token": snapshot.refresh_token}
        client = self.refresh_client
        with contextlib.ExitStack() as stack:
            if client is None:
                client = stack.enter_context(httpx.Client(timeout=self.timeout, follow_redirects=False, trust_env=False))
            try:
                response = stack.enter_context(client.stream(
                    "POST", snapshot.base_url + path, params=params, json=body,
                    follow_redirects=False, timeout=self.timeout))
            except httpx.ConnectTimeout:
                raise RefreshNotSent("connect_timeout") from None
            except httpx.PoolTimeout:
                raise RefreshNotSent("pool_timeout") from None
            except httpx.ConnectError:
                raise RefreshNotSent("connect_error") from None
            if response.status_code != 200:
                raise TransportError("refresh_failed")
            raw = bytearray()
            for chunk in response.iter_bytes():
                raw.extend(chunk)
                if len(raw) > 64_000:
                    raise TransportError("refresh_response_too_large")
        payload = json.loads(raw)
        if not isinstance(payload, dict) or payload.get("error"):
            raise TransportError("refresh_failed")
        for key, expected in (("partner_id", snapshot.partner_id), (snapshot.scope + "_id", snapshot.subject_id)):
            if key in payload and (type(payload[key]) is not int or payload[key] != expected):
                raise TransportError("refresh_binding_mismatch")
        access, refresh, lifetime = payload.get("access_token"), payload.get("refresh_token"), payload.get("expire_in")
        if type(access) is not str or type(refresh) is not str or type(lifetime) is not int or lifetime <= 0:
            raise TransportError("invalid_refresh_response")
        refresh_deadline = (snapshot.refresh_token_expires_at if snapshot.scope == "principal"
                            else now + 30 * 86400)
        return TokenUpdate(access, refresh, now + lifetime, refresh_deadline)

    def _upload(self, endpoint, wire):
        fields, files = freeze_uploads(
            endpoint, wire, self.upload_roots, self.max_upload_bytes)
        return {"data": {key: _scalar(value) for key, value in fields.items()}, "files": files}

    async def execute(self, endpoint, request):
        if endpoint["encoding"] == "credential_refresh":
            scope = request.get("scope", "shop")
            snapshot = await self.store.ensure_async(self.refresh, scope=scope, force=True)
            return {"error": "", "response": {"status": "refreshed", "scope": scope,
                    "access_token_expires_at": snapshot.access_token_expires_at,
                    "refresh_token_expires_at": snapshot.refresh_token_expires_at}}
        encoded = serialize_request(endpoint, request)  # Validate before refresh.
        if endpoint["encoding"] == "multipart":
            encoded = self._upload(endpoint, encoded["data"])  # Pin bytes before credential rotation.
        download = _download_policy(endpoint) if endpoint["encoding"] == "binary" else None
        scope = endpoint["auth_strategy"]
        previous = self.store.snapshot(scope)
        snapshot = await self.store.ensure_async(self.refresh, scope=scope)
        call_secrets = previous.secrets | snapshot.secrets
        safe = endpoint["effects"] == "read" and endpoint["idempotent"]
        attempts = min(5, max(1, endpoint.get("retry_policy", {}).get("max_attempts", 1))) if safe else 1
        attempt, auth_recovered = 0, False
        async with self.semaphore:
            while attempt < attempts:
                # Refresh permission/context was pinned; retry signatures are fresh.
                signed = signed_parameters(snapshot, endpoint["path"], int(self.clock()), scope)
                call_secrets.add(signed["sign"])
                kwargs = dict(encoded)
                kwargs["params"] = list(signed.items()) + kwargs.get("params", [])
                retry_after = None
                try:
                    async with self.client.stream(endpoint["method"], snapshot.base_url + endpoint["path"],
                                                  **kwargs, follow_redirects=False, timeout=self.timeout) as response:
                        status = response.status_code
                        if 300 <= status < 400:
                            raise TransportError("redirect_refused")
                        raw = bytearray()
                        async for chunk in response.aiter_bytes():
                            raw.extend(chunk)
                            if len(raw) > self.max_response_bytes:
                                raise TransportError("response_too_large")
                        retry_after = response.headers.get("Retry-After")
                        if status >= 400:
                            # An HTTP 401/403 alone proves neither token expiry
                            # nor that it is safe to replay a business write.
                            try:
                                rejection = json.loads(raw) if status in {401, 403} else None
                            except (ValueError, UnicodeError):
                                rejection = None
                            if not _access_token_rejected(rejection):
                                retryable = safe and status in endpoint.get("retry_policy", {}).get("statuses", [])
                                raise TransportError("http_error", status=status, retryable=retryable)
                        mime = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
                        try:
                            payload = json.loads(raw)
                        except (ValueError, UnicodeError):
                            if download is not None:
                                if mime == "application/json" or mime.endswith("+json"):
                                    raise TransportError("invalid_response") from None
                                policy, allowed = download
                                if policy == "allowlist" and mime not in allowed:
                                    raise TransportError("download_mime_not_permitted") from None
                                if download_contains_secrets(raw, call_secrets):
                                    raise TransportError("sensitive_download_response") from None
                                artifact_mime = "application/octet-stream" if policy == "opaque" else mime
                                return APIResponse({"_binary": bytes(raw), "_mime_type": artifact_mime}, call_secrets)
                            raise TransportError("invalid_response") from None
                        if not isinstance(payload, dict) or (download is not None and not payload.get("error")):
                            raise TransportError("invalid_response")
                        if _access_token_rejected(payload):
                            if scope != "public" and not auth_recovered:
                                snapshot = await self.store.ensure_async(
                                    self.refresh, scope=scope, force=True, rejected_snapshot=snapshot)
                                call_secrets.update(snapshot.secrets)
                                auth_recovered = True
                                continue  # Re-sign the same pinned request once.
                            return APIResponse(payload, call_secrets)
                        if safe and payload.get("error") in endpoint.get("retry_policy", {}).get("errors", []) and attempt < attempts - 1:
                            await self.sleep(self._delay(attempt, retry_after))
                            attempt += 1
                            continue
                        return APIResponse(payload, call_secrets)
                except httpx.TransportError:
                    if safe and attempt < attempts - 1:
                        await self.sleep(self._delay(attempt, None))
                        attempt += 1
                        continue
                    raise TransportError("network_error" if safe else "outcome_unknown", retryable=safe) from None
                except TransportError as error:
                    if error.retryable and attempt < attempts - 1:
                        await self.sleep(self._delay(attempt, retry_after))
                        attempt += 1
                        continue
                    if not safe and error.kind in {"invalid_response", "response_too_large", "http_error"}:
                        raise TransportError("outcome_unknown", status=error.status) from None
                    raise
        raise TransportError("request_failed")

    @staticmethod
    def _delay(attempt, retry_after):
        try:
            delay = float(retry_after)
            if math.isfinite(delay):
                return min(30.0, max(0.0, delay))
        except (TypeError, ValueError):
            pass
        return min(2.0, 0.25 * 2**attempt)
