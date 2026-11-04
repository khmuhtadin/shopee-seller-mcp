import asyncio
import copy
import json
import os
from pathlib import Path

import httpx
import pytest

from shopee_mcp.catalog import Catalog
from shopee_mcp.credentials import CredentialStore, TokenUpdate
from shopee_mcp.policy import Policy
from shopee_mcp.transport import Transport, TransportError, serialize_request
from shopee_mcp.validation import InputError
from test_credentials import make_env


@pytest.fixture
def store(tmp_path):
    path = tmp_path / ".env"
    make_env(path, SHOPEE_ACCESS_TOKEN_EXPIRES_AT="5000")
    return CredentialStore(path, clock=lambda: 1000)


def endpoint():
    return copy.deepcopy(Catalog().get("v2_product_get_item_list", Policy("test")))


def test_array_serialization_preserves_repeat_order_empty_and_false():
    ep = endpoint()
    assert serialize_request(ep, {"offset": 0, "page_size": 10, "item_status": ["NORMAL", "BANNED"]}) == {
        "params": [("offset", "0"), ("page_size", "10"), ("item_status", "NORMAL"), ("item_status", "BANNED")]
    }
    ep["input_schema"]["properties"]["value"] = {"type": "boolean"}
    assert serialize_request(ep, {"value": False}) == {"params": [("value", "false")]}


@pytest.mark.asyncio
async def test_get_signs_exact_path_and_returns_one_page_without_followup(store):
    seen = []
    def handler(request):
        seen.append(request)
        assert request.url.path == "/api/v2/product/get_item_list"
        assert request.url.params.get_list("item_status") == ["NORMAL", "BANNED"]
        assert request.url.params["shop_id"] == "987654"
        return httpx.Response(200, json={"error": "", "response": {"item": [], "has_next_page": True, "next_offset": 10}})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        transport = Transport(store, client=client, clock=lambda: 1000)
        result = await transport.execute(endpoint(), {"offset": 0, "page_size": 10, "item_status": ["NORMAL", "BANNED"]})
        assert result["response"]["has_next_page"] is True
    assert len(seen) == 1


@pytest.mark.asyncio
async def test_write_timeout_is_unknown_and_never_retried(store):
    seen = []
    def handler(request):
        seen.append(request)
        raise httpx.ReadTimeout("access-secret https://example/?sign=private")
    ep = endpoint()
    ep.update(method="POST", path="/api/v2/test/write", encoding="json", effects="write", idempotent=False)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(TransportError) as caught:
            await Transport(store, client=client, clock=lambda: 1000).execute(ep, {})
    assert caught.value.kind == "outcome_unknown"
    assert "access-secret" not in str(caught.value)
    assert len(seen) == 1


@pytest.mark.asyncio
async def test_safe_rate_limit_retry_is_bounded_and_honors_retry_after(store):
    seen, delays = [], []
    async def sleep(delay):
        delays.append(delay)
    def handler(request):
        seen.append(request)
        return httpx.Response(429, headers={"Retry-After": "1"}, json={"error": "error_rate_limit"})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(TransportError) as caught:
            await Transport(store, client=client, clock=lambda: 1000, sleep=sleep).execute(endpoint(), {})
    assert caught.value.kind == "http_error"
    assert len(seen) == 3
    assert delays == [1.0, 1.0]


@pytest.mark.asyncio
async def test_redirect_is_not_followed_even_with_injected_client_redirects_enabled(store):
    seen = []
    def handler(request):
        seen.append(request)
        return httpx.Response(302, headers={"Location": "https://evil.example/?access_token=secret"})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=True) as client:
        with pytest.raises(TransportError, match="redirect_refused"):
            await Transport(store, client=client, clock=lambda: 1000).execute(endpoint(), {})
    assert len(seen) == 1


@pytest.mark.asyncio
async def test_response_limit_applies_to_decoded_stream_and_no_truncated_json(store):
    def handler(request):
        return httpx.Response(200, content=b'{"large":"' + b'x' * 1024 + b'"}')
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(TransportError, match="response_too_large"):
            await Transport(store, client=client, clock=lambda: 1000, max_response_bytes=100).execute(endpoint(), {})


@pytest.mark.asyncio
async def test_json_body_does_not_drop_false_zero_empty_or_null(store):
    ep = endpoint()
    ep.update(method="POST", path="/api/v2/test/read", encoding="json")
    ep["input_schema"] = {"type": "object", "properties": {}}
    expected = {"zero": 0, "flag": False, "cursor": "", "value": None}
    def handler(request):
        assert json.loads(request.content) == expected
        return httpx.Response(200, json={"error": "", "response": {}})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        await Transport(store, client=client, clock=lambda: 1000).execute(ep, expected)


@pytest.mark.asyncio
async def test_invalid_upload_is_rejected_before_refresh_and_external_symlink_is_not_read(store, tmp_path):
    allowed = tmp_path / "uploads"
    allowed.mkdir()
    external = tmp_path / "secret.png"
    external.write_bytes(b"private")
    (allowed / "escape.png").symlink_to(external)
    ep = endpoint()
    ep.update(encoding="multipart", method="POST", effects="write", idempotent=False,
              upload_fields={"image": {"max_bytes": 100, "mime_types": ["image/png"]}})
    ep["input_schema"] = {"type": "object", "properties": {"image": {"type": "string"}}}
    make_env(store.path, SHOPEE_ACCESS_TOKEN_EXPIRES_AT="1100")
    transport = Transport(store, upload_roots=[allowed], clock=lambda: 1000)
    transport.refresh = lambda _: pytest.fail("bad input must not rotate credentials")
    from shopee_mcp.validation import InputError
    try:
        with pytest.raises(InputError):
            await transport.execute(ep, {"image": str(allowed / "escape.png")})
    finally:
        await transport.close()


@pytest.mark.asyncio
async def test_multipart_file_has_exact_contents_and_mime(store, tmp_path):
    allowed = tmp_path / "uploads"
    allowed.mkdir()
    file = allowed / "synthetic.png"
    data = b"\x89PNG\r\n\x1a\n" + b"synthetic"
    file.write_bytes(data)
    ep = endpoint()
    ep.update(encoding="multipart", method="POST", effects="write", idempotent=False,
              upload_fields={"image": {"max_bytes": 100, "mime_types": ["image/png"]}})
    ep["input_schema"] = {"type": "object", "properties": {"image": {"type": "string"}}}
    seen = []
    def handler(request):
        seen.append(request)
        assert data in request.content
        assert b"Content-Type: image/png" in request.content
        return httpx.Response(200, json={"error": "", "response": {}})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        transport = Transport(store, client=client, upload_roots=[allowed], clock=lambda: 1000)
        await transport.execute(ep, {"image": str(file)})
    assert len(seen) == 1


def upload_endpoint():
    ep = synthetic_endpoint()
    ep.update(encoding="multipart", method="POST", effects="write", idempotent=False,
              upload_fields={"image": {"max_bytes": 100, "mime_types": ["image/png"]}})
    ep["input_schema"] = {"type": "object", "properties": {"image": {"type": "string"}}}
    return ep


def synthetic_endpoint():
    """Transport-only fixture; does not assert a real Shopee API contract."""
    return {"encoding": "json", "method": "POST", "path": "/api/v2/test/read",
            "effects": "read", "idempotent": True, "auth_strategy": "shop",
            "input_schema": {"type": "object", "properties": {}},
            "retry_policy": {"max_attempts": 3, "statuses": [429], "errors": []}}


@pytest.mark.asyncio
async def test_upload_content_must_match_allowed_mime_before_refresh(store, tmp_path):
    file = tmp_path / "spoofed.png"
    file.write_bytes(b"private plaintext disguised by its extension")
    make_env(store.path, SHOPEE_ACCESS_TOKEN_EXPIRES_AT="1100")
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: pytest.fail("no HTTP"))) as client:
        transport = Transport(store, client=client, upload_roots=[tmp_path], clock=lambda: 1000)
        transport.refresh = lambda _: pytest.fail("invalid upload must not rotate credentials")
        with pytest.raises(InputError):
            await transport.execute(upload_endpoint(), {"image": str(file)})


@pytest.mark.asyncio
@pytest.mark.parametrize(("data", "mime"), [
    (b"\x89PNG\r\n\x1a\nsynthetic", "image/png"),
    (b"\xff\xd8\xffsynthetic", "image/jpeg"),
    (b"GIF89asynthetic", "image/gif"),
    (b"RIFF\x10\x00\x00\x00WEBPsynthetic", "image/webp"),
    (b"%PDF-1.7\nsynthetic", "application/pdf"),
])
async def test_upload_mime_is_derived_from_content_not_filename(store, tmp_path, data, mime):
    file = tmp_path / "synthetic.data"
    file.write_bytes(data)
    ep = upload_endpoint()
    ep["upload_fields"]["image"]["mime_types"] = [mime]
    def handler(request):
        assert data in request.content
        assert ("Content-Type: " + mime).encode() in request.content
        return httpx.Response(200, json={"error": "", "response": {}})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        await Transport(store, client=client, upload_roots=[tmp_path], clock=lambda: 1000).execute(
            ep, {"image": str(file)})


@pytest.mark.asyncio
@pytest.mark.parametrize("replacement", [b"\x89PNG\r\n\x1a\nchanged", b"\x89PNG\r\n\x1a\n" + b"x" * 101])
async def test_upload_sends_only_bytes_verified_before_refresh(store, tmp_path, replacement):
    file = tmp_path / "synthetic.png"
    data = b"\x89PNG\r\n\x1a\noriginal"
    file.write_bytes(data)
    make_env(store.path, SHOPEE_ACCESS_TOKEN_EXPIRES_AT="1100")
    def refresh(_):
        file.write_bytes(replacement)
        return TokenUpdate("new-access", "new-refresh", 5000, 8000)
    def handler(request):
        assert data in request.content
        assert replacement not in request.content
        return httpx.Response(200, json={"error": "", "response": {}})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        transport = Transport(store, client=client, upload_roots=[tmp_path], clock=lambda: 1000)
        transport.refresh = refresh
        await transport.execute(upload_endpoint(), {"image": str(file)})


@pytest.mark.asyncio
async def test_upload_parent_swap_cannot_escape_pinned_directory(store, tmp_path, monkeypatch):
    allowed = tmp_path / "uploads"
    nested = allowed / "nested"
    nested.mkdir(parents=True)
    external = tmp_path / "external"
    external.mkdir()
    file = nested / "synthetic.png"
    data = b"\x89PNG\r\n\x1a\noriginal"
    secret = b"\x89PNG\r\n\x1a\nprivate"
    file.write_bytes(data)
    (external / file.name).write_bytes(secret)
    original_open = os.open
    swapped = False
    def swap_parent(path, flags, *args, **kwargs):
        nonlocal swapped
        if Path(path).name == file.name and not swapped:
            swapped = True
            nested.rename(allowed / "original")
            nested.symlink_to(external, target_is_directory=True)
        return original_open(path, flags, *args, **kwargs)
    monkeypatch.setattr(os, "open", swap_parent)
    def handler(request):
        assert data in request.content
        assert secret not in request.content
        return httpx.Response(200, json={"error": "", "response": {}})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        await Transport(store, client=client, upload_roots=[allowed], clock=lambda: 1000).execute(
            upload_endpoint(), {"image": str(file)})
    assert swapped


@pytest.mark.asyncio
async def test_upload_growth_after_stat_is_bounded_and_rejected_before_refresh(store, tmp_path, monkeypatch):
    file = tmp_path / "synthetic.png"
    file.write_bytes(b"\x89PNG\r\n\x1a\noriginal")
    inode = file.stat().st_ino
    original_fstat = os.fstat
    def grow_after_stat(fd):
        info = original_fstat(fd)
        if info.st_ino == inode:
            file.write_bytes(b"\x89PNG\r\n\x1a\n" + b"x" * 101)
        return info
    monkeypatch.setattr(os, "fstat", grow_after_stat)
    make_env(store.path, SHOPEE_ACCESS_TOKEN_EXPIRES_AT="1100")
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: pytest.fail("no HTTP"))) as client:
        transport = Transport(store, client=client, upload_roots=[tmp_path], clock=lambda: 1000)
        transport.refresh = lambda _: pytest.fail("grown upload must not rotate credentials")
        with pytest.raises(InputError):
            await transport.execute(upload_endpoint(), {"image": str(file)})


def binary_endpoint():
    ep = synthetic_endpoint()
    ep.update(encoding="binary", method="POST", path="/api/v2/test/download",
              download_mime_types=["application/pdf"])
    return ep


@pytest.mark.asyncio
@pytest.mark.parametrize("mime", ["application/json", "application/pdf", "application/octet-stream"])
async def test_binary_json_business_error_is_not_returned_as_download(store, mime):
    payload = {"error": "synthetic_business_error", "message": "not a document", "request_id": "test-id"}
    def handler(_):
        return httpx.Response(200, headers={"Content-Type": mime}, content=json.dumps(payload).encode())
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await Transport(store, client=client, clock=lambda: 1000).execute(binary_endpoint(), {})
    assert result == payload
    assert "_binary" not in result


@pytest.mark.asyncio
async def test_binary_json_success_is_not_a_download(store):
    async with httpx.AsyncClient(transport=httpx.MockTransport(
            lambda _: httpx.Response(200, json={"error": "", "response": {}}))) as client:
        with pytest.raises(TransportError, match="invalid_response"):
            await Transport(store, client=client, clock=lambda: 1000).execute(binary_endpoint(), {})


@pytest.mark.asyncio
@pytest.mark.parametrize("mime", [None, "text/html", "application/octet-stream"])
async def test_binary_unapproved_or_missing_mime_is_rejected(store, mime):
    headers = {} if mime is None else {"Content-Type": mime}
    async with httpx.AsyncClient(transport=httpx.MockTransport(
            lambda _: httpx.Response(200, headers=headers, content=b"%PDF-1.7\nsynthetic"))) as client:
        with pytest.raises(TransportError, match="download_mime_not_permitted"):
            await Transport(store, client=client, clock=lambda: 1000).execute(binary_endpoint(), {})


@pytest.mark.asyncio
@pytest.mark.parametrize("allowed", [None, [], ["*/*"]])
async def test_binary_requires_explicit_mime_allowlist_before_refresh(store, allowed):
    ep = binary_endpoint()
    if allowed is None:
        ep.pop("download_mime_types")
    else:
        ep["download_mime_types"] = allowed
    make_env(store.path, SHOPEE_ACCESS_TOKEN_EXPIRES_AT="1100")
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: pytest.fail("no HTTP"))) as client:
        transport = Transport(store, client=client, clock=lambda: 1000)
        transport.refresh = lambda _: pytest.fail("invalid download metadata must not rotate credentials")
        with pytest.raises(InputError):
            await transport.execute(ep, {})


@pytest.mark.asyncio
async def test_binary_approved_mime_returns_exact_bounded_bytes(store):
    data = b"%PDF-1.7\nsynthetic"
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(
            200, headers={"Content-Type": "Application/PDF; charset=binary"}, content=data))) as client:
        result = await Transport(store, client=client, clock=lambda: 1000).execute(binary_endpoint(), {})
    assert result["_binary"] == data
    assert result["_mime_type"] == "application/pdf"


@pytest.mark.parametrize("setting", ["timeout", "max_response_bytes", "concurrency", "max_upload_bytes"])
@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_transport_limits_reject_nonfinite_values(store, setting, value):
    with pytest.raises(ValueError):
        Transport(store, client=object(), **{setting: value})


@pytest.mark.asyncio
@pytest.mark.parametrize("retry_after", ["nan", "inf", "-inf"])
async def test_nonfinite_retry_after_uses_finite_backoff(store, retry_after):
    delays = []
    async def sleep(delay):
        delays.append(delay)
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(
            429, headers={"Retry-After": retry_after}, json={"error": "error_rate_limit"}))) as client:
        with pytest.raises(TransportError, match="http_error"):
            await Transport(store, client=client, sleep=sleep, clock=lambda: 1000).execute(synthetic_endpoint(), {})
    assert delays == [0.25, 0.5]
