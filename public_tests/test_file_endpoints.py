import hashlib
import json

import httpx
import pytest

from shopee_mcp.credentials import CredentialStore
from shopee_mcp.transport import Transport, TransportError, serialize_request
from shopee_mcp.validation import InputError
from test_credentials import make_env


@pytest.fixture
def store(tmp_path):
    path = tmp_path / ".env"
    make_env(path, SHOPEE_ACCESS_TOKEN_EXPIRES_AT="5000")
    return CredentialStore(path, clock=lambda: 1000)


def endpoint(**updates):
    value = {
        "api_name": "v2.test.file",
        "encoding": "multipart",
        "method": "POST",
        "path": "/api/v2/test/file",
        "effects": "write",
        "idempotent": False,
        "auth_strategy": "shop",
        "input_schema": {"type": "object", "properties": {}},
        "retry_policy": {"max_attempts": 1, "statuses": [], "errors": []},
    }
    value.update(updates)
    return value


def png(suffix=b"synthetic"):
    return b"\x89PNG\r\n\x1a\n" + suffix


@pytest.mark.asyncio
async def test_repeated_multipart_files_preserve_order_and_scalar_fields(store, tmp_path):
    first = tmp_path / "first.png"
    second = tmp_path / "second.png"
    first.write_bytes(png(b"first"))
    second.write_bytes(png(b"second"))
    ep = endpoint(upload_fields={"images": {
        "max_bytes": 100,
        "mime_types": ["image/png"],
        "content_kind": "identified",
        "multiple": True,
        "max_files": 3,
    }})
    ep["input_schema"] = {"type": "object", "properties": {
        "business": {"type": "integer"},
        "images": {"type": "array", "items": {"type": "string"}},
    }}

    def handler(request):
        body = request.content
        assert body.count(b'name="images"') == 2
        assert body.index(b"first.png") < body.index(b"second.png")
        assert png(b"first") in body and png(b"second") in body
        assert b'name="business"' in body and b"\r\n\r\n2\r\n" in body
        return httpx.Response(200, json={"error": ""})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        await Transport(store, client=client, upload_roots=[tmp_path], clock=lambda: 1000).execute(
            ep, {"business": 2, "images": [str(first), str(second)]})


@pytest.mark.asyncio
@pytest.mark.parametrize("paths", [[], ["one", "two", "three", "four"]])
async def test_repeated_multipart_requires_one_to_max_files_before_refresh(store, tmp_path, paths):
    ep = endpoint(upload_fields={"images": {
        "max_bytes": 100,
        "mime_types": ["image/png"],
        "content_kind": "identified",
        "multiple": True,
        "max_files": 3,
    }})
    make_env(store.path, SHOPEE_ACCESS_TOKEN_EXPIRES_AT="1100")
    transport = Transport(store, upload_roots=[tmp_path], clock=lambda: 1000)
    transport.refresh = lambda _: pytest.fail("invalid files must not rotate credentials")
    try:
        with pytest.raises(InputError, match="file count"):
            await transport.execute(ep, {"images": paths})
    finally:
        await transport.close()


@pytest.mark.asyncio
async def test_repeated_files_share_the_global_upload_byte_budget(store, tmp_path):
    files = []
    for name in ("first.png", "second.png"):
        path = tmp_path / name
        path.write_bytes(png(b"x" * 50))
        files.append(str(path))
    ep = endpoint(upload_fields={"images": {
        "max_bytes": 100,
        "mime_types": ["image/png"],
        "content_kind": "identified",
        "multiple": True,
        "max_files": 3,
    }})
    make_env(store.path, SHOPEE_ACCESS_TOKEN_EXPIRES_AT="1100")
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: pytest.fail("no HTTP"))) as client:
        transport = Transport(store, client=client, upload_roots=[tmp_path], max_upload_bytes=100,
                              clock=lambda: 1000)
        transport.refresh = lambda _: pytest.fail("oversized upload set must not rotate credentials")
        with pytest.raises(InputError, match="total size"):
            await transport.execute(ep, {"images": files})


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["symlink", "directory"])
async def test_file_nodes_are_regular_and_not_symlinks_before_refresh(store, tmp_path, kind):
    target = tmp_path / "target.png"
    target.write_bytes(png())
    supplied = tmp_path / "supplied"
    if kind == "symlink":
        supplied.symlink_to(target)
    else:
        supplied.mkdir()
    ep = endpoint(upload_fields={"image": {
        "max_bytes": 100,
        "mime_types": ["image/png"],
        "content_kind": "identified",
    }})
    make_env(store.path, SHOPEE_ACCESS_TOKEN_EXPIRES_AT="1100")
    transport = Transport(store, upload_roots=[tmp_path], clock=lambda: 1000)
    transport.refresh = lambda _: pytest.fail("invalid node must not rotate credentials")
    try:
        with pytest.raises(InputError):
            await transport.execute(ep, {"image": str(supplied)})
    finally:
        await transport.close()


@pytest.mark.asyncio
async def test_opaque_chunk_requires_matching_md5_and_freezes_as_octet_stream(store, tmp_path):
    part = tmp_path / "part.bin"
    data = b"opaque-video-part\x00\xff"
    part.write_bytes(data)
    digest = hashlib.md5(data).hexdigest()
    ep = endpoint(upload_fields={"part_content": {
        "max_bytes": 100,
        "mime_types": ["application/octet-stream"],
        "content_kind": "opaque",
        "checksum": {"field": "part_md5", "algorithm": "md5"},
    }})

    def handler(request):
        assert data in request.content
        assert b"Content-Type: application/octet-stream" in request.content
        assert digest.encode() in request.content
        return httpx.Response(200, json={"error": ""})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        transport = Transport(store, client=client, upload_roots=[tmp_path], clock=lambda: 1000)
        await transport.execute(ep, {"part_content": str(part), "part_md5": digest})
        with pytest.raises(InputError, match="checksum"):
            await transport.execute(ep, {"part_content": str(part), "part_md5": "0" * 32})


@pytest.mark.asyncio
async def test_invoice_xml_is_well_formed_and_mime_must_match_file_type(store, tmp_path):
    invoice = tmp_path / "invoice.xml"
    invoice.write_bytes(b'<?xml version="1.0"?><invoice><id>1</id></invoice>')
    ep = endpoint(upload_fields={"file": {
        "max_bytes": 1_000_000,
        "mime_types": ["application/pdf", "image/jpeg", "image/png", "application/xml"],
        "content_kind": "identified",
        "mime_selector": {"field": "file_type", "values": {
            "1": "application/pdf", "2": "image/jpeg", "3": "image/png", "4": "application/xml",
        }},
    }})

    def handler(request):
        assert b"Content-Type: application/xml" in request.content
        assert invoice.read_bytes() in request.content
        return httpx.Response(200, json={"error": ""})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        transport = Transport(store, client=client, upload_roots=[tmp_path], clock=lambda: 1000)
        await transport.execute(ep, {"file": str(invoice), "file_type": 4, "order_sn": "x"})
        with pytest.raises(InputError, match="file type"):
            await transport.execute(ep, {"file": str(invoice), "file_type": 1, "order_sn": "x"})

    invoice.write_bytes(b"<?xml version='1.0'?><invoice>")
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: pytest.fail("no HTTP"))) as client:
        with pytest.raises(InputError, match="unsupported"):
            await Transport(store, client=client, upload_roots=[tmp_path], clock=lambda: 1000).execute(
                ep, {"file": str(invoice), "file_type": 4})


def binary_endpoint(method="GET", request_encoding="query"):
    return endpoint(
        encoding="binary",
        method=method,
        effects="read",
        idempotent=True,
        binary_request_encoding=request_encoding,
        download_mime_policy="opaque",
        upload_fields=None,
        input_schema={"type": "object", "properties": {"order_sn": {"type": "string"}}},
        retry_policy={"max_attempts": 1, "statuses": [], "errors": []},
    )


def test_binary_request_encoding_is_explicit_and_independent_of_method():
    assert serialize_request(binary_endpoint("GET", "query"), {"order_sn": "A"}) == {
        "params": [("order_sn", "A")]
    }
    assert serialize_request(binary_endpoint("POST", "json"), {"order_sn": "A"}) == {
        "json": {"order_sn": "A"}
    }
    with pytest.raises(InputError, match="request encoding"):
        serialize_request(binary_endpoint("POST", "multipart"), {})


@pytest.mark.asyncio
async def test_get_opaque_download_has_no_body_and_normalizes_untrusted_mime(store):
    data = b"opaque official file bytes"

    def handler(request):
        assert request.method == "GET"
        assert request.url.params["order_sn"] == "A"
        assert request.content == b""
        return httpx.Response(200, headers={"Content-Type": "text/html; charset=utf-8"}, content=data)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await Transport(store, client=client, clock=lambda: 1000).execute(
            binary_endpoint(), {"order_sn": "A"})
    assert result["_binary"] == data
    assert result["_mime_type"] == "application/octet-stream"


@pytest.mark.asyncio
@pytest.mark.parametrize("content_type", [None, "application/json", "application/octet-stream"])
async def test_opaque_download_parses_json_errors_before_treating_bytes_as_file(store, content_type):
    payload = {"error": "error_param", "message": "not a document"}
    headers = {} if content_type is None else {"Content-Type": content_type}
    async with httpx.AsyncClient(transport=httpx.MockTransport(
            lambda _: httpx.Response(200, headers=headers, content=json.dumps(payload).encode()))) as client:
        result = await Transport(store, client=client, clock=lambda: 1000).execute(binary_endpoint(), {})
    assert result == payload
    assert "_binary" not in result


@pytest.mark.asyncio
async def test_opaque_download_rejects_json_success_and_bounds_bytes(store):
    async with httpx.AsyncClient(transport=httpx.MockTransport(
            lambda _: httpx.Response(200, json={"error": "", "response": {}}))) as client:
        with pytest.raises(TransportError, match="invalid_response"):
            await Transport(store, client=client, clock=lambda: 1000).execute(binary_endpoint(), {})

    async with httpx.AsyncClient(transport=httpx.MockTransport(
            lambda _: httpx.Response(200, content=b"x" * 101))) as client:
        with pytest.raises(TransportError, match="response_too_large"):
            await Transport(store, client=client, clock=lambda: 1000, max_response_bytes=100).execute(
                binary_endpoint(), {})


@pytest.mark.asyncio
@pytest.mark.parametrize("body", [b"not-json", b"x" * 101])
async def test_file_write_invalid_or_oversize_response_is_unknown_and_not_retried(store, tmp_path, body):
    image = tmp_path / "image.png"
    image.write_bytes(png())
    ep = endpoint(upload_fields={"image": {
        "max_bytes": 100,
        "mime_types": ["image/png"],
        "content_kind": "identified",
    }})
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, content=body)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        transport = Transport(store, client=client, upload_roots=[tmp_path], max_response_bytes=100,
                              clock=lambda: 1000)
        with pytest.raises(TransportError) as caught:
            await transport.execute(ep, {"image": str(image)})
    assert caught.value.kind == "outcome_unknown"
    assert len(seen) == 1
