"""Regressions from independent file transport security review."""
from html import escape
from urllib.parse import quote

import httpx
import pytest

from shopee_mcp.credentials import CredentialStore, TokenUpdate
from shopee_mcp.file_transport import _identified_mime
from shopee_mcp.transport import Transport, TransportError
from shopee_mcp.validation import InputError
from test_credentials import make_env
from test_file_endpoints import binary_endpoint, endpoint


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16", "utf-16-be", "utf-32"])
@pytest.mark.parametrize("declaration", [
    '<!DOCTYPE invoice [<!ENTITY x "EXPANDED">]><invoice>&x;</invoice>',
    '<!DOCTYPE invoice SYSTEM "https://example.invalid/private.dtd"><invoice/>',
])
def test_xml_parser_rejects_all_dtds_independent_of_encoding(encoding, declaration):
    xml_encoding = "UTF-16" if encoding.startswith("utf-16") else encoding.upper()
    data = (f'<?xml version="1.0" encoding="{xml_encoding}"?>' + declaration).encode(encoding)
    with pytest.raises(InputError):
        _identified_mime(data)


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16", "utf-16-be"])
def test_non_dtd_xml_remains_supported_without_building_an_element_tree(encoding):
    xml_encoding = "UTF-16" if encoding.startswith("utf-16") else "UTF-8"
    data = (f'<?xml version="1.0" encoding="{xml_encoding}"?>'
            '<invoice><note>&amp; harmless &lt;markup&gt;</note></invoice>').encode(encoding)
    assert _identified_mime(data) == "application/xml"


@pytest.mark.asyncio
async def test_utf16_dtd_is_rejected_before_any_credential_rotation(tmp_path):
    env = tmp_path / ".env"
    make_env(env)
    store = CredentialStore(env, clock=lambda: 1000)
    xml = tmp_path / "invoice.xml"
    xml.write_bytes(('<?xml version="1.0" encoding="UTF-16"?>'
                     '<!DOCTYPE invoice [<!ENTITY x "expanded">]><invoice>&x;</invoice>').encode("utf-16"))
    item = endpoint(upload_fields={"file": {"max_bytes": 10000, "mime_types": ["application/xml"]}})
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: pytest.fail("no HTTP"))) as client:
        transport = Transport(store, client=client, clock=lambda:1000, upload_roots=[tmp_path])
        transport.refresh = lambda _: pytest.fail("invalid XML must not rotate single-use credentials")
        with pytest.raises(InputError):
            await transport.execute(item, {"file": str(xml)})


@pytest.mark.asyncio
@pytest.mark.parametrize("encoding", ["utf-8", "utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be"])
@pytest.mark.parametrize("representation", ["literal", "percent", "html"])
async def test_opaque_download_never_exposes_echoed_signed_url(tmp_path, encoding, representation):
    env = tmp_path / ".env"
    make_env(env, SHOPEE_ACCESS_TOKEN_EXPIRES_AT="5000")
    def handler(request):
        url = str(request.url)
        if representation == "percent":
            url = quote(url, safe="")
        elif representation == "html":
            url = escape(url)
        return httpx.Response(200, headers={"Content-Type":"text/html"},
                              content=("<html>Failed request " + url + "</html>").encode(encoding))
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(TransportError, match="sensitive_download_response"):
            await Transport(CredentialStore(env, clock=lambda:1000), client=client,
                            clock=lambda:1000).execute(binary_endpoint(), {})


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [
    b"binary\x00access-secret\xff", b"binary refresh-secret", b"binary partner-secret",
    b"https://example.invalid/file?sign=not-the-current-signature",
    b"https://example.invalid/file?X-Amz-Signature=another-signature",
    b"%61%63%63%65%73%73%2d%73%65%63%72%65%74",
])
async def test_opaque_download_rejects_credentials_and_signed_links(tmp_path, payload):
    env = tmp_path / ".env"
    make_env(env, SHOPEE_ACCESS_TOKEN_EXPIRES_AT="5000")
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(200, content=payload))) as client:
        with pytest.raises(TransportError, match="sensitive_download_response"):
            await Transport(CredentialStore(env, clock=lambda:1000), client=client,
                            clock=lambda:1000).execute(binary_endpoint(), {})


@pytest.mark.asyncio
async def test_previous_generation_credentials_are_blocked_after_rotation(tmp_path):
    env = tmp_path / ".env"
    make_env(env)
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(
            200, content=b"old access-secret must not escape"))) as client:
        transport = Transport(CredentialStore(env, clock=lambda:1000), client=client, clock=lambda:1000)
        transport.refresh = lambda _: TokenUpdate("new-access", "new-refresh", 5000, 8000)
        with pytest.raises(TransportError, match="sensitive_download_response"):
            await transport.execute(binary_endpoint(), {})


@pytest.mark.asyncio
async def test_download_keeps_non_sensitive_binary_bytes_unchanged(tmp_path):
    env = tmp_path / ".env"
    make_env(env, SHOPEE_ACCESS_TOKEN_EXPIRES_AT="5000")
    payload = b"\x00\xff\x80document https://example.invalid/help?order_sn=A&code_name=B"
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(200, content=payload))) as client:
        result = await Transport(CredentialStore(env, clock=lambda:1000), client=client,
                                 clock=lambda:1000).execute(binary_endpoint(), {})
    assert result["_binary"] == payload
