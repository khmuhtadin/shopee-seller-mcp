"""Exercise recovery through real storage/transport/MCP, with synthetic HTTP only."""
import asyncio
import json

import httpx
import pytest
from mcp import Client

from shopee_mcp.catalog import Catalog
from shopee_mcp.credentials import CredentialError, CredentialStore, read_values
from shopee_mcp.policy import Policy
from shopee_mcp.results import ArtifactStore
from shopee_mcp.server import MCPService
from shopee_mcp.transport import Transport, TransportError
from test_credentials import make_env
from test_transport import synthetic_endpoint, upload_endpoint, binary_endpoint


@pytest.fixture
def store(tmp_path):
    path = tmp_path / ".env"
    make_env(path, SHOPEE_ACCESS_TOKEN_EXPIRES_AT="5000")
    return CredentialStore(path, clock=lambda: 1000)


def rotated_response():
    return httpx.Response(200, json={
        "error": "", "access_token": "new-access", "refresh_token": "new-refresh",
        "expire_in": 14400, "partner_id": 123456, "shop_id": 987654,
    })


def auth_rejection():
    return {"error": "common.error_auth", "message": "Invalid access_token.",
            "request_id": "synthetic-auth-rejection"}


@pytest.mark.parametrize("failure", [httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout])
def test_unsent_refresh_retries_once_without_quarantining(store, failure):
    seen = []

    def refresh(request):
        seen.append(json.loads(request.content))
        if len(seen) == 1:
            raise failure("refresh-secret https://example/?sign=private")
        return rotated_response()

    with httpx.Client(transport=httpx.MockTransport(refresh)) as client:
        transport = Transport(store, client=object(), refresh_client=client, clock=lambda: 1000)
        got = store.ensure(transport.refresh, force=True)
    assert got.access_token == "new-access"
    assert got.refresh_token == "new-refresh"
    assert len(seen) == 2
    assert seen[0] == seen[1] == {
        "partner_id": 123456, "shop_id": 987654, "refresh_token": "refresh-secret"}
    assert json.loads(store.lock_path.read_text()) == {}


@pytest.mark.parametrize("failure", [httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout])
def test_persistent_unsent_failure_is_bounded_and_next_process_can_recover(store, failure):
    seen = []
    before = store.path.read_bytes()

    def offline(request):
        seen.append(request)
        raise failure("refresh-secret https://example/?sign=private")

    with httpx.Client(transport=httpx.MockTransport(offline)) as client:
        transport = Transport(store, client=object(), refresh_client=client, clock=lambda: 1000)
        with pytest.raises(CredentialError, match="refresh_not_sent") as caught:
            store.ensure(transport.refresh, force=True)
    assert len(seen) == 2
    assert "refresh-secret" not in str(caught.value)
    assert "private" not in str(caught.value)
    assert store.path.read_bytes() == before
    fresh = CredentialStore(store.path, clock=lambda: 1000)
    with httpx.Client(transport=httpx.MockTransport(lambda _: rotated_response())) as client:
        transport = Transport(fresh, client=object(), refresh_client=client, clock=lambda: 1000)
        assert fresh.ensure(transport.refresh, force=True).access_token == "new-access"


@pytest.mark.parametrize("failure", [httpx.ReadTimeout, httpx.WriteTimeout, httpx.ReadError,
                                      httpx.WriteError, httpx.RemoteProtocolError])
def test_possible_remote_rotation_still_quarantines_without_retry(store, failure):
    seen = []

    def uncertain(request):
        seen.append(request)
        raise failure("refresh-secret")

    with httpx.Client(transport=httpx.MockTransport(uncertain)) as client:
        transport = Transport(store, client=object(), refresh_client=client, clock=lambda: 1000)
        with pytest.raises(CredentialError, match="refresh_outcome_unknown"):
            store.ensure(transport.refresh, force=True)
        with pytest.raises(CredentialError, match="credential_quarantined"):
            CredentialStore(store.path, clock=lambda: 1000).ensure(transport.refresh, force=True)
    assert len(seen) == 1


@pytest.mark.parametrize("failure", [httpx.CloseError, httpx.ConnectError])
def test_refresh_response_close_failure_cannot_be_classified_as_unsent(store, failure):
    seen = []

    class FailingClose(httpx.SyncByteStream):
        def __iter__(self):
            yield rotated_response().content

        def close(self):
            raise failure("new-refresh")

    def refresh(request):
        seen.append(request)
        return httpx.Response(200, stream=FailingClose())

    with httpx.Client(transport=httpx.MockTransport(refresh)) as client:
        transport = Transport(store, client=object(), refresh_client=client, clock=lambda: 1000)
        with pytest.raises(CredentialError, match="refresh_outcome_unknown") as caught:
            store.ensure(transport.refresh, force=True)
        assert "new-refresh" not in str(caught.value)
        with pytest.raises(CredentialError, match="credential_quarantined"):
            CredentialStore(store.path, clock=lambda: 1000).ensure(transport.refresh, force=True)
    assert len(seen) == 1


@pytest.mark.parametrize("status,body", [
    (503, b"service unavailable"),
    (200, b"{\"access_token\":"),
    (200, b'{"error":"error_auth","message":"Invalid refresh_token."}'),
    (200, b'{"error":"","access_token":"new-access","refresh_token":"new-refresh","expire_in":14400,"shop_id":99}'),
])
def test_invalid_refresh_responses_remain_quarantined(store, status, body):
    seen = []

    def refresh(request):
        seen.append(request)
        return httpx.Response(status, content=body)

    with httpx.Client(transport=httpx.MockTransport(refresh)) as client:
        transport = Transport(store, client=object(), refresh_client=client, clock=lambda: 1000)
        with pytest.raises(CredentialError, match="refresh_outcome_unknown"):
            store.ensure(transport.refresh, force=True)
        with pytest.raises(CredentialError, match="credential_quarantined"):
            CredentialStore(store.path, clock=lambda: 1000).ensure(transport.refresh, force=True)
    assert len(seen) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [200, 401, 403])
@pytest.mark.parametrize("code,message", [
    ("error_auth", "Invalid access_token."),
    ("error_auth", "Invalid access_token"),
    ("common.error_auth", " Invalid access_token."),
    ("invalid_acceess_token", "Invalid access_token, please have a check."),
])
async def test_documented_token_rejections_refresh_but_not_generic_http_errors(store, status, code, message):
    seen = []

    def business(request):
        seen.append(request)
        if len(seen) == 1:
            return httpx.Response(status, json={"error": code, "message": message})
        return httpx.Response(200, json={"error": "", "response": {"value": 42}})

    with httpx.Client(transport=httpx.MockTransport(lambda _: rotated_response())) as refresh_client:
        async with httpx.AsyncClient(transport=httpx.MockTransport(business)) as client:
            result = await Transport(store, client=client, refresh_client=refresh_client,
                                     clock=lambda: 1000).execute(synthetic_endpoint(), {})
    assert result["response"] == {"value": 42}
    assert len(seen) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("effects", ["read", "write"])
async def test_definitive_auth_rejection_refreshes_saves_and_replays_once(store, effects):
    seen, refreshes = [], []
    ep = synthetic_endpoint()
    ep.update(effects=effects, idempotent=effects == "read")

    def business(request):
        seen.append(request)
        if len(seen) == 1:
            return httpx.Response(200, json=auth_rejection())
        assert store.snapshot().access_token == "new-access"
        assert request.url.params["access_token"] == "new-access"
        return httpx.Response(200, json={"error": "", "response": {"value": 42}})

    def refresh(request):
        refreshes.append(request)
        assert json.loads(request.content)["refresh_token"] == "refresh-secret"
        return rotated_response()

    with httpx.Client(transport=httpx.MockTransport(refresh)) as refresh_client:
        async with httpx.AsyncClient(transport=httpx.MockTransport(business)) as client:
            transport = Transport(store, client=client, refresh_client=refresh_client, clock=lambda: 1000)
            result = await transport.execute(ep, {"value": 7})
    assert result["response"] == {"value": 42}
    assert len(seen) == 2 and len(refreshes) == 1
    assert seen[0].content == seen[1].content == b'{"value":7}'
    assert seen[0].url.params["sign"] != seen[1].url.params["sign"]
    assert {"access-secret", "refresh-secret", "new-access", "new-refresh"} <= result.secrets
    assert store.snapshot().refresh_token == "new-refresh"


@pytest.mark.asyncio
async def test_repeated_auth_rejection_stops_after_one_recovery(store):
    seen, refreshes = [], []

    def business(request):
        seen.append(request)
        return httpx.Response(200, json=auth_rejection())

    def refresh(request):
        refreshes.append(request)
        return rotated_response()

    ep = synthetic_endpoint()
    # Even a catalog retry policy must not turn auth recovery into a loop.
    ep["retry_policy"]["errors"] = ["common.error_auth"]
    with httpx.Client(transport=httpx.MockTransport(refresh)) as refresh_client:
        async with httpx.AsyncClient(transport=httpx.MockTransport(business)) as client:
            result = await Transport(store, client=client, refresh_client=refresh_client,
                                     clock=lambda: 1000).execute(ep, {})
    assert result["error"] == "common.error_auth"
    assert len(seen) == 2 and len(refreshes) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [
    {"error": "common.error_auth", "message": "Permission denied."},
    {"error": "common.error_auth", "message": "Invalid sign."},
    {"error": "common.error_auth", "message": "Shop is not authorized."},
    {"error": "common.error_auth", "message": "Invalid refresh_token."},
    {"error": "error_permission", "message": "Invalid access_token."},
    {"error": "common.error_auth", "message": "Access token has expired."},
    {"error": "invalid_acceess_token", "message": "Permission denied."},
    {**auth_rejection(), "response": {"success_list": [123]}},
    {**auth_rejection(), "success_list": [123]},
    {"error": "", "response": {"error": "common.error_auth", "message": "Invalid access_token."}},
])
async def test_non_token_errors_and_partial_results_are_not_refreshed_or_replayed(store, payload):
    seen = []

    def business(request):
        seen.append(request)
        return httpx.Response(200, json=payload)

    with httpx.Client(transport=httpx.MockTransport(lambda _: pytest.fail("must not refresh"))) as refresh_client:
        async with httpx.AsyncClient(transport=httpx.MockTransport(business)) as client:
            result = await Transport(store, client=client, refresh_client=refresh_client,
                                     clock=lambda: 1000).execute(synthetic_endpoint(), {})
    assert result == payload
    assert len(seen) == 1


@pytest.mark.asyncio
async def test_mcp_request_after_25_hours_refreshes_before_business_and_persists(tmp_path):
    path = tmp_path / ".env"
    make_env(path, SHOPEE_ACCESS_TOKEN_EXPIRES_AT="15400",
             SHOPEE_REFRESH_TOKEN_EXPIRES_AT="2593000", SHOPEE_AUTH_EXPIRES_AT="4000000")
    clock = [1000]
    store = CredentialStore(path, clock=lambda: clock[0])
    events = []

    def refresh(request):
        events.append("refresh")
        assert request.url.params["timestamp"] == "91000"
        return rotated_response()

    def business(request):
        events.append("business")
        expected = "access-secret" if clock[0] == 1000 else "new-access"
        assert request.url.params["access_token"] == expected
        assert read_values(path)["SHOPEE_ACCESS_TOKEN"] == expected
        return httpx.Response(200, json={"error": "", "response": {
            "item": [], "total_count": 0, "has_next_page": False}})

    with httpx.Client(transport=httpx.MockTransport(refresh)) as refresh_client:
        async with httpx.AsyncClient(transport=httpx.MockTransport(business)) as http:
            transport = Transport(store, client=http, refresh_client=refresh_client, clock=lambda: clock[0])
            service = MCPService(Catalog(), Policy("test"), transport, ArtifactStore(tmp_path / "artifacts"))
            async with Client(service.server) as client:
                args = {"request": {"offset": 0, "page_size": 10, "item_status": ["NORMAL"]}}
                initial = await client.call_tool("v2_product_get_item_list", args)
                assert initial.structured_content["ok"] is True
                clock[0] = 91000  # 1000 + 25 * 60 * 60; no production clock or token edits.
                later = await client.call_tool("v2_product_get_item_list", args)
                assert later.structured_content["ok"] is True
    assert events == ["business", "refresh", "business"]
    assert store.snapshot().access_token_expires_at == 105400
    assert store.snapshot().refresh_token_expires_at == 2683000
    assert path.stat().st_mode & 0o777 == 0o600
    assert "OTHER=keep\n" in path.read_text()


@pytest.mark.asyncio
async def test_mcp_unsent_error_is_retryable_and_has_only_safe_diagnostics(store, tmp_path):
    make_env(store.path)

    def offline(_):
        raise httpx.ConnectError("refresh-secret https://example/?sign=private")

    with httpx.Client(transport=httpx.MockTransport(offline)) as refresh_client:
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: pytest.fail("no business"))) as http:
            transport = Transport(store, client=http, refresh_client=refresh_client, clock=lambda: 1000)
            service = MCPService(Catalog(), Policy("test"), transport, ArtifactStore(tmp_path / "artifacts"))
            async with Client(service.server) as client:
                result = await client.call_tool("v2_product_get_item_list", {
                    "request": {"offset": 0, "page_size": 10, "item_status": ["NORMAL"]}})
    envelope = result.structured_content
    assert result.is_error and envelope["error"]["kind"] == "refresh_not_sent"
    assert envelope["error"]["retryable"] is True
    assert "refresh-secret" not in result.model_dump_json()
    assert "private" not in result.model_dump_json()


@pytest.mark.asyncio
async def test_late_concurrent_auth_rejection_reuses_already_rotated_file(store):
    both_sent, first_replayed = asyncio.Event(), asyncio.Event()
    seen, refreshes = [], []

    async def business(request):
        seen.append(request.url.params["access_token"])
        if request.url.params["access_token"] == "access-secret":
            position = seen.count("access-secret")
            if position == 2:
                both_sent.set()
                await asyncio.wait_for(first_replayed.wait(), 3)
            else:
                await asyncio.wait_for(both_sent.wait(), 3)
            return httpx.Response(200, json=auth_rejection())
        first_replayed.set()
        return httpx.Response(200, json={"error": "", "response": {"value": 42}})

    def refresh(request):
        refreshes.append(request)
        return rotated_response()

    with httpx.Client(transport=httpx.MockTransport(refresh)) as refresh_client:
        async with httpx.AsyncClient(transport=httpx.MockTransport(business)) as client:
            other = CredentialStore(store.path, clock=lambda: 1000)
            transports = [Transport(s, client=client, refresh_client=refresh_client,
                                    clock=lambda: 1000) for s in (store, other)]
            results = await asyncio.wait_for(asyncio.gather(*[
                t.execute(synthetic_endpoint(), {}) for t in transports]), 5)
    assert [r["response"] for r in results] == [{"value": 42}, {"value": 42}]
    assert seen == ["access-secret", "access-secret", "new-access", "new-access"]
    assert len(refreshes) == 1


@pytest.mark.asyncio
async def test_write_timeout_after_auth_replay_is_not_replayed_again(store):
    seen = []

    def business(request):
        seen.append(request)
        if len(seen) == 1:
            return httpx.Response(200, json=auth_rejection())
        raise httpx.ReadTimeout("new-access")

    ep = synthetic_endpoint()
    ep.update(effects="write", idempotent=False)
    with httpx.Client(transport=httpx.MockTransport(lambda _: rotated_response())) as refresh_client:
        async with httpx.AsyncClient(transport=httpx.MockTransport(business)) as client:
            with pytest.raises(TransportError, match="outcome_unknown"):
                await Transport(store, client=client, refresh_client=refresh_client,
                                clock=lambda: 1000).execute(ep, {})
    assert len(seen) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [401, 403, 500])
async def test_http_status_without_exact_auth_rejection_never_replays_write(store, status):
    seen = []

    def business(request):
        seen.append(request)
        return httpx.Response(status, json={"message": "Unauthorized"})

    ep = synthetic_endpoint()
    ep.update(effects="write", idempotent=False)
    with httpx.Client(transport=httpx.MockTransport(lambda _: pytest.fail("must not refresh"))) as refresh_client:
        async with httpx.AsyncClient(transport=httpx.MockTransport(business)) as client:
            with pytest.raises(TransportError, match="outcome_unknown"):
                await Transport(store, client=client, refresh_client=refresh_client,
                                clock=lambda: 1000).execute(ep, {})
    assert len(seen) == 1


@pytest.mark.asyncio
async def test_auth_recovery_save_failure_stops_before_business_replay(store, monkeypatch):
    seen = []

    def business(request):
        seen.append(request)
        return httpx.Response(200, json=auth_rejection())

    def fail_save(*_):
        raise OSError("synthetic disk failure")

    monkeypatch.setattr(store, "_save", fail_save)
    with httpx.Client(transport=httpx.MockTransport(lambda _: rotated_response())) as refresh_client:
        async with httpx.AsyncClient(transport=httpx.MockTransport(business)) as client:
            with pytest.raises(CredentialError, match="credential_persistence_failed"):
                await Transport(store, client=client, refresh_client=refresh_client,
                                clock=lambda: 1000).execute(synthetic_endpoint(), {})
    assert len(seen) == 1


@pytest.mark.asyncio
async def test_auth_recovery_preserves_the_existing_read_retry_budget(store):
    seen, delays = [], []

    def business(request):
        seen.append(request)
        if len(seen) < 3:
            return httpx.Response(429)
        if len(seen) == 3:
            return httpx.Response(200, json=auth_rejection())
        return httpx.Response(200, json={"error": "", "response": {"value": 42}})

    async def sleep(delay):
        delays.append(delay)

    with httpx.Client(transport=httpx.MockTransport(lambda _: rotated_response())) as refresh_client:
        async with httpx.AsyncClient(transport=httpx.MockTransport(business)) as client:
            result = await Transport(store, client=client, refresh_client=refresh_client,
                                     clock=lambda: 1000, sleep=sleep).execute(synthetic_endpoint(), {})
    assert result["response"] == {"value": 42}
    assert len(seen) == 4 and delays == [0.25, 0.5]


@pytest.mark.asyncio
async def test_auth_replay_uses_pinned_upload_not_file_changed_during_refresh(store, tmp_path):
    path = tmp_path / "image.png"
    original = b"\x89PNG\r\n\x1a\noriginal"
    replacement = b"\x89PNG\r\n\x1a\nchanged"
    path.write_bytes(original)
    seen = []

    def business(request):
        seen.append(request)
        assert original in request.content and replacement not in request.content
        return httpx.Response(200, json=auth_rejection() if len(seen) == 1 else {"error": "", "response": {}})

    def refresh(_):
        path.write_bytes(replacement)
        return rotated_response()

    with httpx.Client(transport=httpx.MockTransport(refresh)) as refresh_client:
        async with httpx.AsyncClient(transport=httpx.MockTransport(business)) as client:
            result = await Transport(store, client=client, refresh_client=refresh_client,
                                     upload_roots=[tmp_path], clock=lambda: 1000).execute(
                                         upload_endpoint(), {"image": str(path)})
    assert result["error"] == "" and len(seen) == 2


@pytest.mark.asyncio
async def test_binary_download_can_recover_from_json_auth_error(store):
    seen = []

    def business(request):
        seen.append(request)
        if len(seen) == 1:
            return httpx.Response(200, json=auth_rejection())
        return httpx.Response(200, headers={"Content-Type": "application/pdf"}, content=b"%PDF-1.7\nsynthetic")

    with httpx.Client(transport=httpx.MockTransport(lambda _: rotated_response())) as refresh_client:
        async with httpx.AsyncClient(transport=httpx.MockTransport(business)) as client:
            result = await Transport(store, client=client, refresh_client=refresh_client,
                                     clock=lambda: 1000).execute(binary_endpoint(), {})
    assert result["_binary"] == b"%PDF-1.7\nsynthetic" and len(seen) == 2


@pytest.mark.asyncio
async def test_public_request_never_uses_shop_refresh_even_on_token_error(store):
    seen = []

    def business(request):
        seen.append(request)
        assert "access_token" not in request.url.params
        return httpx.Response(200, json=auth_rejection())

    ep = synthetic_endpoint()
    ep["auth_strategy"] = "public"
    with httpx.Client(transport=httpx.MockTransport(lambda _: pytest.fail("public request must not refresh"))) as refresh_client:
        async with httpx.AsyncClient(transport=httpx.MockTransport(business)) as client:
            result = await Transport(store, client=client, refresh_client=refresh_client,
                                     clock=lambda: 1000).execute(ep, {})
    assert result == auth_rejection() and len(seen) == 1
