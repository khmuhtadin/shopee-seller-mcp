import json
import os
from pathlib import Path

import pytest

from shopee_mcp.catalog import Catalog, output_schema
from shopee_mcp.policy import Policy
from shopee_mcp.results import ArtifactStore, ResultError, build_result, redact
from jsonschema import validate


def ep():
    return Catalog().get("v2_ams_get_open_campaign_added_product", Policy("test"))


def response():
    return {"error": "", "request_id": "r1", "response": {
        "item_list": [{"item_id": 9223372036854775807, "campaign_id": 1, "item_name": "Synthetic"}],
        "has_more": True, "cursor": "next", "total_count": 100,
    }}


def test_redaction_keeps_business_code_state_but_removes_secrets_in_keys_values_urls():
    payload = {"code": "business-code", "state": "READY", "access_token": "remote-token",
               "message": "access-secret", "url": "https://test/?Sign=remote-sign", "access-secret": "value",
               "auth": {"code": "sensitive-code"}}
    got = redact(payload, {"access-secret"}, ["/auth/code"])
    assert got["code"] == "business-code" and got["state"] == "READY"
    for secret in ("remote-token", "access-secret", "remote-sign", "sensitive-code"):
        assert secret not in json.dumps(got)


def test_result_projects_fields_but_preserves_pagination_and_int64(tmp_path):
    result = build_result(ep(), response(), "test", "fixture", {"fields": ["item_list"]}, set(), ArtifactStore(tmp_path))
    assert result["data"]["item_list"][0]["item_id"] == "9223372036854775807"
    assert result["data"]["has_more"] is True
    assert result["data"]["cursor"] == "next"
    assert result["meta"]["partial"] is True
    validate(result, output_schema(ep()))


def test_oversized_output_is_complete_sanitized_artifact_not_truncated_json(tmp_path):
    store = ArtifactStore(tmp_path)
    raw = response()
    raw["response"]["item_list"][0]["item_name"] = "secret" * 200
    result = build_result(ep(), raw, "test", "fixture", {}, {"secret"}, store, inline_bytes=50)
    assert result["meta"]["partial"] is True
    artifact = result["data"]["artifact"]
    content, mime = store.read(artifact["uri"])
    saved = json.loads(content)
    assert mime == "application/json"
    assert len(saved["item_list"]) == 1
    assert saved["cursor"] == "next"
    assert "secret" not in content.decode()
    assert Path(artifact["path"]).stat().st_mode & 0o777 == 0o600
    validate(result, output_schema(ep()))


def test_resource_namespace_expiry_and_cross_session_access_fail_closed(tmp_path):
    first = ArtifactStore(tmp_path, clock=lambda: 1000, ttl=10)
    artifact = first.save(b"{}", "application/json")
    second = ArtifactStore(tmp_path, clock=lambda: 1000)
    with pytest.raises(ResultError):
        second.read(artifact["uri"])
    with pytest.raises(ResultError):
        first.read("file:///etc/passwd")
    first.clock = lambda: 1011
    with pytest.raises(ResultError):
        first.read(artifact["uri"])


def test_business_error_is_distinct_from_success_and_remote_message_is_safe(tmp_path):
    raw = {"error": "error_auth", "message": "denied secret https://test/?sign=remote", "request_id": "req"}
    result = build_result(ep(), raw, "test", "fixture", {}, {"secret"}, ArtifactStore(tmp_path))
    assert not result["ok"]
    assert result["error"]["kind"] == "shopee_error"
    assert result["meta"]["request_id"] == "req"
    assert "secret" not in json.dumps(result) and "remote" not in json.dumps(result)


def test_schema_drift_is_reported_without_dropping_new_fields(tmp_path):
    raw = response()
    raw["response"]["future_field"] = 7
    result = build_result(ep(), raw, "test", "fixture", {}, set(), ArtifactStore(tmp_path))
    assert result["data"]["future_field"] == 7
    assert "/future_field" in result["meta"]["unknown_fields"]
    raw["response"]["item_list"] = "wrong-type"
    with pytest.raises(ResultError, match="invalid_response"):
        build_result(ep(), raw, "test", "fixture", {}, set(), ArtifactStore(tmp_path))


def test_remote_json_cannot_impersonate_binary_download(tmp_path):
    raw = response()
    raw.update(_binary="untrusted", _mime_type="text/plain")
    result = build_result(ep(), raw, "test", "fixture", {}, set(), ArtifactStore(tmp_path))
    assert result["data"]["item_list"][0]["item_id"] == "9223372036854775807"


def test_error_metadata_cannot_bypass_size_limit(tmp_path):
    raw = {"error": "failed", "message": "x" * 10000, "request_id": "r1"}
    result = build_result(ep(), raw, "test", "fixture", {}, set(), ArtifactStore(tmp_path), inline_bytes=1000)
    assert len(json.dumps(result).encode()) < 1500
    assert result["meta"]["partial"]
    assert result["data"]["artifact"]["size"] > 10000


def test_expired_artifacts_are_reaped_after_process_restart_without_touching_unrelated_files(tmp_path):
    first = ArtifactStore(tmp_path, clock=lambda: 1000, ttl=10)
    expired = first.save(b"{}", "application/json")
    current = ArtifactStore(tmp_path, clock=lambda: 1005, ttl=10).save(b"[]", "application/json")
    unrelated = tmp_path / "keep.txt"
    unrelated.write_text("keep")
    ArtifactStore(tmp_path, clock=lambda: 1011)
    assert not Path(expired["path"]).exists()
    assert Path(current["path"]).exists()
    assert unrelated.read_text() == "keep"


def test_artifact_scavenger_does_not_follow_symlinks(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    protected = outside / ("1-" + "b" * 32)
    protected.write_bytes(b"protected")
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / ("session-" + "a" * 32)).symlink_to(outside, target_is_directory=True)
    ArtifactStore(artifacts, clock=lambda: 1000)
    assert protected.read_bytes() == b"protected"


def test_same_length_artifact_tampering_is_detected(tmp_path):
    store = ArtifactStore(tmp_path)
    artifact = store.save(b"safe", "text/plain")
    Path(artifact["path"]).write_bytes(b"evil")
    with pytest.raises(ResultError, match="changed"):
        store.read(artifact["uri"])


def test_artifact_store_rejects_untrusted_shared_directory(tmp_path):
    os.chmod(tmp_path, 0o777)
    try:
        with pytest.raises(ResultError):
            ArtifactStore(tmp_path).save(b"safe", "text/plain")
    finally:
        os.chmod(tmp_path, 0o700)
