"""Live response-shape regressions; no business requests or real credentials."""
import copy

import pytest
from jsonschema import validate

from shopee_mcp.catalog import Catalog, output_schema
from shopee_mcp.policy import Policy
from shopee_mcp.results import ArtifactStore, ResultError, build_result


@pytest.fixture
def endpoint():
    return Catalog().get("v2_product_get_item_list", Policy("test"))


@pytest.mark.parametrize("output", [{}, {"fields": ["item"]}])
def test_zero_matching_items_may_omit_item_array(endpoint, tmp_path, output):
    # Shopee's successful BANNED + REVIEWING response omits item entirely.
    payload = {"error": "", "request_id": "empty-list-fixture", "response": {
        "total_count": 0, "has_next_page": False, "next": "",
    }}
    original = copy.deepcopy(payload)
    result = build_result(endpoint, payload, "test", "fixture", output, set(), ArtifactStore(tmp_path))

    assert result["ok"] is True
    assert result["error"] is None
    assert result["data"] == {"total_count": 0, "has_next_page": False, "next": ""}
    assert result["meta"]["request_id"] == "empty-list-fixture"
    assert payload == original  # Do not invent arrays in the upstream response.
    validate(result, output_schema(endpoint))


def test_item_projection_preserves_live_and_legacy_pagination_fields(endpoint, tmp_path):
    payload = {"error": "", "response": {
        "item": [{"item_id": 9223372036854775807, "item_status": "NORMAL"}],
        "total_count": 200, "has_next_page": True, "next": "100", "next_offset": 100,
    }}
    result = build_result(endpoint, payload, "test", "fixture", {"fields": ["item"]},
                          set(), ArtifactStore(tmp_path))

    assert result["data"] == {
        "item": [{"item_id": "9223372036854775807", "item_status": "NORMAL"}],
        "total_count": 200, "has_next_page": True, "next": "100", "next_offset": 100,
    }
    validate(result, output_schema(endpoint))


@pytest.mark.parametrize("item", [None, {}, False, "", 0])
def test_present_item_still_requires_an_array(endpoint, tmp_path, item):
    payload = {"error": "", "response": {"item": item, "total_count": 0, "has_next_page": False}}
    with pytest.raises(ResultError, match="response schema mismatch"):
        build_result(endpoint, payload, "test", "fixture", {}, set(), ArtifactStore(tmp_path))


def test_empty_payload_without_pagination_is_not_success(endpoint, tmp_path):
    with pytest.raises(ResultError, match="response schema mismatch"):
        build_result(endpoint, {"error": "", "response": {}}, "test", "fixture", {},
                     set(), ArtifactStore(tmp_path))


@pytest.fixture(params=[
    "v2_ams_get_open_campaign_added_product",
    "v2_ams_get_open_campaign_not_added_product",
])
def ams_endpoint(request):
    return Catalog().get(request.param, Policy("test"))


def test_ams_array_is_not_required_by_official_contract(ams_endpoint, tmp_path):
    # Preventive, documentation-based correction; not a recorded live AMS response.
    response = {"total_count": 0, "has_more": False, "cursor": ""}
    result = build_result(ams_endpoint, {"error": "", "response": response},
                          "test", "fixture", {"fields": ["item_list"]}, set(),
                          ArtifactStore(tmp_path))
    assert result["data"] == response
    assert result["ok"] is True
    validate(result, output_schema(ams_endpoint))


@pytest.mark.parametrize("item_list", [None, {}, False, "", 0])
def test_ams_present_array_remains_validated(ams_endpoint, tmp_path, item_list):
    response = {"total_count": 0, "has_more": False, "cursor": "", "item_list": item_list}
    with pytest.raises(ResultError, match="response schema mismatch"):
        build_result(ams_endpoint, {"error": "", "response": response},
                     "test", "fixture", {}, set(), ArtifactStore(tmp_path))


@pytest.mark.parametrize("missing_field", ["has_more", "cursor"])
def test_ams_pagination_requirements_remain(ams_endpoint, tmp_path, missing_field):
    response = {"total_count": 0, "has_more": False, "cursor": "", "item_list": []}
    del response[missing_field]
    with pytest.raises(ResultError, match="response schema mismatch"):
        build_result(ams_endpoint, {"error": "", "response": response},
                     "test", "fixture", {}, set(), ArtifactStore(tmp_path))
