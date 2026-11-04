"""Distinguish documented business IDs from context-controlled auth query IDs."""
from copy import deepcopy

import httpx
import pytest

from shopee_mcp.catalog import Catalog, CatalogError
from shopee_mcp.credentials import CredentialStore
from shopee_mcp.policy import Policy
from shopee_mcp.transport import Transport, serialize_request
from shopee_mcp.validation import InputError, parameter_aliases, validate_arguments
from test_auth_scope_expansion import scope_env


def endpoint(encoding="query", scope="merchant"):
    item = deepcopy(Catalog().get("v2_shop_get_shop_info", Policy("fixture")))
    item.update(encoding=encoding, auth_strategy=scope,
                parameter_aliases={"target_shop_id": "shop_id"},
                input_schema={"type": "object", "additionalProperties": False,
                              "required": ["target_shop_id"],
                              "properties": {"target_shop_id": {"type": "string", "x-wire-integer": True,
                                                                "pattern": "^(0|[1-9][0-9]*)$"}}})
    return item


@pytest.mark.parametrize("encoding,expected", [
    ("query", {"params": [("shop_id", "9223372036854775807")]}),
    ("json", {"json": {"shop_id": 9223372036854775807}}),
])
def test_explicit_business_id_alias_is_lossless_and_not_sent_under_model_name(encoding, expected):
    item = endpoint(encoding)
    Catalog()._validate_endpoint(item)
    request, _ = validate_arguments(item, {"request": {"target_shop_id": "9223372036854775807"}}, "fixture")
    assert serialize_request(item, request) == expected
    for field in ("shop_id", "merchant_id", "principal_id", "supplier_id", "user_id", "partner_id", "access_token", "sign"):
        with pytest.raises(InputError):
            validate_arguments(item, {"request": {"target_shop_id": "42", field: "injected"}}, "fixture")


@pytest.mark.parametrize("changes", [
    {"parameter_aliases": {"target_shop_id": "access_token"}},
    {"parameter_aliases": {"missing": "shop_id"}},
    {"parameter_aliases": {"target_shop_id": "partner_id"}},
    {"parameter_aliases": {"target_shop_id": "../shop_id"}},
    {"parameter_aliases": []},
    {"auth_strategy": "shop"},
])
def test_invalid_or_auth_colliding_alias_is_rejected_by_catalog_and_serializer(changes):
    item = endpoint()
    item.update(changes)
    with pytest.raises(CatalogError):
        Catalog()._validate_endpoint(item)
    with pytest.raises(InputError):
        serialize_request(item, {"target_shop_id": "42"})


def test_duplicate_wire_field_cannot_be_silently_overwritten():
    item = endpoint()
    item["input_schema"]["properties"]["shop_id"] = {"type": "integer"}
    with pytest.raises(CatalogError):
        Catalog()._validate_endpoint(item)
    with pytest.raises(InputError):
        serialize_request(item, {"target_shop_id": "42", "shop_id": 99})


@pytest.mark.asyncio
async def test_same_named_body_business_id_does_not_override_auth_query_id(tmp_path):
    path = tmp_path / ".env"
    scope_env(path)
    store = CredentialStore(path, clock=lambda: 0)
    item = endpoint("json", "shop")
    Catalog()._validate_endpoint(item)
    seen = []

    def handler(request):
        seen.append(request)
        assert request.url.params["shop_id"] == "987654"
        assert request.content == b'{"shop_id":42}'
        return httpx.Response(200, json={"error": "", "response": {}})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        await Transport(store, client=client, clock=lambda: 0).execute(item, {"target_shop_id": "42"})
    assert len(seen) == 1


@pytest.mark.parametrize("field", ("supplier_id", "user_id", "principal_id"))
def test_new_auth_subject_names_are_reserved_without_reviewed_alias(field):
    item = endpoint("json")
    item.pop("parameter_aliases")
    item["input_schema"]["properties"][field] = {"type": "string"}
    with pytest.raises(CatalogError):
        Catalog()._validate_endpoint(item)
    with pytest.raises(InputError):
        serialize_request(item, {field: "42"})


def test_binary_endpoint_with_query_request_cannot_alias_over_auth_subject():
    item = {
        "encoding": "binary",
        "binary_request_encoding": "query",
        "auth_strategy": "shop",
        "parameter_aliases": {"target_shop_id": "shop_id"},
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["target_shop_id"],
            "properties": {"target_shop_id": {"type": "string"}},
        },
    }

    with pytest.raises(InputError, match="authentication-colliding"):
        parameter_aliases(item)
