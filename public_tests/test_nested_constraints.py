"""Cross-field limits documented by kit and logistics endpoint snapshots."""
from copy import deepcopy

import pytest

from shopee_mcp.constraints import ConstraintViolation, enforce_constraint, validate_constraint_metadata
from shopee_mcp.validation import InputError, validate_arguments


def obj(properties):
    return {"type": "object", "properties": properties, "additionalProperties": False}


def array(items):
    return {"type": "array", "items": items}


SCHEMA = obj({
    "item_setting": obj({"model_list": array(obj({
        "component_list": array(obj({"main_component": {"type": "boolean"}})),
    }))}),
    "unpackaged_sku_requests": array(obj({"quantity": {"type": "string", "x-wire-int64": True}})),
    "from_date": {"type": "string"},
    "to_date": {"type": "string"},
})
COUNT = {"kind": "nested_value_count", "field": "item_setting.model_list",
         "nested_field": "component_list", "value_field": "main_component", "value": True, "maximum": 1}
SUM = {"kind": "nested_integer_sum_lte", "field": "unpackaged_sku_requests",
       "value_field": "quantity", "maximum": 600}
DATES = {"kind": "iso_date_order", "from": "from_date", "to": "to_date", "allow_equal": False}


def endpoint(*constraints):
    return {"input_schema": SCHEMA, "response_schema": obj({}), "constraints": list(constraints)}


@pytest.mark.parametrize("constraint", [COUNT, SUM, DATES])
def test_new_metadata_accepts_reviewed_schema_shapes(constraint):
    validate_constraint_metadata(constraint, SCHEMA)


@pytest.mark.parametrize("constraint,changes", [
    (COUNT, {"field": "item_setting..model_list"}),
    (COUNT, {"field": ".item_setting.model_list"}),
    (COUNT, {"field": "item_setting.model_list.component_list"}),
    (COUNT, {"field": "item_setting"}),
    (COUNT, {"nested_field": "missing"}),
    (COUNT, {"value_field": "missing"}),
    (COUNT, {"value": 1}),
    (COUNT, {"maximum": True}),
    (COUNT, {"maximum": -1}),
    (COUNT, {"extra": "ignored"}),
    (SUM, {"field": "item_setting.model_list"}),
    (SUM, {"value_field": "missing"}),
    (SUM, {"maximum": True}),
    (SUM, {"maximum": 0}),
    (DATES, {"from": "missing"}),
    (DATES, {"to": "from_date"}),
    (DATES, {"allow_equal": 1}),
    (DATES, {"maximum_days": 30}),
])
def test_new_metadata_rejects_malformed_and_schema_incompatible_bindings(constraint, changes):
    with pytest.raises(ValueError):
        validate_constraint_metadata({**constraint, **changes}, SCHEMA)


def test_kit_main_component_limit_aggregates_across_models():
    request = {"item_setting": {"model_list": [
        {"component_list": [{"main_component": True}, {"main_component": False}]},
        {"component_list": [{"main_component": False}]},
    ]}}
    validated, _ = validate_arguments(endpoint(COUNT), {"request": request}, "fixture")
    assert validated == request
    request["item_setting"]["model_list"][1]["component_list"][0]["main_component"] = True
    with pytest.raises(InputError, match="count"):
        validate_arguments(endpoint(COUNT), {"request": request}, "fixture")


@pytest.mark.parametrize("payload", [{}, {"item_setting": {}}, {"item_setting": {"model_list": []}},
                                      {"item_setting": {"model_list": [{"component_list": [{}]}]}}])
def test_optional_kit_update_paths_do_not_introduce_new_required_fields(payload):
    assert validate_arguments(endpoint(COUNT), {"request": payload}, "fixture")[0] == payload


def test_shipping_label_limit_sums_exact_wire_integers_instead_of_counting_rows():
    request = {"unpackaged_sku_requests": [{"quantity": "599"}, {"quantity": "1"}]}
    assert validate_arguments(endpoint(SUM), {"request": request}, "fixture")[0] == request
    request["unpackaged_sku_requests"][1]["quantity"] = "2"
    with pytest.raises(InputError, match="sum"):
        validate_arguments(endpoint(SUM), {"request": request}, "fixture")
    request["unpackaged_sku_requests"] = [{"quantity": "9223372036854775807"}]
    with pytest.raises(InputError, match="sum"):
        validate_arguments(endpoint(SUM), {"request": request}, "fixture")


@pytest.mark.parametrize("bad", [True, "1", -1])
def test_sum_rejects_invalid_wire_quantities_without_allowing_negative_offset(bad):
    with pytest.raises(ConstraintViolation):
        enforce_constraint(SUM, {"unpackaged_sku_requests": [{"quantity": 600}, {"quantity": bad}]})


def test_iso_date_order_supports_explicit_strictness_without_inventing_a_span_limit():
    enforce_constraint(DATES, {"from_date": "2020-02-29", "to_date": "2026-12-31"})
    with pytest.raises(ConstraintViolation):
        enforce_constraint(DATES, {"from_date": "2026-09-22", "to_date": "2026-09-22"})
    enforce_constraint({**DATES, "allow_equal": True}, {"from_date": "2026-09-22", "to_date": "2026-09-22"})


@pytest.mark.parametrize("start,end", [("2026-09-23", "2026-09-22"), ("2026-02-29", "2026-03-01"),
                                      ("2026-9-22", "2026-09-23"), ("2026-09-22", "2026-13-01")])
def test_iso_date_order_rejects_reversed_and_unreal_dates(start, end):
    with pytest.raises(ConstraintViolation):
        enforce_constraint(DATES, {"from_date": start, "to_date": end})


def test_nested_metadata_rejects_non_array_non_object_and_non_integer_fields():
    for constraint, path in [(COUNT, ("item_setting", "model_list")), (SUM, ("unpackaged_sku_requests",))]:
        schema = deepcopy(SCHEMA)
        properties = schema["properties"]
        for part in path[:-1]:
            properties = properties[part]["properties"]
        properties[path[-1]]["items"] = {"type": "string"}
        with pytest.raises(ValueError):
            validate_constraint_metadata(constraint, schema)
    schema = deepcopy(SCHEMA)
    schema["properties"]["unpackaged_sku_requests"]["items"]["properties"]["quantity"] = {"type": "number"}
    with pytest.raises(ValueError):
        validate_constraint_metadata(SUM, schema)
