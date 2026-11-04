"""Static operating-hour rules from v2.logistics.update_operating_hours."""
from copy import deepcopy

import pytest

from shopee_mcp.constraints import validate_constraint_metadata
from shopee_mcp.validation import InputError, validate_arguments


def obj(properties, required=()):
    return {"type": "object", "properties": properties, "required": list(required), "additionalProperties": False}


TIME = {"start_time": {"type": "string"}, "end_time": {"type": "string"}}
PERIOD = obj(TIME, TIME)
SPECIAL_DAY = obj({**TIME, "date": {"type": "string"}, "enable": {"type": "boolean"}},
                  ["date", "start_time", "end_time", "enable"])
SCHEMA = obj({
    "regular_operating_hour": obj({"monday": PERIOD, "public_holiday": PERIOD}),
    # The official request field is spelled thrusday.
    "instant_operating_hour": obj({"thrusday": PERIOD}),
    "shop_collection_operating_hour": obj({"sunday": PERIOD}),
    "special_operating_hour": obj({
        "start_date": {"type": "string"}, "end_date": {"type": "string"},
        "operating_hours": {"type": "array", "items": SPECIAL_DAY},
    }, ["start_date", "end_date", "operating_hours"]),
})
CONSTRAINT = {
    "kind": "logistics_operating_hours",
    "regular_fields": ["regular_operating_hour", "instant_operating_hour", "shop_collection_operating_hour"],
    "special_field": "special_operating_hour",
}
ENDPOINT = {"input_schema": SCHEMA, "response_schema": obj({}), "constraints": [CONSTRAINT]}


def validate(payload):
    return validate_arguments(ENDPOINT, {"request": payload}, "fixture")[0]


def day(date, **overrides):
    return {"date": date, "start_time": "09:00", "end_time": "18:30", "enable": True, **overrides}


def special(start="2026-09-22", end="2026-09-23", rows=None):
    return {"special_operating_hour": {"start_date": start, "end_date": end,
                                      "operating_hours": [day(start), day(end)] if rows is None else rows}}


def test_operating_metadata_accepts_documented_time_and_special_calendar_shapes():
    validate_constraint_metadata(CONSTRAINT, SCHEMA)


@pytest.mark.parametrize("changes", [
    {"regular_fields": []}, {"regular_fields": "regular_operating_hour"},
    {"regular_fields": ["regular_operating_hour", "regular_operating_hour"]},
    {"regular_fields": ["missing"]}, {"regular_fields": [{}]},
    {"special_field": "missing"}, {"special_field": "regular_operating_hour"},
    {"timezone": "GMT+8"},
])
def test_operating_metadata_rejects_malformed_bindings(changes):
    with pytest.raises(ValueError):
        validate_constraint_metadata({**CONSTRAINT, **changes}, SCHEMA)


@pytest.mark.parametrize("field", ["start_date", "end_date", "operating_hours"])
def test_operating_metadata_rejects_incompatible_special_schema(field):
    schema = deepcopy(SCHEMA)
    schema["properties"]["special_operating_hour"]["properties"][field] = {"type": "integer"}
    with pytest.raises(ValueError):
        validate_constraint_metadata(CONSTRAINT, schema)


def test_operating_metadata_rejects_incompatible_time_and_enabled_fields():
    schema = deepcopy(SCHEMA)
    schema["properties"]["regular_operating_hour"]["properties"]["monday"]["properties"]["end_time"] = {"type": "integer"}
    with pytest.raises(ValueError):
        validate_constraint_metadata(CONSTRAINT, schema)
    schema = deepcopy(SCHEMA)
    schema["properties"]["special_operating_hour"]["properties"]["operating_hours"]["items"]["properties"]["enable"] = {"type": "string"}
    with pytest.raises(ValueError):
        validate_constraint_metadata(CONSTRAINT, schema)


@pytest.mark.parametrize("target", ["period", "special", "day"])
def test_operating_metadata_requires_fields_used_for_cross_field_validation(target):
    schema = deepcopy(SCHEMA)
    if target == "period":
        node = schema["properties"]["regular_operating_hour"]["properties"]["monday"]
    elif target == "special":
        node = schema["properties"]["special_operating_hour"]
    else:
        node = schema["properties"]["special_operating_hour"]["properties"]["operating_hours"]["items"]
    node["required"] = []
    with pytest.raises(ValueError):
        validate_constraint_metadata(CONSTRAINT, schema)


@pytest.mark.parametrize("payload", [{}, {"regular_operating_hour": {}},
    {"regular_operating_hour": {"monday": {"start_time": "09:00", "end_time": "18:30"}}},
    {"instant_operating_hour": {"thrusday": {"start_time": "00:00", "end_time": "23:59"}}},
    {"shop_collection_operating_hour": {"sunday": {"start_time": "23:00", "end_time": "23:30"}}},
])
def test_regular_hours_allow_omitted_closed_days_half_hours_and_exact_all_day_exception(payload):
    assert validate(payload) == payload


@pytest.mark.parametrize("start,end", [("09:15", "18:30"), ("09:00", "18:15"), ("24:00", "24:30"),
    ("9:00", "18:30"), ("09:00", "09:00"), ("18:30", "09:00"), ("00:30", "23:59")])
def test_regular_hours_reject_non_half_hours_invalid_hours_reverse_equal_and_wrong_2359_exception(start, end):
    with pytest.raises(InputError):
        validate({"regular_operating_hour": {"monday": {"start_time": start, "end_time": end}}})


def test_special_hours_accept_complete_calendar_coverage_in_any_order():
    payload = special(rows=[day("2026-09-23", enable=False, start_time="00:00", end_time="00:00"),
                            day("2026-09-22", start_time="00:00", end_time="23:59")])
    assert validate(payload) == payload
    assert validate(special("2024-02-29", "2024-02-29", [day("2024-02-29")]))


def test_special_hours_accept_start_plus_30_days_but_not_plus_31():
    rows = [day(f"2026-01-{index:02}") for index in range(1, 32)]
    assert validate(special("2026-01-01", "2026-01-31", rows))
    with pytest.raises(InputError, match="range"):
        validate(special("2026-01-01", "2026-02-01", rows + [day("2026-02-01")]))


@pytest.mark.parametrize("payload", [
    special(rows=[day("2026-09-22")]),
    special(rows=[day("2026-09-22"), day("2026-09-22")]),
    special(rows=[day("2026-09-22"), day("2026-09-24")]),
    special(rows=[day("2026-09-22"), day("2026-09-23"), day("2026-09-24")]),
    special("2026-09-23", "2026-09-22"),
    special("2026-02-29", "2026-03-01"),
    special(rows=[day("2026-09-22"), day("2026-09-23", start_time="17:30", end_time="09:00")]),
    special(rows=[day("2026-09-22"), day("2026-09-23", enable=False, start_time="25:00")]),
])
def test_special_hours_reject_gaps_duplicates_outside_dates_invalid_calendar_and_invalid_times(payload):
    with pytest.raises(InputError):
        validate(payload)
