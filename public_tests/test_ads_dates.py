"""Static Ads calendar contracts; server-relative dates need a source timezone."""
from copy import deepcopy

import pytest

from shopee_mcp.constraints import ConstraintViolation, enforce_constraint, validate_constraint_metadata
from shopee_mcp.validation import InputError, validate_arguments

SCHEMA = {"type": "object", "properties": {"start_date": {"type": "string"}, "end_date": {"type": "string"}, "performance_date": {"type": "string"}}, "additionalProperties": False}
DATE = {"kind": "ads_date", "field": "performance_date"}
RANGE = {"kind": "ads_date_range", "from": "start_date", "to": "end_date", "allow_equal": False, "allow_empty_end": False, "maximum_months": 1}


@pytest.mark.parametrize("constraint", [DATE, RANGE, {**RANGE, "allow_empty_end": True, "allow_equal": True, "maximum_months": None}, {**RANGE, "maximum_months": 3}])
def test_reviewed_ads_date_metadata(constraint):
    validate_constraint_metadata(constraint, SCHEMA)


@pytest.mark.parametrize("constraint,changes", [(DATE, {"field": "missing"}), (DATE, {"field": []}), (DATE, {"maximum_days": 30}),
    (RANGE, {"from": "end_date"}), (RANGE, {"from": "missing"}), (RANGE, {"to": []}),
    (RANGE, {"allow_equal": 1}), (RANGE, {"allow_empty_end": 0}), (RANGE, {"maximum_months": 0}),
    (RANGE, {"maximum_months": -1}), (RANGE, {"maximum_months": True}), (RANGE, {"maximum_months": 1.0}),
    (RANGE, {"maximum_days": 30})])
def test_malformed_ads_date_metadata(constraint, changes):
    with pytest.raises(ValueError):
        validate_constraint_metadata({**constraint, **changes}, SCHEMA)


@pytest.mark.parametrize("constraint,field", [(DATE, "performance_date"), (RANGE, "start_date"), (RANGE, "end_date")])
def test_date_metadata_requires_string_fields(constraint, field):
    schema = deepcopy(SCHEMA)
    schema["properties"][field] = {"type": "integer"}
    with pytest.raises(ValueError):
        validate_constraint_metadata(constraint, schema)


@pytest.mark.parametrize("value", ["29-02-2024", "01-01-0001", "31-12-9999"])
def test_single_date_accepts_real_dd_mm_yyyy(value):
    enforce_constraint(DATE, {"performance_date": value})


@pytest.mark.parametrize("value", ["29-02-2023", "31-04-2026", "00-01-2026", "01-13-2026", "01-01-0000", "1-01-2026", "01-1-2026", "2026-01-01", " 01-01-2026", "01-01-2026\n", "０１-０１-２０２６", "", None, 123])
def test_single_date_rejects_impossible_and_noncanonical_input(value):
    with pytest.raises(ConstraintViolation):
        enforce_constraint(DATE, {"performance_date": value})


@pytest.mark.parametrize("start,end,months,valid", [
    ("31-01-2024", "29-02-2024", 1, True), ("31-01-2024", "01-03-2024", 1, False),
    ("31-01-2023", "28-02-2023", 1, True), ("31-01-2023", "01-03-2023", 1, False),
    ("31-12-2025", "31-01-2026", 1, True), ("31-01-2026", "30-04-2026", 3, True),
    ("31-01-2026", "01-05-2026", 3, False), ("30-11-2023", "29-02-2024", 3, True),
    ("31-10-9999", "31-12-9999", 3, True),
])
def test_calendar_month_boundaries_are_not_fixed_day_counts(start, end, months, valid):
    constraint = {**RANGE, "maximum_months": months}
    request = {"start_date": start, "end_date": end}
    if valid:
        enforce_constraint(constraint, request)
    else:
        with pytest.raises(ConstraintViolation):
            enforce_constraint(constraint, request)


def test_dates_are_ordered_chronologically_not_lexically():
    enforce_constraint(RANGE, {"start_date": "31-01-2026", "end_date": "01-02-2026"})
    with pytest.raises(ConstraintViolation):
        enforce_constraint(RANGE, {"start_date": "01-02-2026", "end_date": "31-01-2026"})
    with pytest.raises(ConstraintViolation):
        enforce_constraint(RANGE, {"start_date": "01-02-2026", "end_date": "01-02-2026"})
    enforce_constraint({**RANGE, "allow_equal": True}, {"start_date": "01-02-2026", "end_date": "01-02-2026"})


def test_optional_fields_and_unlimited_end_do_not_create_required_inputs():
    campaign = {**RANGE, "allow_equal": True, "allow_empty_end": True, "maximum_months": None}
    for request in ({}, {"start_date": "31-01-2026"}, {"end_date": "01-02-2026"}, {"start_date": "31-01-2026", "end_date": ""}, {"start_date": "01-01-0001", "end_date": "31-12-9999"}):
        enforce_constraint(campaign, request)
    for request in ({"start_date": "31-02-2026"}, {"end_date": "31-02-2026"}, {"start_date": "", "end_date": ""}):
        with pytest.raises(ConstraintViolation):
            enforce_constraint(campaign, request)
    with pytest.raises(ConstraintViolation):
        enforce_constraint(RANGE, {"start_date": "01-02-2026", "end_date": ""})
    enforce_constraint(DATE, {})


def test_local_validation_uses_static_rules_and_does_not_consult_clock():
    def forbidden_clock():
        raise AssertionError("Source does not specify shop timezone")
    item = {"input_schema": SCHEMA, "response_schema": {"type": "object", "properties": {}}, "constraints": [RANGE]}
    request = {"start_date": "01-01-2000", "end_date": "02-01-2000"}
    assert validate_arguments(item, {"request": request}, "fixture", clock=forbidden_clock)[0] == request
    with pytest.raises(InputError, match="invalid_arguments"):
        validate_arguments(item, {"request": {"start_date": "31-02-2000"}}, "fixture", clock=forbidden_clock)
