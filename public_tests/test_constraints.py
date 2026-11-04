import copy
from datetime import datetime, timezone

import pytest

from shopee_mcp.constraints import (
    ConstraintViolation,
    enforce_constraint,
    validate_constraint_metadata,
)
from shopee_mcp.validation import InputError, validate_arguments


SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "page_no": {"type": "integer", "minimum": 1},
        "page_size": {"type": "integer", "minimum": 1},
        "period_type": {
            "type": "string",
            "enum": ["Day", "Week", "Month", "Last7d", "Last30d"],
        },
        "start_date": {"type": "string", "pattern": "^[0-9]{8}$"},
        "end_date": {"type": "string", "pattern": "^[0-9]{8}$"},
        "ids": {"type": "string"},
    },
    "required": [],
}


@pytest.mark.parametrize(
    "constraint",
    [
        {"kind": "ordered_pair", "from": "page_no", "to": "page_size"},
        {"kind": "csv_ids", "field": "ids", "when": {}, "max_items": 20},
        {
            "kind": "integer_product_lte",
            "fields": ["page_no", "page_size"],
            "maximum": 10_000,
        },
        {
            "kind": "ams_calendar_range",
            "period_type": "period_type",
            "from": "start_date",
            "to": "end_date",
        },
    ],
)
def test_constraint_metadata_accepts_the_complete_supported_shapes(constraint):
    validate_constraint_metadata(constraint, SCHEMA)


@pytest.mark.parametrize(
    "constraint",
    [
        {"kind": "unknown"},
        {"kind": "ordered_pair", "from": "page_no", "to": "missing"},
        {"kind": "ordered_pair", "from": "page_no", "to": "page_size", "extra": 1},
        {"kind": "csv_ids", "field": "page_no", "when": {}, "max_items": 20},
        {"kind": "csv_ids", "field": "ids", "when": {"missing": 1}, "max_items": 20},
        {"kind": "csv_ids", "field": "ids", "when": {}, "max_items": True},
        {"kind": "integer_product_lte", "fields": ["page_no"], "maximum": 10_000},
        {"kind": "integer_product_lte", "fields": ["page_no", {}], "maximum": 10_000},
        {
            "kind": "integer_product_lte",
            "fields": ["page_no", "page_no"],
            "maximum": 10_000,
        },
        {
            "kind": "integer_product_lte",
            "fields": ["page_no", "ids"],
            "maximum": 10_000,
        },
        {
            "kind": "integer_product_lte",
            "fields": ["page_no", "page_size"],
            "maximum": 0,
        },
        {
            "kind": "ams_calendar_range",
            "period_type": "ids",
            "from": "start_date",
            "to": "end_date",
        },
        {
            "kind": "ams_calendar_range",
            "period_type": "period_type",
            "from": "page_no",
            "to": "end_date",
        },
    ],
)
def test_constraint_metadata_rejects_unsupported_or_ill_typed_shapes(constraint):
    with pytest.raises(ValueError):
        validate_constraint_metadata(constraint, SCHEMA)


def test_calendar_metadata_rejects_non_string_period_enum_with_value_error():
    schema = copy.deepcopy(SCHEMA)
    schema["properties"]["period_type"]["enum"] = [{}]
    with pytest.raises(ValueError):
        validate_constraint_metadata(
            {
                "kind": "ams_calendar_range",
                "period_type": "period_type",
                "from": "start_date",
                "to": "end_date",
            },
            schema,
        )


def test_integer_product_limit_accepts_boundary_and_rejects_excess():
    constraint = {
        "kind": "integer_product_lte",
        "fields": ["page_no", "page_size"],
        "maximum": 10_000,
    }

    enforce_constraint(constraint, {"page_no": 20, "page_size": 500})
    with pytest.raises(ConstraintViolation, match="product exceeds"):
        enforce_constraint(constraint, {"page_no": 21, "page_size": 500})


@pytest.mark.parametrize(
    ("period_type", "start", "end"),
    [
        ("Day", "20250819", "20250819"),
        ("Week", "20250817", "20250823"),
        ("Month", "20250201", "20250219"),
        ("Month", "20250201", "20250228"),
        ("Last7d", "20250813", "20250819"),
        ("Last30d", "20250721", "20250819"),
    ],
)
def test_ams_calendar_range_accepts_documented_static_rules(period_type, start, end):
    enforce_constraint(
        {
            "kind": "ams_calendar_range",
            "period_type": "period_type",
            "from": "start_date",
            "to": "end_date",
        },
        {"period_type": period_type, "start_date": start, "end_date": end},
    )


@pytest.mark.parametrize(
    ("period_type", "start", "end"),
    [
        ("Day", "20250818", "20250819"),
        ("Week", "20250818", "20250823"),
        ("Week", "20250817", "20250830"),
        ("Month", "20250202", "20250228"),
        ("Month", "20250201", "20250301"),
        ("Last7d", "20250812", "20250819"),
        ("Last30d", "20250801", "20250831"),
        ("Day", "20250229", "20250229"),
        ("Day", "2025-08-19", "2025-08-19"),
    ],
)
def test_ams_calendar_range_rejects_invalid_dates_and_misaligned_periods(
    period_type, start, end
):
    with pytest.raises(ConstraintViolation):
        enforce_constraint(
            {
                "kind": "ams_calendar_range",
                "period_type": "period_type",
                "from": "start_date",
                "to": "end_date",
            },
            {"period_type": period_type, "start_date": start, "end_date": end},
        )


def test_validation_integration_uses_constraint_module_without_exposing_values():
    endpoint = {
        "auth_strategy": "shop",
        "encoding": "query",
        "input_schema": SCHEMA,
        "response_schema": {"type": "object", "properties": {}},
        "constraints": [
            {
                "kind": "integer_product_lte",
                "fields": ["page_no", "page_size"],
                "maximum": 10_000,
            }
        ],
    }
    with pytest.raises(InputError, match="invalid_arguments: integer product exceeds limit"):
        validate_arguments(
            endpoint,
            {"request": {"page_no": 21, "page_size": 500}},
            "fixture",
        )


def test_ordered_pair_compares_decimal_int64_by_wire_value_and_returns_original_strings():
    int64 = {
        "type": "string",
        "pattern": "^(0|-?[1-9][0-9]*)$",
        "x-wire-int64": True,
    }
    endpoint = {
        "auth_strategy": "shop",
        "encoding": "json",
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {"start": int64, "end": int64},
            "required": ["start", "end"],
        },
        "response_schema": {"type": "object", "properties": {}},
        "constraints": [{"kind": "ordered_pair", "from": "start", "to": "end"}],
    }

    request, _ = validate_arguments(
        endpoint, {"request": {"start": "9", "end": "10"}}, "fixture"
    )
    assert request == {"start": "9", "end": "10"}
    with pytest.raises(InputError, match="time range is reversed"):
        validate_arguments(
            endpoint, {"request": {"start": "10", "end": "9"}}, "fixture"
        )


PRINCIPAL_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "start_date": {"type": "string"},
        "end_date": {"type": "string"},
        "timezone": {"type": "string", "enum": ["GMT+7", "GMT+8", "GMT-3"]},
        "granularity": {
            "type": "string",
            "enum": ["customize", "day", "week", "month", "quarter", "year"],
        },
        "shop_list": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "shop_id": {"type": "string", "x-wire-integer": True},
                    "currency": {"type": "string"},
                    "content_ids": {
                        "type": "array",
                        "items": {"type": "string", "x-wire-integer": True},
                    },
                },
                "required": ["shop_id"],
                "additionalProperties": False,
            },
        },
        "page_size": {"type": "string", "x-wire-int64": True},
        "cursor": {"type": "string", "x-wire-int64": True},
        "start_time": {"type": "string"},
        "end_time": {"type": "string"},
        "epoch_start": {"type": "string", "x-wire-int64": True},
        "epoch_end": {"type": "string", "x-wire-int64": True},
    },
    "required": [],
}


@pytest.mark.parametrize(
    "constraint",
    [
        {
            "kind": "principal_calendar_range",
            "granularity": "granularity",
            "timezone": "timezone",
            "from": "start_date",
            "to": "end_date",
        },
        {
            "kind": "unique_list_keys",
            "field": "shop_list",
            "keys": ["shop_id"],
        },
        {
            "kind": "unique_nested_values",
            "field": "shop_list",
            "value_field": "content_ids",
            "maximum": None,
        },
        {
            "kind": "consistent_list_value",
            "field": "shop_list",
            "key": "shop_id",
            "value": "currency",
            "default": "USD",
        },
        {
            "kind": "pagination_requires_empty_list",
            "field": "shop_list",
            "pagination_fields": ["page_size", "cursor"],
        },
        {
            "kind": "iso_date_range",
            "from": "start_time",
            "to": "end_time",
            "maximum_days": 90,
        },
        {
            "kind": "numeric_delta",
            "from": "epoch_start",
            "to": "epoch_end",
            "minimum": 86_400,
            "maximum": 7_948_800,
        },
    ],
)
def test_extended_constraint_metadata_accepts_supported_shapes(constraint):
    validate_constraint_metadata(constraint, PRINCIPAL_SCHEMA)


@pytest.mark.parametrize(
    "constraint",
    [
        {"kind": "unique_list_keys", "field": "start_date", "keys": ["shop_id"]},
        {"kind": "unique_list_keys", "field": "shop_list", "keys": ["missing"]},
        {"kind": "unique_list_keys", "field": "shop_list", "keys": ["content_ids"]},
        {
            "kind": "unique_nested_values",
            "field": "shop_list",
            "value_field": "currency",
            "maximum": 100,
        },
        {
            "kind": "consistent_list_value",
            "field": "shop_list",
            "key": "content_ids",
            "value": "currency",
            "default": "USD",
        },
        {
            "kind": "pagination_requires_empty_list",
            "field": "shop_list",
            "pagination_fields": ["missing"],
        },
        {
            "kind": "iso_date_range",
            "from": "start_time",
            "to": "end_time",
            "maximum_days": 0,
        },
        {
            "kind": "numeric_delta",
            "from": "start_date",
            "to": "epoch_end",
            "minimum": 1,
            "maximum": 2,
        },
        {
            "kind": "numeric_delta",
            "from": "epoch_start",
            "to": "epoch_end",
            "minimum": 3,
            "maximum": 2,
        },
    ],
)
def test_extended_constraint_metadata_rejects_bad_shapes(constraint):
    with pytest.raises(ValueError):
        validate_constraint_metadata(constraint, PRINCIPAL_SCHEMA)


@pytest.mark.parametrize(
    ("granularity", "start", "end"),
    [
        ("customize", "2025-03-01", "2026-03-01"),
        ("day", "2026-03-01", "2026-03-01"),
        ("week", "2026-03-01", "2026-03-07"),
        ("month", "2026-03-01", "2026-03-07"),
        ("quarter", "2026-01-01", "2026-03-07"),
        ("year", "2026-01-01", "2026-03-07"),
    ],
)
def test_principal_calendar_accepts_documented_ranges(granularity, start, end):
    enforce_constraint(
        {
            "kind": "principal_calendar_range",
            "granularity": "granularity",
            "timezone": "timezone",
            "from": "start_date",
            "to": "end_date",
        },
        {
            "granularity": granularity,
            "timezone": "GMT+8",
            "start_date": start,
            "end_date": end,
        },
        clock=lambda: datetime(2026, 3, 8, 0, 30, tzinfo=timezone.utc),
    )


@pytest.mark.parametrize(
    ("granularity", "start", "end"),
    [
        ("customize", "2025-02-28", "2026-03-01"),
        ("customize", "2024-03-06", "2024-03-06"),
        ("customize", "2025-03-01", "2026-03-02"),
        ("day", "2026-03-01", "2026-03-02"),
        ("week", "2026-03-02", "2026-03-07"),
        ("week", "2026-03-01", "2026-03-08"),
        ("month", "2026-03-02", "2026-03-07"),
        ("month", "2026-03-01", "2026-04-01"),
        ("quarter", "2026-02-01", "2026-03-07"),
        ("quarter", "2026-01-01", "2026-04-01"),
        ("year", "2026-02-01", "2026-03-07"),
        ("year", "2026-01-01", "2027-01-01"),
        ("day", "2026-02-29", "2026-02-29"),
    ],
)
def test_principal_calendar_rejects_out_of_window_or_misaligned_ranges(
    granularity, start, end
):
    with pytest.raises(ConstraintViolation):
        enforce_constraint(
            {
                "kind": "principal_calendar_range",
                "granularity": "granularity",
                "timezone": "timezone",
                "from": "start_date",
                "to": "end_date",
            },
            {
                "granularity": granularity,
                "timezone": "GMT+8",
                "start_date": start,
                "end_date": end,
            },
            clock=lambda: datetime(2026, 3, 8, 0, 30, tzinfo=timezone.utc),
        )


def test_principal_calendar_uses_requested_fixed_offset_and_clamps_leap_year():
    constraint = {
        "kind": "principal_calendar_range",
        "granularity": "granularity",
        "timezone": "timezone",
        "from": "start_date",
        "to": "end_date",
    }
    clock = lambda: datetime(2024, 3, 1, 2, 0, tzinfo=timezone.utc)
    enforce_constraint(
        constraint,
        {
            "granularity": "customize",
            "timezone": "GMT+8",
            "start_date": "2022-02-28",
            "end_date": "2023-02-28",
        },
        clock=clock,
    )
    with pytest.raises(ConstraintViolation):
        enforce_constraint(
            constraint,
            {
                "granularity": "customize",
                "timezone": "GMT+8",
                "start_date": "2022-02-27",
                "end_date": "2023-02-27",
            },
            clock=clock,
        )
    enforce_constraint(
        constraint,
        {
            "granularity": "day",
            "timezone": "GMT+8",
            "start_date": "2024-02-29",
            "end_date": "2024-02-29",
        },
        clock=clock,
    )
    with pytest.raises(ConstraintViolation):
        enforce_constraint(
            constraint,
            {
                "granularity": "day",
                "timezone": "GMT-3",
                "start_date": "2024-02-29",
                "end_date": "2024-02-29",
            },
            clock=clock,
        )


def test_validation_accepts_an_injected_clock_for_principal_ranges():
    endpoint = {
        "auth_strategy": "principal",
        "encoding": "json",
        "input_schema": PRINCIPAL_SCHEMA,
        "response_schema": {"type": "object", "properties": {}},
        "constraints": [{
            "kind": "principal_calendar_range",
            "granularity": "granularity",
            "timezone": "timezone",
            "from": "start_date",
            "to": "end_date",
        }],
    }
    request = {
        "granularity": "day",
        "timezone": "GMT+8",
        "start_date": "2026-03-07",
        "end_date": "2026-03-07",
    }
    validate_arguments(
        endpoint,
        {"request": request},
        "fixture",
        clock=lambda: datetime(2026, 3, 8, tzinfo=timezone.utc),
    )


def test_list_constraints_reject_duplicates_conflicts_totals_and_pagination():
    with pytest.raises(ConstraintViolation, match="duplicate list key"):
        enforce_constraint(
            {"kind": "unique_list_keys", "field": "shop_list", "keys": ["shop_id"]},
            {"shop_list": [{"shop_id": 1}, {"shop_id": 1}]},
        )
    with pytest.raises(ConstraintViolation, match="duplicate nested value"):
        enforce_constraint(
            {
                "kind": "unique_nested_values",
                "field": "shop_list",
                "value_field": "content_ids",
                "maximum": None,
            },
            {"shop_list": [{"content_ids": [1, 2]}, {"content_ids": [2, 3]}]},
        )
    with pytest.raises(ConstraintViolation, match="nested value limit"):
        enforce_constraint(
            {
                "kind": "unique_nested_values",
                "field": "shop_list",
                "value_field": "content_ids",
                "maximum": 3,
            },
            {"shop_list": [{"content_ids": [1, 2]}, {"content_ids": [3, 4]}]},
        )
    with pytest.raises(ConstraintViolation, match="conflicting list value"):
        enforce_constraint(
            {
                "kind": "consistent_list_value",
                "field": "shop_list",
                "key": "shop_id",
                "value": "currency",
                "default": "USD",
            },
            {"shop_list": [{"shop_id": 1}, {"shop_id": 1, "currency": "LOCAL"}]},
        )
    with pytest.raises(ConstraintViolation, match="pagination requires an empty target list"):
        enforce_constraint(
            {
                "kind": "pagination_requires_empty_list",
                "field": "shop_list",
                "pagination_fields": ["page_size", "cursor"],
            },
            {"shop_list": [{"shop_id": 1}], "cursor": 0},
        )


def test_list_constraints_accept_documented_duplicate_and_empty_cases():
    enforce_constraint(
        {
            "kind": "consistent_list_value",
            "field": "shop_list",
            "key": "shop_id",
            "value": "currency",
            "default": "USD",
        },
        {"shop_list": [{"shop_id": 1}, {"shop_id": 1, "currency": "USD"}]},
    )
    enforce_constraint(
        {
            "kind": "pagination_requires_empty_list",
            "field": "shop_list",
            "pagination_fields": ["page_size", "cursor"],
        },
        {"shop_list": [], "page_size": 100, "cursor": 0},
    )


def test_iso_date_range_uses_inclusive_90_day_limit():
    constraint = {
        "kind": "iso_date_range",
        "from": "start_time",
        "to": "end_time",
        "maximum_days": 90,
    }
    enforce_constraint(constraint, {"start_time": "2025-01-01", "end_time": "2025-03-31"})
    for request in (
        {"start_time": "2025-01-01", "end_time": "2025-04-01"},
        {"start_time": "2025-03-01", "end_time": "2025-02-28"},
        {"start_time": "2025-02-29", "end_time": "2025-03-01"},
    ):
        with pytest.raises(ConstraintViolation):
            enforce_constraint(constraint, request)


def test_numeric_delta_enforces_optional_wire_integer_bounds():
    constraint = {
        "kind": "numeric_delta",
        "from": "epoch_start",
        "to": "epoch_end",
        "minimum": 86_400,
        "maximum": 7_948_800,
    }
    enforce_constraint(constraint, {})
    enforce_constraint(constraint, {"epoch_start": 0, "epoch_end": 86_400})
    enforce_constraint(constraint, {"epoch_start": 0, "epoch_end": 7_948_800})
    for end in (86_399, 7_948_801):
        with pytest.raises(ConstraintViolation, match="numeric delta outside bounds"):
            enforce_constraint(constraint, {"epoch_start": 0, "epoch_end": end})


def test_video_period_end_metadata_and_calendar_alignment():
    schema = {
        "type": "object",
        "properties": {
            "period_type": {
                "type": "string",
                "enum": ["Day", "Week", "Month", "Last7d", "Last15d", "Last30d"],
            },
            "end_date": {"type": "string"},
        },
    }
    constraint = {
        "kind": "video_period_end",
        "period_type": "period_type",
        "end_date": "end_date",
    }
    validate_constraint_metadata(constraint, schema)
    for period, end_date in (
        ("Day", "2024-02-29"),
        ("Last7d", "2026-03-07"),
        ("Last15d", "2026-03-07"),
        ("Last30d", "2026-03-07"),
        ("Week", "2026-03-08"),
        ("Month", "2024-02-29"),
    ):
        enforce_constraint(
            constraint, {"period_type": period, "end_date": end_date}
        )
    for period, end_date in (
        ("Day", "2026-02-29"),
        ("Week", "2026-03-07"),
        ("Month", "2024-02-28"),
    ):
        with pytest.raises(ConstraintViolation):
            enforce_constraint(
                constraint, {"period_type": period, "end_date": end_date}
            )


@pytest.mark.parametrize(
    "schema",
    [
        {
            "type": "object",
            "properties": {
                "period_type": {"type": "string", "enum": ["Day", "Week"]},
                "end_date": {"type": "string"},
            },
        },
        {
            "type": "object",
            "properties": {
                "period_type": {
                    "type": "string",
                    "enum": ["Day", "Week", "Month", "Last7d", "Last15d", "Last30d"],
                },
                "end_date": {"type": "integer"},
            },
        },
    ],
)
def test_video_period_end_metadata_rejects_incompatible_fields(schema):
    with pytest.raises(ValueError):
        validate_constraint_metadata(
            {
                "kind": "video_period_end",
                "period_type": "period_type",
                "end_date": "end_date",
            },
            schema,
        )
