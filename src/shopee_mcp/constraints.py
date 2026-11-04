"""Catalog constraint metadata validation and request-time enforcement."""

from __future__ import annotations

from calendar import monthrange
from datetime import datetime, timedelta, timezone
import re

from jsonschema import Draft202012Validator


AMS_PERIODS = {"Day", "Week", "Month", "Last7d", "Last30d"}
PRINCIPAL_GRANULARITIES = {"customize", "day", "week", "month", "quarter", "year"}
PRINCIPAL_TIMEZONES = {"GMT+7": 7, "GMT+8": 8, "GMT-3": -3}
VIDEO_PERIODS = {"Day", "Week", "Month", "Last7d", "Last15d", "Last30d"}


class ConstraintViolation(ValueError):
    """A request violates reviewed endpoint constraint metadata."""


def _exact_keys(constraint, expected):
    if not isinstance(constraint, dict) or set(constraint) != expected:
        raise ValueError("Invalid constraint metadata shape")


def _properties(schema):
    if not isinstance(schema, dict) or schema.get("type") != "object":
        raise ValueError("Constraint schema must be an object")
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        raise ValueError("Constraint schema must define properties")
    return properties


def _field(properties, name):
    if not isinstance(name, str) or name not in properties:
        raise ValueError("Constraint references an unknown field")
    field = properties[name]
    if not isinstance(field, dict):
        raise ValueError("Constraint field schema must be an object")
    return field


def _array_object_properties(properties, name):
    field = _field(properties, name)
    items = field.get("items")
    if field.get("type") != "array" or not isinstance(items, dict) or items.get("type") != "object":
        raise ValueError("Constraint field must be an array of objects")
    item_properties = items.get("properties")
    if not isinstance(item_properties, dict):
        raise ValueError("Constraint array items must define properties")
    return field, item_properties


def _path_parts(path):
    if not isinstance(path, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*", path):
        raise ValueError("Constraint path must contain named object fields")
    return path.split(".")


def _path_schema(schema, path):
    for part in _path_parts(path):
        schema = _field(_properties(schema), part)
    return schema


def _path_array_items(schema, path):
    field = _path_schema(schema, path)
    items = field.get("items")
    if field.get("type") != "array" or not isinstance(items, dict):
        raise ValueError("Constraint path must name an array of objects")
    _properties(items)
    return items


_MISSING = object()


def _path_value(value, path):
    for part in _path_parts(path):
        if not isinstance(value, dict):
            raise ConstraintViolation("constraint path contains a non-object")
        if part not in value:
            return _MISSING
        value = value[part]
    return value


def _integer_like(field):
    return field.get("type") == "integer" or (
        field.get("type") == "string"
        and (field.get("x-wire-int64") or field.get("x-wire-integer") or field.get("x-wire-uint64"))
    )


def _scalar(field):
    return field.get("type") in {"string", "integer", "number", "boolean"}


def _time_period_schema(schema):
    properties = _properties(schema)
    if (not {"start_time", "end_time"} <= set(schema.get("required", []))
            or any(_field(properties, name).get("type") != "string" for name in ("start_time", "end_time"))):
        raise ValueError("Operating times must be required strings")


def validate_constraint_metadata(constraint, schema):
    """Reject malformed or schema-incompatible catalog constraint metadata."""
    properties = _properties(schema)
    if not isinstance(constraint, dict):
        raise ValueError("Constraint metadata must be an object")
    kind = constraint.get("kind")

    if kind == "ads_date":
        _exact_keys(constraint, {"kind", "field"})
        if _field(properties, constraint["field"]).get("type") != "string":
            raise ValueError("Ads date must refer to a string field")
        return

    if kind == "ads_date_range":
        _exact_keys(constraint, {"kind", "from", "to", "allow_equal", "allow_empty_end", "maximum_months"})
        low = _field(properties, constraint["from"])
        high = _field(properties, constraint["to"])
        maximum = constraint["maximum_months"]
        if (constraint["from"] == constraint["to"]
                or low.get("type") != "string" or high.get("type") != "string"
                or type(constraint["allow_equal"]) is not bool
                or type(constraint["allow_empty_end"]) is not bool
                or (maximum is not None and (type(maximum) is not int or maximum <= 0))):
            raise ValueError("Invalid Ads date range metadata")
        return

    if kind == "ordered_pair":
        _exact_keys(constraint, {"kind", "from", "to"})
        low = _field(properties, constraint["from"])
        high = _field(properties, constraint["to"])
        if constraint["from"] == constraint["to"] or low.get("type") != high.get("type"):
            raise ValueError("Ordered pair fields must be distinct and share a type")
        if low.get("type") not in {"integer", "number", "string"}:
            raise ValueError("Ordered pair fields are not comparable")
        return

    if kind == "csv_ids":
        _exact_keys(constraint, {"kind", "field", "when", "max_items"})
        field = _field(properties, constraint["field"])
        if field.get("type") != "string":
            raise ValueError("CSV identifier field must be a string")
        when = constraint["when"]
        if not isinstance(when, dict):
            raise ValueError("CSV condition must be an object")
        for name, value in when.items():
            condition = _field(properties, name)
            if not Draft202012Validator(condition).is_valid(value):
                raise ValueError("CSV condition value does not match its field schema")
        maximum = constraint["max_items"]
        if type(maximum) is not int or maximum <= 0:
            raise ValueError("CSV maximum must be a positive integer")
        return

    if kind == "integer_product_lte":
        _exact_keys(constraint, {"kind", "fields", "maximum"})
        fields = constraint["fields"]
        if (
            not isinstance(fields, list)
            or len(fields) < 2
            or any(not isinstance(name, str) for name in fields)
            or len(fields) != len(set(fields))
        ):
            raise ValueError("Integer product requires distinct fields")
        if any(_field(properties, name).get("type") != "integer" for name in fields):
            raise ValueError("Integer product fields must be integers")
        maximum = constraint["maximum"]
        if type(maximum) is not int or maximum <= 0:
            raise ValueError("Integer product maximum must be a positive integer")
        return

    if kind == "ams_calendar_range":
        _exact_keys(constraint, {"kind", "period_type", "from", "to"})
        period = _field(properties, constraint["period_type"])
        low = _field(properties, constraint["from"])
        high = _field(properties, constraint["to"])
        period_enum = period.get("enum")
        if (
            len({constraint["period_type"], constraint["from"], constraint["to"]}) != 3
            or period.get("type") != "string"
            or not isinstance(period_enum, list)
            or any(not isinstance(value, str) for value in period_enum)
            or set(period_enum) != AMS_PERIODS
            or low.get("type") != "string"
            or high.get("type") != "string"
        ):
            raise ValueError("Invalid AMS calendar fields")
        return

    if kind == "principal_calendar_range":
        _exact_keys(constraint, {"kind", "granularity", "timezone", "from", "to"})
        names = [constraint[name] for name in ("granularity", "timezone", "from", "to")]
        if len(names) != len(set(names)):
            raise ValueError("Principal calendar fields must be distinct")
        granularity = _field(properties, constraint["granularity"])
        zone = _field(properties, constraint["timezone"])
        low = _field(properties, constraint["from"])
        high = _field(properties, constraint["to"])
        if (
            granularity.get("type") != "string"
            or set(granularity.get("enum", [])) != PRINCIPAL_GRANULARITIES
            or zone.get("type") != "string"
            or set(zone.get("enum", [])) != set(PRINCIPAL_TIMEZONES)
            or low.get("type") != "string"
            or high.get("type") != "string"
        ):
            raise ValueError("Invalid principal calendar fields")
        return

    if kind == "unique_list_keys":
        _exact_keys(constraint, {"kind", "field", "keys"})
        _, item_properties = _array_object_properties(properties, constraint["field"])
        keys = constraint["keys"]
        if (
            not isinstance(keys, list)
            or not keys
            or any(
                not isinstance(name, str)
                or name not in item_properties
                or not _scalar(item_properties[name])
                for name in keys
            )
            or len(keys) != len(set(keys))
        ):
            raise ValueError("Unique list keys must name distinct item fields")
        return

    if kind == "unique_nested_values":
        _exact_keys(constraint, {"kind", "field", "value_field", "maximum"})
        _, item_properties = _array_object_properties(properties, constraint["field"])
        value_field = constraint["value_field"]
        nested = item_properties.get(value_field) if isinstance(value_field, str) else None
        if (
            not isinstance(nested, dict)
            or nested.get("type") != "array"
            or not isinstance(nested.get("items"), dict)
            or not _scalar(nested["items"])
        ):
            raise ValueError("Nested unique field must be an array")
        maximum = constraint["maximum"]
        if maximum is not None and (type(maximum) is not int or maximum <= 0):
            raise ValueError("Nested value maximum must be null or positive")
        return

    if kind == "consistent_list_value":
        _exact_keys(constraint, {"kind", "field", "key", "value", "default"})
        _, item_properties = _array_object_properties(properties, constraint["field"])
        key = constraint["key"]
        value = constraint["value"]
        if (
            not isinstance(key, str)
            or not isinstance(value, str)
            or key == value
            or key not in item_properties
            or value not in item_properties
            or not _scalar(item_properties[key])
            or not _scalar(item_properties[value])
            or not Draft202012Validator(item_properties[value]).is_valid(constraint["default"])
        ):
            raise ValueError("Invalid consistent list value fields")
        return

    if kind == "pagination_requires_empty_list":
        _exact_keys(constraint, {"kind", "field", "pagination_fields"})
        field = _field(properties, constraint["field"])
        fields = constraint["pagination_fields"]
        if (
            field.get("type") != "array"
            or not isinstance(fields, list)
            or not fields
            or any(not isinstance(name, str) or name not in properties for name in fields)
            or len(fields) != len(set(fields))
        ):
            raise ValueError("Invalid conditional pagination fields")
        return

    if kind == "conditional_iso_date_delta":
        _exact_keys(constraint, {"kind", "from", "to", "when", "minimum_days", "maximum_days"})
        low = _field(properties, constraint["from"])
        high = _field(properties, constraint["to"])
        when = constraint["when"]
        if (constraint["from"] == constraint["to"] or low.get("type") != "string"
                or high.get("type") != "string" or not isinstance(when, dict) or not when
                or type(constraint["minimum_days"]) is not int or type(constraint["maximum_days"]) is not int
                or not 0 <= constraint["minimum_days"] <= constraint["maximum_days"]):
            raise ValueError("Invalid conditional ISO date difference")
        for name, value in when.items():
            if not Draft202012Validator(_field(properties, name)).is_valid(value):
                raise ValueError("Invalid date condition")
        return

    if kind == "iso_date_range":
        _exact_keys(constraint, {"kind", "from", "to", "maximum_days"})
        low = _field(properties, constraint["from"])
        high = _field(properties, constraint["to"])
        maximum = constraint["maximum_days"]
        if (
            constraint["from"] == constraint["to"]
            or low.get("type") != "string"
            or high.get("type") != "string"
            or type(maximum) is not int
            or maximum <= 0
        ):
            raise ValueError("Invalid ISO date range fields")
        return

    if kind == "numeric_delta":
        _exact_keys(constraint, {"kind", "from", "to", "minimum", "maximum"})
        low = _field(properties, constraint["from"])
        high = _field(properties, constraint["to"])
        minimum = constraint["minimum"]
        maximum = constraint["maximum"]
        if (
            constraint["from"] == constraint["to"]
            or not _integer_like(low)
            or not _integer_like(high)
            or type(minimum) is not int
            or type(maximum) is not int
            or minimum < 0
            or maximum < minimum
        ):
            raise ValueError("Invalid numeric delta fields")
        return

    if kind == "video_period_end":
        _exact_keys(constraint, {"kind", "period_type", "end_date"})
        period = _field(properties, constraint["period_type"])
        end = _field(properties, constraint["end_date"])
        if (
            constraint["period_type"] == constraint["end_date"]
            or period.get("type") != "string"
            or set(period.get("enum", [])) != VIDEO_PERIODS
            or end.get("type") != "string"
        ):
            raise ValueError("Invalid video period end fields")
        return

    if kind == "nested_value_count":
        _exact_keys(constraint, {"kind", "field", "nested_field", "value_field", "value", "maximum"})
        items = _path_array_items(schema, constraint["field"])
        nested_items = _path_array_items(items, constraint["nested_field"])
        value = _path_schema(nested_items, constraint["value_field"])
        if (not _scalar(value)
                or any(value.get(flag) for flag in ("x-wire-int64", "x-wire-integer", "x-wire-uint64"))
                or not Draft202012Validator(value).is_valid(constraint["value"])
                or type(constraint["maximum"]) is not int or constraint["maximum"] < 0):
            raise ValueError("Invalid nested value count metadata")
        return

    if kind == "nested_integer_sum_lte":
        _exact_keys(constraint, {"kind", "field", "value_field", "maximum"})
        items = _path_array_items(schema, constraint["field"])
        value = _path_schema(items, constraint["value_field"])
        if (not _integer_like(value) or type(constraint["maximum"]) is not int
                or constraint["maximum"] <= 0):
            raise ValueError("Invalid nested integer sum metadata")
        return

    if kind == "iso_date_order":
        _exact_keys(constraint, {"kind", "from", "to", "allow_equal"})
        low = _path_schema(schema, constraint["from"])
        high = _path_schema(schema, constraint["to"])
        if (constraint["from"] == constraint["to"] or low.get("type") != "string"
                or high.get("type") != "string" or type(constraint["allow_equal"]) is not bool):
            raise ValueError("Invalid ISO date order metadata")
        return

    if kind == "logistics_operating_hours":
        _exact_keys(constraint, {"kind", "regular_fields", "special_field"})
        regular = constraint["regular_fields"]
        special = constraint["special_field"]
        if (not isinstance(regular, list) or not regular
                or any(not isinstance(name, str) for name in regular)
                or len(set(regular)) != len(regular) or special in regular):
            raise ValueError("Invalid regular operating-hour fields")
        for name in regular:
            periods = _properties(_path_schema(schema, name))
            if not periods:
                raise ValueError("Operating hours must declare day fields")
            for period in periods.values():
                _time_period_schema(period)
        special_schema = _path_schema(schema, special)
        special_properties = _properties(special_schema)
        if not {"start_date", "end_date", "operating_hours"} <= set(special_schema.get("required", [])):
            raise ValueError("Special operating dates and hours must be required")
        for name in ("start_date", "end_date"):
            if _field(special_properties, name).get("type") != "string":
                raise ValueError("Special operating dates must be strings")
        day = _path_array_items(special_schema, "operating_hours")
        _time_period_schema(day)
        if (not {"date", "enable"} <= set(day.get("required", []))
                or _field(_properties(day), "date").get("type") != "string"
                or _field(_properties(day), "enable").get("type") != "boolean"):
            raise ValueError("Invalid special operating-day fields")
        return

    raise ValueError("Unsupported constraint kind")


def _ads_date(value):
    if type(value) is not str or not re.fullmatch(r"[0-9]{2}-[0-9]{2}-[0-9]{4}", value):
        raise ConstraintViolation("Ads date must use DD-MM-YYYY")
    try:
        return datetime.strptime(value, "%d-%m-%Y").date()
    except ValueError:
        raise ConstraintViolation("Ads date is not a real calendar date") from None


def _calendar_date(value):
    if type(value) is not str or not re.fullmatch(r"[0-9]{8}", value):
        raise ConstraintViolation("AMS date must use YYYYMMDD")
    try:
        return datetime.strptime(value, "%Y%m%d").date()
    except ValueError:
        raise ConstraintViolation("AMS date is not a real calendar date") from None


def _iso_date(value):
    if type(value) is not str or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value):
        raise ConstraintViolation("date must use YYYY-MM-DD")
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError:
        raise ConstraintViolation("date is not a real calendar date") from None


def _subtract_years(value, years):
    year = value.year - years
    return value.replace(year=year, day=min(value.day, monthrange(year, value.month)[1]))


def _operating_period(period, *, enabled=True):
    start, end = period["start_time"], period["end_time"]
    half_hour = r"(?:[01][0-9]|2[0-3]):(?:00|30)"
    if (not isinstance(start, str) or not re.fullmatch(half_hour, start)
            or not isinstance(end, str)
            or not (re.fullmatch(half_hour, end) or (start == "00:00" and end == "23:59"))):
        raise ConstraintViolation("operating time must use half hours or the full-day exception")
    if enabled and start >= end:
        raise ConstraintViolation("operating time range must start before it ends")


def enforce_constraint(constraint, request, *, clock=None):
    """Enforce one already metadata-validated constraint against a request."""
    kind = constraint.get("kind")
    if kind == "ads_date":
        if constraint["field"] in request:
            _ads_date(request[constraint["field"]])
        return

    if kind == "ads_date_range":
        low, high = constraint["from"], constraint["to"]
        start = _ads_date(request[low]) if low in request else None
        end = None
        if high in request and not (constraint["allow_empty_end"] and request[high] == ""):
            end = _ads_date(request[high])
        if start is None or end is None:
            return
        if end < start or (end == start and not constraint["allow_equal"]):
            raise ConstraintViolation("Ads date range is reversed or does not allow equal dates")
        maximum = constraint["maximum_months"]
        if maximum is not None:
            month_index = start.year * 12 + start.month - 1 + maximum
            year, month = divmod(month_index, 12)
            month += 1
            last = (year, month, min(start.day, monthrange(year, month)[1]))
            if (end.year, end.month, end.day) > last:
                raise ConstraintViolation("Ads date range exceeds calendar month limit")
        return

    if kind == "ordered_pair":
        low, high = constraint["from"], constraint["to"]
        if low in request and high in request and request[low] > request[high]:
            raise ConstraintViolation("time range is reversed")
        return

    if kind == "csv_ids":
        if all(request.get(key) == value for key, value in constraint["when"].items()):
            field = constraint["field"]
            if field in request:
                values = request[field].split(",")
                if len(values) > constraint["max_items"] or any(
                    not re.fullmatch(r"[0-9]+", value) for value in values
                ):
                    raise ConstraintViolation("invalid comma-separated identifier list")
        return

    if kind == "integer_product_lte":
        fields = constraint["fields"]
        if not all(field in request for field in fields):
            return
        product = 1
        for field in fields:
            value = request[field]
            if type(value) is not int:
                raise ConstraintViolation("integer product contains a non-integer")
            product *= value
        if product > constraint["maximum"]:
            raise ConstraintViolation("integer product exceeds limit")
        return

    if kind == "ams_calendar_range":
        names = (constraint["period_type"], constraint["from"], constraint["to"])
        if not all(name in request for name in names):
            return
        period = request[constraint["period_type"]]
        start = _calendar_date(request[constraint["from"]])
        end = _calendar_date(request[constraint["to"]])
        delta = (end - start).days
        valid = (
            (period == "Day" and delta == 0)
            or (period == "Week" and start.weekday() == 6 and end.weekday() == 5 and delta == 6)
            or (
                period == "Month"
                and start.day == 1
                and (start.year, start.month) == (end.year, end.month)
            )
            or (period == "Last7d" and delta == 6)
            or (period == "Last30d" and delta == 29)
        )
        if not valid:
            raise ConstraintViolation("AMS date range does not align with period type")
        return

    if kind == "principal_calendar_range":
        names = (
            constraint["granularity"], constraint["timezone"],
            constraint["from"], constraint["to"],
        )
        if not all(name in request for name in names):
            return
        start = _iso_date(request[constraint["from"]])
        end = _iso_date(request[constraint["to"]])
        if start > end:
            raise ConstraintViolation("principal date range is reversed")
        now = clock() if clock is not None else datetime.now(timezone.utc)
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
            raise ConstraintViolation("principal calendar clock must be timezone-aware")
        offset = PRINCIPAL_TIMEZONES.get(request[constraint["timezone"]])
        if offset is None:
            raise ConstraintViolation("unsupported principal timezone")
        latest = now.astimezone(timezone(timedelta(hours=offset))).date() - timedelta(days=1)
        earliest = _subtract_years(latest, 2)
        if start < earliest or end > latest:
            raise ConstraintViolation("principal date range is outside the selectable window")
        granularity = request[constraint["granularity"]]
        delta = (end - start).days
        quarter = (start.month - 1) // 3
        valid = (
            (granularity == "customize" and delta <= 365)
            or (granularity == "day" and delta == 0)
            or (granularity == "week" and start.weekday() == 6 and delta <= 6)
            or (
                granularity == "month"
                and start.day == 1
                and (start.year, start.month) == (end.year, end.month)
            )
            or (
                granularity == "quarter"
                and start.day == 1
                and start.month in {1, 4, 7, 10}
                and start.year == end.year
                and (end.month - 1) // 3 == quarter
            )
            or (
                granularity == "year"
                and start.month == 1
                and start.day == 1
                and start.year == end.year
            )
        )
        if not valid:
            raise ConstraintViolation("principal date range does not align with granularity")
        return

    if kind == "unique_list_keys":
        items = request.get(constraint["field"])
        if not items:
            return
        seen = set()
        for item in items:
            key = tuple(item.get(name) for name in constraint["keys"])
            if key in seen:
                raise ConstraintViolation("duplicate list key")
            seen.add(key)
        return

    if kind == "unique_nested_values":
        items = request.get(constraint["field"])
        if not items:
            return
        seen = set()
        count = 0
        for item in items:
            for value in item.get(constraint["value_field"], []):
                count += 1
                if value in seen:
                    raise ConstraintViolation("duplicate nested value")
                seen.add(value)
        maximum = constraint["maximum"]
        if maximum is not None and count > maximum:
            raise ConstraintViolation("nested value limit exceeded")
        return

    if kind == "consistent_list_value":
        items = request.get(constraint["field"])
        if not items:
            return
        values = {}
        for item in items:
            key = item.get(constraint["key"])
            value = item.get(constraint["value"], constraint["default"])
            if key in values and values[key] != value:
                raise ConstraintViolation("conflicting list value")
            values[key] = value
        return

    if kind == "pagination_requires_empty_list":
        if request.get(constraint["field"]) and any(
            name in request for name in constraint["pagination_fields"]
        ):
            raise ConstraintViolation("pagination requires an empty target list")
        return

    if kind == "conditional_iso_date_delta":
        if any(request.get(name, _MISSING) != value for name, value in constraint["when"].items()):
            return
        low = _iso_date(request.get(constraint["from"]))
        high = _iso_date(request.get(constraint["to"]))
        if not constraint["minimum_days"] <= (high - low).days <= constraint["maximum_days"]:
            raise ConstraintViolation("conditional date difference outside bounds")
        return

    if kind == "iso_date_range":
        if constraint["from"] not in request or constraint["to"] not in request:
            return
        start = _iso_date(request[constraint["from"]])
        end = _iso_date(request[constraint["to"]])
        inclusive_days = (end - start).days + 1
        if inclusive_days < 1 or inclusive_days > constraint["maximum_days"]:
            raise ConstraintViolation("date range is reversed or exceeds inclusive limit")
        return

    if kind == "numeric_delta":
        if constraint["from"] not in request or constraint["to"] not in request:
            return
        low = request[constraint["from"]]
        high = request[constraint["to"]]
        if type(low) is not int or type(high) is not int:
            raise ConstraintViolation("numeric delta contains a non-integer")
        delta = high - low
        if not constraint["minimum"] <= delta <= constraint["maximum"]:
            raise ConstraintViolation("numeric delta outside bounds")
        return

    if kind == "video_period_end":
        if constraint["period_type"] not in request or constraint["end_date"] not in request:
            return
        period = request[constraint["period_type"]]
        end = _iso_date(request[constraint["end_date"]])
        if period == "Week" and end.weekday() != 6:
            raise ConstraintViolation("video weekly period must end on Sunday")
        if period == "Month" and end.day != monthrange(end.year, end.month)[1]:
            raise ConstraintViolation("video monthly period must end on month end")
        return

    if kind == "nested_value_count":
        items = _path_value(request, constraint["field"])
        if items is _MISSING:
            return
        count = 0
        for item in items:
            nested = _path_value(item, constraint["nested_field"])
            if nested is _MISSING:
                continue
            for child in nested:
                value = _path_value(child, constraint["value_field"])
                if value is not _MISSING and value == constraint["value"]:
                    count += 1
        if count > constraint["maximum"]:
            raise ConstraintViolation("nested value count exceeds limit")
        return

    if kind == "nested_integer_sum_lte":
        items = _path_value(request, constraint["field"])
        if items is _MISSING:
            return
        total = 0
        for item in items:
            value = _path_value(item, constraint["value_field"])
            if value is _MISSING:
                continue
            if type(value) is not int or value < 0:
                raise ConstraintViolation("nested sum contains an invalid nonnegative integer")
            total += value
        if total > constraint["maximum"]:
            raise ConstraintViolation("nested integer sum exceeds limit")
        return

    if kind == "iso_date_order":
        low = _path_value(request, constraint["from"])
        high = _path_value(request, constraint["to"])
        start = _iso_date(low) if low is not _MISSING else None
        end = _iso_date(high) if high is not _MISSING else None
        if start is not None and end is not None:
            if start > end or (start == end and not constraint["allow_equal"]):
                raise ConstraintViolation("date order is invalid")
        return

    if kind == "logistics_operating_hours":
        for name in constraint["regular_fields"]:
            periods = _path_value(request, name)
            if periods is not _MISSING:
                for period in periods.values():
                    _operating_period(period)
        special = _path_value(request, constraint["special_field"])
        if special is _MISSING:
            return
        start, end = _iso_date(special["start_date"]), _iso_date(special["end_date"])
        delta = (end - start).days
        if not 0 <= delta <= 30:
            raise ConstraintViolation("special operating date range exceeds its limit or is reversed")
        dates = []
        for period in special["operating_hours"]:
            dates.append(_iso_date(period["date"]))
            _operating_period(period, enabled=period["enable"])
        expected = {start + timedelta(days=offset) for offset in range(delta + 1)}
        if len(dates) != len(expected) or set(dates) != expected:
            raise ConstraintViolation("special operating dates must cover the complete range exactly once")
        # The source specifies today+1..365 but does not identify the timezone.
        # Leave that dynamic limit to Shopee instead of assuming a local zone.
        return

    raise ConstraintViolation("unsupported constraint")
