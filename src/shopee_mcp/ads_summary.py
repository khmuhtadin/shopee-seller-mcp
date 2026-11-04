"""Read-only Shopee Ads (all CPC ads) summary built on raw Open Platform responses.

The module never talks to the network itself. Callers inject ``execute``, an async
callback ``(api_name, params) -> raw Shopee payload`` already bound to one shop.

Design rules:

* Dates are strict ``DD-MM-YYYY`` and must be ordered (``start <= end``).
* A range of two or more days uses ``v2.ads.get_all_cpc_ads_daily_performance``
  split into non-overlapping chunks of at most one calendar month (the endpoint
  rejects equal dates and ranges over one month). A single day uses
  ``v2.ads.get_all_cpc_ads_hourly_performance``. Daily and hourly data are never
  mixed for the same date, so nothing is counted twice.
* Failures, missing dates/hours, duplicate rows and malformed numbers are reported
  explicitly. They are never replaced with zero. ``totals`` is ``None`` unless the
  whole requested period is covered; ``partial_totals`` only covers ``covered_dates``.
* Direct and broad attribution stay separate. Nothing adds direct + broad, and
  nothing adds these CPC numbers to GMV Max or any other campaign type.
* Money/conversion values are ``decimal.Decimal`` internally and serialized as
  strings; counts are ints. The result is JSON-serializable.
* Field names are Open API names. No mapping to Seller Center labels is claimed.
"""

from __future__ import annotations

from calendar import monthrange
from datetime import date, datetime, timedelta
from decimal import Decimal, InvalidOperation
import re
from typing import Any, Awaitable, Callable, Literal, Mapping, TypedDict

__all__ = [
    "DAILY_API",
    "HOURLY_API",
    "BALANCE_API",
    "DECIMAL_METRICS",
    "INTEGER_METRICS",
    "AdsSummaryInputError",
    "Execute",
    "AdsSummary",
    "parse_ads_date",
    "plan_daily_chunks",
    "summarize_ads",
]

DAILY_API = "v2.ads.get_all_cpc_ads_daily_performance"
HOURLY_API = "v2.ads.get_all_cpc_ads_hourly_performance"
BALANCE_API = "v2.ads.get_total_balance"

# Additive metrics only. Rates/ratios are never summed: ctr, *_roas, cost_per_conversion and
# *_conversions (the API documents conversions as a rate, not a count; use *_order for orders).
DECIMAL_METRICS = ("expense", "direct_gmv", "broad_gmv")
INTEGER_METRICS = ("impression", "clicks", "direct_order", "direct_item_sold", "broad_order", "broad_item_sold")
RATIO_FIELDS = ("ctr", "direct_roas", "broad_roas", "cost_per_conversion", "direct_conversions", "broad_conversions")
METRICS = INTEGER_METRICS + DECIMAL_METRICS

MAX_RANGE_DAYS = 366
MAX_DAILY_CHUNK_DAYS = 30  # verified against the live sandbox, see plan_daily_chunks
_DATE_RE = re.compile(r"[0-9]{2}-[0-9]{2}-[0-9]{4}")
_ISO_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")

Execute = Callable[[str, dict[str, Any]], Awaitable[Any]]
Status = Literal["complete", "partial", "failed"]


class AdsSummaryInputError(ValueError):
    """Raised before any API call when caller input is invalid."""


class ApiCall(TypedDict):
    api_name: str
    params: dict[str, Any]
    ok: bool
    error: str | None          # Shopee "error" code, or "exception:<Type>" / "invalid_payload"
    message: str | None        # Shopee "message" only (exception text is not copied)
    request_id: str | None
    warning: Any               # Shopee "warning" as returned (None when absent)
    raw: Any                   # raw payload as returned by execute (None when it raised)


class Issue(TypedDict):
    kind: str
    detail: str
    api_name: str | None
    dates: list[str]


class Balance(TypedDict):
    ok: bool
    total_balance: str | None
    data_timestamp: int | None
    note: str


class AdsSummary(TypedDict):
    shop_label: str | None
    start_date: str
    end_date: str
    source: Literal["daily", "hourly"]
    status: Status
    complete: bool
    requested_dates: list[str]
    covered_dates: list[str]
    missing_dates: list[str]
    failed_dates: list[str]
    hours_covered: list[int] | None
    totals: dict[str, int | str] | None
    partial_totals: dict[str, int | str]
    partial_totals_missing_metrics: list[str]
    rows: list[dict[str, Any]]
    balance: Balance | None
    issues: list[Issue]
    notes: list[str]
    api_calls: list[ApiCall]


# --------------------------------------------------------------------------- dates

def parse_ads_date(value: Any, field: str = "date") -> date:
    """Parse strict DD-MM-YYYY (ASCII digits, real calendar date)."""
    if type(value) is not str or not _DATE_RE.fullmatch(value):
        raise AdsSummaryInputError(f"{field} must use DD-MM-YYYY")
    try:
        return datetime.strptime(value, "%d-%m-%Y").date()
    except ValueError:
        raise AdsSummaryInputError(f"{field} is not a real calendar date") from None


def _fmt(value: date) -> str:
    return value.strftime("%d-%m-%Y")


def _add_month(value: date) -> date:
    year, month = divmod(value.year * 12 + value.month, 12)
    month += 1
    return date(year, month, min(value.day, monthrange(year, month)[1]))


def plan_daily_chunks(start: date, end: date) -> list[tuple[date, date]]:
    """Split [start, end] (start < end) into contiguous, non-overlapping chunks.

    Every chunk satisfies the daily endpoint contract: chunk_start < chunk_end and
    spans at most MAX_DAILY_CHUNK_DAYS calendar days inclusive and never ends past
    chunk_start + 1 calendar month (the catalog constraint). No chunk is a single day.

    The documented limit is "1 month", but the live sandbox (Nov 2026) rejects
    01-10..31-10 with ads.performance.error_date_range_too_long and accepts
    01-10..30-10, so the effective limit is 30 inclusive days.
    """
    if not start < end:
        raise AdsSummaryInputError("daily chunks need start_date before end_date")
    chunks: list[tuple[date, date]] = []
    cursor = start
    while cursor <= end:
        # Both limits apply: the live 30-inclusive-day limit and the catalog's
        # calendar-month constraint (e.g. 31-01 may only reach 28-02).
        chunk_end = min(end, cursor + timedelta(days=MAX_DAILY_CHUNK_DAYS - 1), _add_month(cursor))
        if chunk_end < end and chunk_end + timedelta(days=1) == end:
            chunk_end -= timedelta(days=1)   # keep the final chunk at >= 2 days
        chunks.append((cursor, chunk_end))
        cursor = chunk_end + timedelta(days=1)
    return chunks


def _row_date(value: Any) -> date | None:
    if type(value) is not str:
        return None
    for pattern, fmt in ((_DATE_RE, "%d-%m-%Y"), (_ISO_RE, "%Y-%m-%d")):
        if pattern.fullmatch(value):
            try:
                return datetime.strptime(value, fmt).date()
            except ValueError:
                return None
    return None


# ------------------------------------------------------------------------- numbers

def _to_decimal(value: Any) -> Decimal | None:
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return None
    try:
        number = Decimal(str(value).strip()) if isinstance(value, str) else Decimal(str(value))
    except InvalidOperation:
        return None
    return number if number.is_finite() else None


def _to_int(value: Any) -> int | None:
    number = _to_decimal(value)
    if number is None or number != number.to_integral_value():
        return None
    return int(number)


def _parse_metrics(row: Mapping[str, Any]) -> tuple[dict[str, int | Decimal], list[str], list[str]]:
    """Return (values, missing_fields, invalid_fields) for additive metrics."""
    values: dict[str, int | Decimal] = {}
    missing: list[str] = []
    invalid: list[str] = []
    for name in METRICS:
        if name not in row or row[name] is None:
            missing.append(name)
            continue
        parsed = _to_int(row[name]) if name in INTEGER_METRICS else _to_decimal(row[name])
        if parsed is None:
            invalid.append(name)
        else:
            values[name] = parsed
    return values, missing, invalid


def _serialize(values: Mapping[str, int | Decimal]) -> dict[str, int | str]:
    return {k: (str(v) if isinstance(v, Decimal) else v) for k, v in values.items()}


# ------------------------------------------------------------------------- calling

async def _call(execute: Execute, api_name: str, params: dict[str, Any], calls: list[ApiCall]) -> tuple[ApiCall, Any]:
    record: ApiCall = {"api_name": api_name, "params": dict(params), "ok": False, "error": None,
                       "message": None, "request_id": None, "warning": None, "raw": None}
    calls.append(record)
    try:
        payload = await execute(api_name, dict(params))
    except Exception as exc:  # noqa: BLE001 - surfaced as a failed call, never as zero
        kind = getattr(exc, "kind", None)
        record["error"] = f"exception:{type(exc).__name__}" + (f":{kind}" if isinstance(kind, str) else "")
        return record, None
    record["raw"] = payload
    if not isinstance(payload, Mapping):
        record["error"] = "invalid_payload"
        return record, None
    if isinstance(payload.get("request_id"), str):
        record["request_id"] = payload["request_id"]
    if isinstance(payload.get("message"), str):
        record["message"] = payload["message"]
    if payload.get("warning") not in (None, "", [], {}):
        record["warning"] = payload["warning"]
    error = payload.get("error")
    if error not in (None, ""):
        record["error"] = str(error)
        return record, None
    record["ok"] = True
    return record, payload.get("response")


def _issue(issues: list[Issue], kind: str, detail: str, api_name: str | None = None, dates: list[str] | None = None) -> None:
    issues.append({"kind": kind, "detail": detail, "api_name": api_name, "dates": dates or []})


# -------------------------------------------------------------------------- public

async def summarize_ads(
    execute: Execute,
    start_date: str,
    end_date: str,
    *,
    include_hourly_for_single_day: bool = True,
    include_balance: bool = True,
    include_raw: bool = True,
    shop_label: str | None = None,
) -> AdsSummary:
    """Summarize all-CPC Shopee Ads performance for one shop, read-only.

    Args:
        execute: async ``(api_name, params) -> raw Shopee payload`` bound to one shop.
            Payload shape: ``{"error": "", "message": "", "request_id": ..., "response": ...}``.
            Exceptions are captured as failed calls.
        start_date, end_date: inclusive, ``DD-MM-YYYY``; ``start_date <= end_date``;
            span at most 366 days.
        include_hourly_for_single_day: when start == end, call the hourly endpoint
            (the daily endpoint rejects equal dates). If False the day is reported as
            failed/not fetched instead of being zero.
        include_balance: also call ``v2.ads.get_total_balance`` (point-in-time,
            unrelated to the date range).
        include_raw: keep raw payloads in ``api_calls[*].raw``.
        shop_label: opaque label echoed back for multi-shop callers.

    Raises:
        AdsSummaryInputError: invalid dates/arguments, before any API call.
    """
    if not callable(execute):
        raise AdsSummaryInputError("execute must be an async callable")
    if shop_label is not None and type(shop_label) is not str:
        raise AdsSummaryInputError("shop_label must be a string")
    start = parse_ads_date(start_date, "start_date")
    end = parse_ads_date(end_date, "end_date")
    if end < start:
        raise AdsSummaryInputError("end_date must not be before start_date")
    span = (end - start).days + 1
    if span > MAX_RANGE_DAYS:
        raise AdsSummaryInputError(f"range spans {span} days; maximum is {MAX_RANGE_DAYS}")

    requested = [start + timedelta(days=i) for i in range(span)]
    requested_set = set(requested)
    calls: list[ApiCall] = []
    issues: list[Issue] = []
    notes: list[str] = [
        "Figures come from all-CPC-ads Open API endpoints only; GMV Max or other ad types are not added.",
        "direct_* and broad_* are separate attribution views and are never added together.",
        "Field names are Open API names; no mapping to Seller Center report labels is asserted.",
        "Rate fields (ctr, *_roas, cost_per_conversion, *_conversions) are not aggregated; see rows[].reported_ratios. Orders are *_order.",
        "Money values carry no currency in the API response; no currency (e.g. IDR) is assumed.",
        "Missing or null metrics stay unknown and are never treated as 0.",
        "Dates follow Shopee's own day boundary for the shop; no timezone conversion is applied.",
    ]
    covered: dict[date, dict[str, Any]] = {}
    failed: set[date] = set()
    hours_covered: list[int] | None = None
    source: Literal["daily", "hourly"] = "hourly" if span == 1 else "daily"

    if span == 1:
        day = start
        if not include_hourly_for_single_day:
            failed.add(day)
            _issue(issues, "not_fetched", "single-day range needs the hourly endpoint, which was disabled", HOURLY_API, [_fmt(day)])
        else:
            record, response = await _call(execute, HOURLY_API, {"performance_date": _fmt(day)}, calls)
            day_row = _summarize_hourly(day, record, response, issues)
            if day_row is None:
                failed.add(day)
            else:
                covered[day], hours_covered = day_row
            notes.append("Single-day range uses hourly data summed per hour; daily endpoint is not called for that day.")
    else:
        for chunk_start, chunk_end in plan_daily_chunks(start, end):
            chunk_dates = [chunk_start + timedelta(days=i) for i in range((chunk_end - chunk_start).days + 1)]
            params = {"start_date": _fmt(chunk_start), "end_date": _fmt(chunk_end)}
            record, response = await _call(execute, DAILY_API, params, calls)
            if not record["ok"]:
                failed.update(chunk_dates)
                _issue(issues, "api_error", f"{record['error']}: {record['message'] or ''}".strip(), DAILY_API, [_fmt(d) for d in chunk_dates])
                continue
            if not isinstance(response, list):
                failed.update(chunk_dates)
                _issue(issues, "invalid_response", "response is not a list of daily rows", DAILY_API, [_fmt(d) for d in chunk_dates])
                continue
            _collect_daily(response, set(chunk_dates), requested_set, covered, failed, issues)

    for record in calls:
        if record["warning"] is not None:
            _issue(issues, "api_warning", "Shopee returned a warning; see api_calls[].warning", record["api_name"])
        if not include_raw:
            record["raw"] = None

    covered_dates = sorted(covered)
    missing = sorted(d for d in requested if d not in covered and d not in failed)
    if missing:
        _issue(issues, "missing_dates", "no row returned; not assumed to be zero", DAILY_API if source == "daily" else HOURLY_API, [_fmt(d) for d in missing])

    partial: dict[str, int | Decimal] = {}
    missing_metrics: set[str] = set()
    for d in covered_dates:
        values = covered[d]["_values"]
        for name in METRICS:
            if name in values:
                partial[name] = partial.get(name, Decimal(0) if name in DECIMAL_METRICS else 0) + values[name]
            else:
                missing_metrics.add(name)
    for name in missing_metrics:
        partial.pop(name, None)

    hourly_incomplete = source == "hourly" and hours_covered is not None and len(hours_covered) != 24
    complete = (not failed and not missing and not missing_metrics and len(covered_dates) == span and not hourly_incomplete)
    status: Status = "complete" if complete else ("partial" if covered_dates else "failed")

    balance: Balance | None = None
    if include_balance:
        balance = await _balance(execute, calls, issues, include_raw)

    rows = [{k: v for k, v in covered[d].items() if k != "_values"} for d in covered_dates]
    return {
        "shop_label": shop_label,
        "start_date": _fmt(start),
        "end_date": _fmt(end),
        "source": source,
        "status": status,
        "complete": complete,
        "requested_dates": [_fmt(d) for d in requested],
        "covered_dates": [_fmt(d) for d in covered_dates],
        "missing_dates": [_fmt(d) for d in missing],
        "failed_dates": [_fmt(d) for d in sorted(failed)],
        "hours_covered": hours_covered,
        "totals": _serialize(partial) if complete else None,
        "partial_totals": _serialize(partial),
        "partial_totals_missing_metrics": sorted(missing_metrics),
        "rows": rows,
        "balance": balance,
        "issues": issues,
        "notes": notes,
        "api_calls": calls,
    }


def _collect_daily(response: list[Any], chunk: set[date], requested: set[date],
                   covered: dict[date, dict[str, Any]], failed: set[date], issues: list[Issue]) -> None:
    seen: dict[date, list[Mapping[str, Any]]] = {}
    for row in response:
        if not isinstance(row, Mapping):
            _issue(issues, "invalid_row", "daily row is not an object", DAILY_API)
            failed.update(chunk)   # cannot tell which date it belonged to
            continue
        when = _row_date(row.get("date"))
        if when is None:
            _issue(issues, "invalid_row", f"unparseable date {row.get('date')!r}", DAILY_API)
            failed.update(chunk)
            continue
        if when not in chunk:
            kind = "out_of_range_row" if when not in requested else "row_outside_chunk"
            _issue(issues, kind, "row ignored to avoid overlap/double counting", DAILY_API, [_fmt(when)])
            continue
        seen.setdefault(when, []).append(row)
    for when, rows in seen.items():
        if when in failed:
            continue
        if len(rows) > 1:
            if all(dict(r) == dict(rows[0]) for r in rows[1:]):
                _issue(issues, "duplicate_row", "identical duplicate rows collapsed to one", DAILY_API, [_fmt(when)])
            else:
                failed.add(when)
                _issue(issues, "conflicting_rows", "different rows for the same date; date excluded", DAILY_API, [_fmt(when)])
                continue
        row = rows[0]
        values, missing, invalid = _parse_metrics(row)
        if invalid:
            failed.add(when)
            _issue(issues, "invalid_number", f"invalid values for {', '.join(invalid)}", DAILY_API, [_fmt(when)])
            continue
        if missing:
            _issue(issues, "missing_fields", f"fields absent: {', '.join(missing)}", DAILY_API, [_fmt(when)])
        covered[when] = _row_output(when, values, missing, row)


def _summarize_hourly(day: date, record: ApiCall, response: Any, issues: list[Issue]) -> tuple[dict[str, Any], list[int]] | None:
    if not record["ok"]:
        _issue(issues, "api_error", f"{record['error']}: {record['message'] or ''}".strip(), HOURLY_API, [_fmt(day)])
        return None
    if not isinstance(response, list):
        _issue(issues, "invalid_response", "response is not a list of hourly rows", HOURLY_API, [_fmt(day)])
        return None
    by_hour: dict[int, Mapping[str, Any]] = {}
    for row in response:
        hour = _to_int(row.get("hour")) if isinstance(row, Mapping) else None
        if hour is None or not 0 <= hour <= 23:
            _issue(issues, "invalid_row", "hourly row without a valid hour 0-23", HOURLY_API, [_fmt(day)])
            return None
        row_day = _row_date(row.get("date")) if row.get("date") not in (None, "") else day
        if row_day != day:
            _issue(issues, "out_of_range_row", f"hourly row date {row.get('date')!r} differs from requested day", HOURLY_API, [_fmt(day)])
            return None
        if hour in by_hour:
            if dict(by_hour[hour]) != dict(row):
                _issue(issues, "conflicting_rows", f"different rows for hour {hour}", HOURLY_API, [_fmt(day)])
                return None
            _issue(issues, "duplicate_row", f"identical duplicate rows for hour {hour} collapsed", HOURLY_API, [_fmt(day)])
            continue
        by_hour[hour] = row
    totals: dict[str, int | Decimal] = {}
    missing_any: set[str] = set()
    for hour in sorted(by_hour):
        values, missing, invalid = _parse_metrics(by_hour[hour])
        if invalid:
            _issue(issues, "invalid_number", f"hour {hour}: invalid values for {', '.join(invalid)}", HOURLY_API, [_fmt(day)])
            return None
        missing_any.update(missing)
        for name, value in values.items():
            totals[name] = totals.get(name, Decimal(0) if name in DECIMAL_METRICS else 0) + value
    for name in missing_any:
        totals.pop(name, None)
    hours = sorted(by_hour)
    if missing_any:
        _issue(issues, "missing_fields", f"fields absent in some hours: {', '.join(sorted(missing_any))}", HOURLY_API, [_fmt(day)])
    if len(hours) != 24:
        absent = [h for h in range(24) if h not in by_hour]
        _issue(issues, "missing_hours", f"hours not returned (not assumed zero; day may be in progress): {absent}", HOURLY_API, [_fmt(day)])
    if not hours:
        return None
    return _row_output(day, totals, sorted(missing_any), None), hours


def _row_output(when: date, values: dict[str, int | Decimal], missing: list[str], raw_row: Mapping[str, Any] | None) -> dict[str, Any]:
    ratios = {k: str(_to_decimal(raw_row[k])) if _to_decimal(raw_row.get(k)) is not None else None
              for k in RATIO_FIELDS if k in raw_row} if raw_row is not None else {}
    return {"date": _fmt(when), "metrics": _serialize(values), "missing_fields": list(missing),
            "reported_ratios": ratios, "_values": values}


async def _balance(execute: Execute, calls: list[ApiCall], issues: list[Issue], include_raw: bool) -> Balance:
    record, response = await _call(execute, BALANCE_API, {}, calls)
    if record["warning"] is not None:
        _issue(issues, "api_warning", "Shopee returned a warning; see api_calls[].warning", BALANCE_API)
    if not include_raw:
        record["raw"] = None
    note = "Point-in-time ads balance at data_timestamp; not tied to the requested date range; currency not stated by the API."
    if not record["ok"] or not isinstance(response, Mapping):
        detail = f"{record['error']}: {record['message'] or ''}".strip() if not record["ok"] else "response is not an object"
        _issue(issues, "balance_unavailable", detail, BALANCE_API)
        return {"ok": False, "total_balance": None, "data_timestamp": None, "note": note}
    amount = _to_decimal(response.get("total_balance"))
    stamp = _to_int(response.get("data_timestamp"))
    if amount is None:
        _issue(issues, "balance_unavailable", "total_balance missing or not numeric", BALANCE_API)
    return {"ok": amount is not None, "total_balance": str(amount) if amount is not None else None,
            "data_timestamp": stamp, "note": note}
