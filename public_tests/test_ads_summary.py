"""Offline tests for the read-only Ads summary (no network, no credentials)."""
from datetime import date
import json

import pytest

from shopee_mcp.ads_summary import (
    BALANCE_API, DAILY_API, HOURLY_API, AdsSummaryInputError, parse_ads_date, plan_daily_chunks, summarize_ads,
)


def row(day, **overrides):
    base = {"date": day, "impression": 100, "clicks": 10, "ctr": 0.1, "expense": 1000.1,
            "direct_order": 1, "direct_item_sold": 2, "direct_gmv": 5000.2, "direct_conversions": 1,
            "direct_roas": 5.0, "broad_order": 3, "broad_item_sold": 4, "broad_gmv": 9000.3,
            "broad_conversions": 3, "broad_roas": 9.0, "cost_per_conversion": 333.3}
    base.update(overrides)
    return base


def ok(response):
    return {"error": "", "message": "", "request_id": "req-1", "response": response}


class Fake:
    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    async def __call__(self, api_name, params):
        self.calls.append((api_name, dict(params)))
        return self.handler(api_name, params)


def daily_for(days_by_range, balance=ok({"total_balance": 12345.67, "data_timestamp": 1700000000})):
    def handler(api_name, params):
        if api_name == BALANCE_API:
            return balance
        assert api_name == DAILY_API
        return days_by_range(params["start_date"], params["end_date"])
    return Fake(handler)


def full_range(start, end):
    s, e = parse_ads_date(start), parse_ads_date(end)
    out, d = [], s
    while d <= e:
        out.append(row(d.strftime("%d-%m-%Y")))
        d = date.fromordinal(d.toordinal() + 1)
    return ok(out)


async def test_complete_two_days_uses_decimal_and_keeps_direct_broad_separate():
    fake = daily_for(full_range)
    result = await summarize_ads(fake, "01-10-2026", "02-10-2026", shop_label="store-a")
    json.dumps(result)
    assert result["status"] == "complete" and result["complete"] and result["source"] == "daily"
    assert fake.calls[0] == (DAILY_API, {"start_date": "01-10-2026", "end_date": "02-10-2026"})
    totals = result["totals"]
    assert totals["expense"] == "2000.2"   # exact Decimal, not 2000.2000000000003
    assert totals["direct_gmv"] == "10000.4" and totals["broad_gmv"] == "18000.6"
    assert totals["impression"] == 200 and totals["direct_order"] == 2 and totals["broad_order"] == 6
    assert "direct_conversions" not in totals and "broad_conversions" not in totals   # rates, never summed
    assert result["rows"][0]["reported_ratios"]["direct_conversions"] == "1"
    forbidden = {"gmv", "total_gmv", "orders", "roas", "direct_plus_broad", "gmv_max", "cpc"}
    assert not forbidden & set(totals)
    assert result["rows"][0]["reported_ratios"]["direct_roas"] == "5.0"
    assert result["balance"] == {"ok": True, "total_balance": "12345.67", "data_timestamp": 1700000000,
                                 "note": result["balance"]["note"]}
    assert result["shop_label"] == "store-a"
    assert any("Seller Center" in n for n in result["notes"])


async def test_thirty_day_range_is_single_call():
    fake = daily_for(full_range)
    result = await summarize_ads(fake, "01-10-2026", "30-10-2026", include_balance=False)
    assert result["complete"] and len(result["covered_dates"]) == 30
    assert [c for c in fake.calls] == [(DAILY_API, {"start_date": "01-10-2026", "end_date": "30-10-2026"})]


async def test_31_day_month_is_split_because_shopee_rejects_it():
    # Shopee sandbox rejects 01-10..31-10 (error_date_range_too_long).
    fake = daily_for(full_range)
    result = await summarize_ads(fake, "01-10-2026", "31-10-2026", include_balance=False)
    assert result["complete"] and len(result["covered_dates"]) == 31
    assert [c for c in fake.calls] == [
        (DAILY_API, {"start_date": "01-10-2026", "end_date": "29-10-2026"}),
        (DAILY_API, {"start_date": "30-10-2026", "end_date": "31-10-2026"}),
    ]


@pytest.mark.parametrize("bad", ["2026-10-01", "1-10-2026", "31-02-2026", " 01-10-2026", "０１-１０-２０２６", "", None, 20261001])
async def test_invalid_dates_raise_before_any_call(bad):
    fake = daily_for(full_range)
    with pytest.raises(AdsSummaryInputError):
        await summarize_ads(fake, bad, "05-10-2026")
    assert fake.calls == []


async def test_reversed_and_too_long_ranges_rejected():
    fake = daily_for(full_range)
    with pytest.raises(AdsSummaryInputError):
        await summarize_ads(fake, "02-10-2026", "01-10-2026")
    with pytest.raises(AdsSummaryInputError):
        await summarize_ads(fake, "01-01-2025", "02-01-2026")
    with pytest.raises(AdsSummaryInputError):
        await summarize_ads("not callable", "01-10-2026", "02-10-2026")
    assert fake.calls == []


@pytest.mark.parametrize("start,end", [("01-01-2026", "31-12-2026"), ("31-01-2026", "01-03-2026"),
                                       ("01-01-2026", "02-02-2026"), ("15-03-2026", "16-03-2026")])
def test_chunks_are_contiguous_non_overlapping_and_within_contract(start, end):
    s, e = parse_ads_date(start), parse_ads_date(end)
    chunks = plan_daily_chunks(s, e)
    assert chunks[0][0] == s and chunks[-1][1] == e
    for (a, b), nxt in zip(chunks, chunks[1:] + [None]):
        assert a < b   # endpoint rejects equal dates
        assert (b - a).days + 1 <= 30   # live Shopee limit: 30 inclusive days
        y, m = divmod(a.year * 12 + a.month, 12)   # catalog: at most 1 calendar month
        from calendar import monthrange
        assert b <= date(y, m + 1, min(a.day, monthrange(y, m + 1)[1]))
        if nxt:
            assert nxt[0].toordinal() == b.toordinal() + 1


async def test_multi_chunk_range_counts_each_day_once():
    fake = daily_for(full_range)
    result = await summarize_ads(fake, "01-01-2026", "15-03-2026", include_balance=False)
    assert len(fake.calls) > 1 and result["complete"]
    assert len(result["covered_dates"]) == len(set(result["covered_dates"])) == 74
    assert result["totals"]["clicks"] == 740


async def test_partial_chunk_failure_is_not_zero():
    def handler(start, end):
        if start == "01-01-2026":
            return {"error": "error_server", "message": "busy", "request_id": "r"}
        return full_range(start, end)
    fake = daily_for(handler)
    result = await summarize_ads(fake, "01-01-2026", "15-03-2026", include_balance=False)
    assert result["status"] == "partial" and result["complete"] is False and result["totals"] is None
    assert "01-01-2026" in result["failed_dates"] and "01-01-2026" not in result["covered_dates"]
    assert result["partial_totals"]["clicks"] == 10 * len(result["covered_dates"])
    assert any(i["kind"] == "api_error" and "error_server" in i["detail"] for i in result["issues"])


async def test_all_failures_status_failed_and_exception_text_not_leaked():
    def boom(api_name, params):
        raise RuntimeError("access_token=SECRET123 leaked")
    result = await summarize_ads(Fake(boom), "01-10-2026", "03-10-2026")
    assert result["status"] == "failed" and result["totals"] is None
    assert result["partial_totals"] == {} and result["balance"]["ok"] is False
    assert "SECRET123" not in json.dumps(result)
    assert result["api_calls"][0]["error"] == "exception:RuntimeError"


async def test_missing_dates_reported_not_zero():
    fake = daily_for(lambda s, e: ok([row("01-10-2026"), row("03-10-2026")]))
    result = await summarize_ads(fake, "01-10-2026", "03-10-2026", include_balance=False)
    assert result["missing_dates"] == ["02-10-2026"] and result["status"] == "partial" and result["totals"] is None


async def test_duplicates_out_of_range_and_conflicts():
    rows = [row("01-10-2026"), row("01-10-2026"), row("02-10-2026"), row("02-10-2026", clicks=99),
            row("03-10-2026"), row("30-09-2026")]
    fake = daily_for(lambda s, e: ok(rows))
    result = await summarize_ads(fake, "01-10-2026", "03-10-2026", include_balance=False)
    kinds = {i["kind"] for i in result["issues"]}
    assert {"duplicate_row", "conflicting_rows", "out_of_range_row"} <= kinds
    assert result["covered_dates"] == ["01-10-2026", "03-10-2026"]
    assert result["failed_dates"] == ["02-10-2026"]
    assert result["partial_totals"]["clicks"] == 20


async def test_invalid_and_missing_numbers_are_flagged():
    rows = [row("01-10-2026", expense="abc"), row("02-10-2026", broad_gmv=None), row("03-10-2026", clicks=True)]
    fake = daily_for(lambda s, e: ok(rows))
    result = await summarize_ads(fake, "01-10-2026", "03-10-2026", include_balance=False)
    assert set(result["failed_dates"]) == {"01-10-2026", "03-10-2026"}
    assert "broad_gmv" in result["partial_totals_missing_metrics"]
    assert "broad_gmv" not in result["partial_totals"] and result["totals"] is None


async def test_non_list_response_is_failure():
    fake = daily_for(lambda s, e: ok({"unexpected": True}))
    result = await summarize_ads(fake, "01-10-2026", "02-10-2026", include_balance=False)
    assert result["status"] == "failed" and result["failed_dates"] == ["01-10-2026", "02-10-2026"]


async def test_single_day_uses_hourly_only():
    def handler(api_name, params):
        assert api_name == HOURLY_API and params == {"performance_date": "05-10-2026"}
        return ok([{**row("05-10-2026"), "hour": h} for h in range(24)])
    fake = Fake(handler)
    result = await summarize_ads(fake, "05-10-2026", "05-10-2026", include_balance=False)
    assert result["source"] == "hourly" and result["complete"] and result["hours_covered"] == list(range(24))
    assert result["totals"]["expense"] == str(24 * __import__("decimal").Decimal("1000.1"))
    assert all(c[0] != DAILY_API for c in fake.calls)


async def test_single_day_missing_hours_is_partial():
    fake = Fake(lambda a, p: ok([{**row("05-10-2026"), "hour": h} for h in range(10)]))
    result = await summarize_ads(fake, "05-10-2026", "05-10-2026", include_balance=False)
    assert result["status"] == "partial" and result["totals"] is None
    assert result["partial_totals"]["clicks"] == 100
    assert any(i["kind"] == "missing_hours" for i in result["issues"])


async def test_single_day_hourly_error_or_disabled():
    fake = Fake(lambda a, p: {"error": "ads.error_param", "message": "date not supported"})
    result = await summarize_ads(fake, "05-10-2026", "05-10-2026", include_balance=False)
    assert result["status"] == "failed" and result["failed_dates"] == ["05-10-2026"]
    fake2 = Fake(lambda a, p: pytest.fail("must not be called"))
    result2 = await summarize_ads(fake2, "05-10-2026", "05-10-2026", include_balance=False,
                                  include_hourly_for_single_day=False)
    assert result2["status"] == "failed" and fake2.calls == []


async def test_include_raw_false_strips_payloads_and_only_read_endpoints_called():
    fake = daily_for(full_range)
    result = await summarize_ads(fake, "01-10-2026", "02-10-2026", include_raw=False)
    assert all(c["raw"] is None for c in result["api_calls"])
    assert {c[0] for c in fake.calls} == {DAILY_API, BALANCE_API}
    assert result["api_calls"][0]["request_id"] == "req-1"


async def test_balance_failure_does_not_affect_performance_status():
    fake = daily_for(full_range, balance={"error": "error_auth", "message": "no permission"})
    result = await summarize_ads(fake, "01-10-2026", "02-10-2026")
    assert result["complete"] and result["balance"]["ok"] is False
    assert any(i["kind"] == "balance_unavailable" for i in result["issues"])


async def test_warning_is_surfaced():
    fake = daily_for(lambda s, e: {**full_range(s, e), "warning": "partial data"})
    result = await summarize_ads(fake, "01-10-2026", "02-10-2026", include_balance=False)
    assert result["api_calls"][0]["warning"] == "partial data"
    assert any(i["kind"] == "api_warning" for i in result["issues"])
