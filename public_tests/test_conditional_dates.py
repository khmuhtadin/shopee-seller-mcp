from copy import deepcopy

import pytest

from shopee_mcp.constraints import ConstraintViolation, enforce_constraint, validate_constraint_metadata

RULE = {"kind":"conditional_iso_date_delta", "from":"date_from", "to":"date_to",
        "when":{"income_status":1}, "minimum_days":1, "maximum_days":14}
SCHEMA = {"type":"object", "properties":{"date_from":{"type":"string"}, "date_to":{"type":"string"},
          "income_status":{"type":"integer", "enum":[0,1,2]}}, "required":["date_from","date_to","income_status"]}


@pytest.mark.parametrize("start,end", [("2026-09-01","2026-09-01"), ("2026-09-02","2026-09-01"),
    ("2026-09-01","2026-09-16"), ("2026-02-29","2026-03-01"), ("2026-9-1","2026-09-03")])
def test_released_income_rejects_invalid_dates_or_delta(start, end):
    with pytest.raises(ConstraintViolation):
        enforce_constraint(RULE, {"date_from":start, "date_to":end, "income_status":1})


@pytest.mark.parametrize("start,end", [("2026-09-01","2026-09-02"), ("2026-09-01","2026-09-15"),
                                     ("2024-02-29","2024-03-01")])
def test_date_difference_boundaries(start, end):
    validate_constraint_metadata(RULE, SCHEMA)
    enforce_constraint(RULE, {"date_from":start, "date_to":end, "income_status":1})


def test_ignored_status_dates_are_not_overconstrained():
    enforce_constraint(RULE, {"date_from":"ignored", "date_to":"ignored", "income_status":2})


@pytest.mark.parametrize("changes", [{"when":{}}, {"when":{"income_status":3}}, {"when":{"unknown":1}},
    {"minimum_days":False}, {"maximum_days":0}, {"from":"unknown"}, {"from":"date_to"}])
def test_invalid_date_rule_metadata(changes):
    with pytest.raises(ValueError):
        validate_constraint_metadata({**RULE, **changes}, SCHEMA)
