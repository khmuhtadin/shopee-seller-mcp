import math

import pytest

from shopee_mcp.schema_validation import ExactDraft202012Validator
from shopee_mcp.validation import InputError, validate_arguments


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
def test_nonfinite_floats_are_not_json_numbers_even_without_numeric_bounds(value):
    assert not ExactDraft202012Validator({"type": "number"}).is_valid(value)
    assert not ExactDraft202012Validator({"type": ["number", "null"]}).is_valid(value)
    item = {"input_schema": {"type": "object", "additionalProperties": False,
                             "properties": {"price": {"type": "number"}}},
            "response_schema": {"type": "object", "properties": {}}}
    with pytest.raises(InputError, match="check the tool input schema"):
        validate_arguments(item, {"request": {"price": value}}, "test")


@pytest.mark.parametrize("value", [0, -1, 1.13, 2.55, 0.29, 1e20])
def test_finite_json_numbers_and_exact_decimal_multiples_remain_valid(value):
    assert ExactDraft202012Validator({"type": "number"}).is_valid(value)
    assert ExactDraft202012Validator({"type": "number", "multipleOf": 0.01}).is_valid(value)


def test_non_multiple_and_boolean_still_fail_number_validation():
    assert not ExactDraft202012Validator({"type": "number", "multipleOf": 0.01}).is_valid(1.131)
    assert not ExactDraft202012Validator({"type": "number"}).is_valid(True)
