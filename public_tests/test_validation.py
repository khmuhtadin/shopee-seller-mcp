import pytest

from shopee_mcp.validation import InputError, from_wire, to_wire


INT64_SCHEMA = {"type": "string", "x-wire-int64": True}


@pytest.mark.parametrize(
    "model_value,wire_value",
    [
        ("-9223372036854775808", -9223372036854775808),
        ("-1", -1),
        ("0", 0),
        ("1", 1),
        ("9223372036854775807", 9223372036854775807),
    ],
)
def test_signed_int64_model_input_converts_canonical_decimal_strings(model_value, wire_value):
    assert to_wire(model_value, INT64_SCHEMA) == wire_value


@pytest.mark.parametrize(
    "model_value",
    [
        True,
        False,
        1,
        -1,
        1.0,
        "",
        "+1",
        "01",
        "-0",
        "-01",
        " 1",
        "1 ",
        "9223372036854775808",
        "-9223372036854775809",
    ],
)
def test_signed_int64_model_input_rejects_noncanonical_or_nonstring_values(model_value):
    with pytest.raises(InputError, match="invalid_arguments"):
        to_wire(model_value, INT64_SCHEMA)


@pytest.mark.parametrize(
    "wire_value,model_value",
    [
        (-9223372036854775808, "-9223372036854775808"),
        (-1, "-1"),
        (0, "0"),
        (1, "1"),
        (9223372036854775807, "9223372036854775807"),
        ("-9223372036854775808", "-9223372036854775808"),
        ("0", "0"),
        ("9223372036854775807", "9223372036854775807"),
    ],
)
def test_signed_int64_wire_output_is_a_lossless_canonical_string(wire_value, model_value):
    assert from_wire(wire_value, INT64_SCHEMA) == model_value


@pytest.mark.parametrize(
    "wire_value",
    [
        True,
        False,
        1.0,
        "",
        "+1",
        "01",
        "-0",
        "-01",
        " 1",
        "1 ",
        9223372036854775808,
        -9223372036854775809,
        "9223372036854775808",
        "-9223372036854775809",
    ],
)
def test_signed_int64_wire_output_rejects_noncanonical_or_out_of_range_values(wire_value):
    with pytest.raises(InputError, match="invalid_response"):
        from_wire(wire_value, INT64_SCHEMA)


def test_signed_int64_conversion_follows_nested_object_and_array_schemas():
    schema = {
        "type": "object",
        "properties": {
            "counts": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {"delta": INT64_SCHEMA},
                },
            }
        },
    }
    model = {"counts": [{"delta": "-9223372036854775808"}, {"delta": "7"}]}
    wire = {"counts": [{"delta": -9223372036854775808}, {"delta": 7}]}

    assert to_wire(model, schema) == wire
    assert from_wire(wire, schema) == model


def test_unsigned_wire_integer_semantics_remain_nonnegative():
    schema = {"type": "string", "x-wire-integer": True}

    assert to_wire("9223372036854775807", schema) == 9223372036854775807
    with pytest.raises(InputError, match="invalid_arguments"):
        to_wire("-1", schema)
    with pytest.raises(InputError, match="invalid_response"):
        from_wire(-1, schema)
