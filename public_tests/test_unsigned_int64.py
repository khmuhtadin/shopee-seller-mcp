import pytest

from shopee_mcp.validation import InputError, from_wire, to_wire


SCHEMA = {"type": "string", "pattern": "^(0|[1-9][0-9]*)$", "x-wire-uint64": True}


@pytest.mark.parametrize("number", [0, 1, 2**63, 2**64 - 1])
def test_unsigned_64_bit_integer_roundtrip_is_exact(number):
    assert to_wire(str(number), SCHEMA) == number
    assert from_wire(number, SCHEMA) == str(number)
    assert from_wire(str(number), SCHEMA) == str(number)


@pytest.mark.parametrize("value", [True, False, 1, 1.0, "-1", "-0", "01", "+1", " 1", str(2**64)])
def test_unsigned_64_bit_input_refuses_loss_and_noncanonical_values(value):
    with pytest.raises(InputError, match="invalid_arguments"):
        to_wire(value, SCHEMA)


@pytest.mark.parametrize("value", [True, False, 1.0, -1, "-1", "-0", "01", "+1", " 1", 2**64, str(2**64)])
def test_unsigned_64_bit_response_refuses_loss_and_overflow(value):
    with pytest.raises(InputError, match="invalid_response"):
        from_wire(value, SCHEMA)


def test_unsigned_conversion_is_recursive_and_preserves_null():
    schema = {"type": "object", "properties": {"ids": {"type": "array", "items": SCHEMA}}}
    model = {"ids": [str(2**64 - 1), None]}
    wire = {"ids": [2**64 - 1, None]}
    assert to_wire(model, schema) == wire
    assert from_wire(wire, schema) == model
