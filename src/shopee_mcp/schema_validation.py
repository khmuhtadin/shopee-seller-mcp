"""JSON Schema validation with exact decimal ``multipleOf`` semantics."""

from decimal import Decimal, InvalidOperation
import math

from jsonschema import Draft202012Validator, ValidationError, validators


def _exact_multiple_of(validator, divisor, instance, _schema):
    if not validator.is_type(instance, "number"):
        return
    try:
        remainder = Decimal(str(instance)) % Decimal(str(divisor))
    except (InvalidOperation, ValueError):
        yield ValidationError("number is not an exact multiple")
        return
    if remainder != 0:
        yield ValidationError("number is not an exact multiple")


def _finite_number(_checker, instance):
    return (Draft202012Validator.TYPE_CHECKER.is_type(instance, "number")
            and (not isinstance(instance, float) or math.isfinite(instance)))


ExactDraft202012Validator = validators.extend(
    Draft202012Validator,
    {"multipleOf": _exact_multiple_of},
    type_checker=Draft202012Validator.TYPE_CHECKER.redefine("number", _finite_number),
)
