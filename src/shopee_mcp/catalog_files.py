"""Validate explicit file endpoint metadata without inferring wire formats."""
import re


IDENTIFIED_MIMES = {"image/png", "image/jpeg", "image/gif", "image/webp", "application/pdf",
                    "application/xml", "text/xml"}
UPLOAD_KEYS = {"max_bytes", "mime_types", "multiple", "max_files", "content_kind", "checksum", "mime_selector"}


def _positive_integer(value):
    return type(value) is int and value > 0


def validate_file_contract(endpoint):
    if endpoint["encoding"] == "binary":
        if endpoint.get("binary_request_encoding") not in {"query", "json"}:
            raise ValueError("Binary response requires explicit query or JSON request encoding")
        policy = endpoint.get("download_mime_policy", "strict")
        if policy == "opaque":
            if "download_mime_types" in endpoint:
                raise ValueError("Opaque binary response must not mix a MIME allowlist")
        elif policy == "strict":
            mimes = endpoint.get("download_mime_types")
            if (not isinstance(mimes, list) or not mimes
                    or any(not isinstance(mime, str) or not re.fullmatch(
                        r"[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*", mime) for mime in mimes)):
                raise ValueError("Binary download requires a concrete MIME allowlist")
        else:
            raise ValueError("Unknown binary MIME policy")
    if endpoint["encoding"] != "multipart":
        return
    fields = endpoint.get("upload_fields")
    if not isinstance(fields, dict) or not fields:
        raise ValueError("Multipart requires explicit upload fields")
    properties = endpoint["input_schema"].get("properties", {})
    for name, limits in fields.items():
        if (not isinstance(limits, dict) or set(limits) - UPLOAD_KEYS
                or not _positive_integer(limits.get("max_bytes"))):
            raise ValueError("Invalid upload constraints")
        field = properties.get(name, {})
        multiple = limits.get("multiple", False)
        if type(multiple) is not bool:
            raise ValueError("Upload multiple must be a boolean")
        if multiple:
            if (field.get("type") != "array" or field.get("items", {}).get("type") != "string"
                    or not _positive_integer(limits.get("max_files"))
                    or not _positive_integer(field.get("maxItems"))
                    or field["maxItems"] > limits["max_files"]):
                raise ValueError("Multiple uploads require a bounded array of paths")
        elif field.get("type") != "string" or "max_files" in limits:
            raise ValueError("Single upload requires a path string without max_files")
        mimes = limits.get("mime_types")
        if not isinstance(mimes, list) or not mimes or any(not isinstance(mime, str) for mime in mimes):
            raise ValueError("Upload requires concrete MIME types")
        kind = limits.get("content_kind", "identified")
        if kind == "opaque":
            if mimes != ["application/octet-stream"]:
                raise ValueError("Opaque upload must use only application/octet-stream")
        elif kind != "identified" or not set(mimes) <= IDENTIFIED_MIMES:
            raise ValueError("Unsupported identified upload content type")
        checksum = limits.get("checksum")
        if checksum is not None:
            if (not isinstance(checksum, dict) or set(checksum) != {"field", "algorithm"}
                    or checksum["algorithm"] != "md5" or checksum["field"] in fields
                    or properties.get(checksum["field"], {}).get("type") != "string" or multiple):
                raise ValueError("Invalid upload checksum binding")
        selector = limits.get("mime_selector")
        if selector is not None:
            if not isinstance(selector, dict) or set(selector) != {"field", "values"}:
                raise ValueError("Invalid upload MIME selector")
            discriminant = properties.get(selector["field"], {})
            values = selector["values"]
            enum = discriminant.get("enum")
            if (not isinstance(values, dict) or not isinstance(enum, list) or not enum
                    or any(type(value) not in {str, int} for value in enum)
                    or set(values) != {str(value) for value in enum}
                    or any(value not in mimes for value in values.values())):
                raise ValueError("MIME selector must exactly cover the declared input enum")
