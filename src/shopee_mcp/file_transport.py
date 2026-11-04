"""Secure, bounded preparation of catalog-declared multipart files."""
from __future__ import annotations

import contextlib
from html import unescape
import hashlib
import hmac
import os
import re
import stat
from pathlib import Path
from urllib.parse import parse_qsl, unquote, urlsplit
from xml.parsers import expat

from .validation import InputError


def _identified_mime(data: bytes) -> str:
    """Identify only formats that a reviewed endpoint explicitly permits."""
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    if data.startswith(b"%PDF-"):
        return "application/pdf"
    # Parser-level rejection covers UTF-16 as well as ASCII-compatible XML.
    # No element tree is built, and a DTD is rejected before entity expansion.
    def reject_declaration(*_args):
        raise ValueError("XML declarations are not permitted")
    parser = expat.ParserCreate()
    parser.StartDoctypeDeclHandler = reject_declaration
    parser.EntityDeclHandler = reject_declaration
    parser.ExternalEntityRefHandler = reject_declaration
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    try:
        parser.Parse(data, True)
    except (expat.ExpatError, ValueError, LookupError):
        pass
    else:
        return "application/xml"
    raise InputError("Upload content type is unsupported")


def download_contains_secrets(data: bytes, secrets) -> bool:
    """Reject credential-bearing downloads without rewriting document bytes.

    Inspect bounded textual views only; never render or expand remote content.
    MIME is untrusted, so this applies equally to PDF and opaque responses.
    """
    secret_values = tuple(value for value in secrets if isinstance(value, str) and value)
    sensitive_query_keys = {"partner_key", "access_token", "refresh_token", "sign", "signature",
                            "x-amz-signature", "authorization", "code", "state"}
    encodings = ["utf-8"]
    if b"\x00" in data or data.startswith((b"\xff\xfe", b"\xfe\xff")):
        encodings += ["utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be"]
    for encoding in encodings:
        text = data.decode(encoding, errors="ignore")
        # Handles percent-encoded signed URLs and HTML error-page escaping;
        # bounded rounds prevent unbounded normalization of hostile content.
        for _ in range(3):
            if any(secret in text for secret in secret_values):
                return True
            for match in re.finditer(r"https?://[^\s<>\"'\x00]+", text, re.IGNORECASE):
                try:
                    keys = {key.lower() for key, _ in parse_qsl(urlsplit(match.group()).query)}
                except ValueError:
                    return True
                if keys & sensitive_query_keys:
                    return True
            normalized = unquote(unescape(text))
            if normalized == text:
                break
            text = normalized
    return False


def _read_file(path, roots, limit):
    if not isinstance(path, str) or not path:
        raise InputError("Upload path must be a non-empty string")
    supplied = Path(path).absolute()
    if ".." in supplied.parts or not any(supplied.is_relative_to(root) for root in roots):
        raise InputError("Upload must be inside an allowed root")
    try:
        with contextlib.ExitStack() as stack:
            directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            directory_fd = os.open(supplied.anchor, directory_flags)
            stack.callback(os.close, directory_fd)
            for component in supplied.parts[1:-1]:
                directory_fd = os.open(component, directory_flags, dir_fd=directory_fd)
                stack.callback(os.close, directory_fd)
            fd = os.open(supplied.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                         dir_fd=directory_fd)
            stream = stack.enter_context(os.fdopen(fd, "rb"))
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
                raise InputError("Upload file type or size not permitted")
            data = stream.read(limit + 1)
            if len(data) > limit:
                raise InputError("Upload file type or size not permitted")
    except OSError:
        raise InputError("Unable to open upload file") from None
    return supplied, data


def _mime(constraints, data):
    kind = constraints.get("content_kind", "identified")
    if kind == "identified":
        return _identified_mime(data)
    if kind == "opaque" and constraints.get("mime_types") == ["application/octet-stream"]:
        return "application/octet-stream"
    raise InputError("Upload content kind is unsupported")


def _verify_relations(constraints, fields, data, mime):
    checksum = constraints.get("checksum")
    if checksum is not None:
        expected = fields.get(checksum.get("field"))
        if checksum.get("algorithm") != "md5" or not isinstance(expected, str) or not re.fullmatch(
                r"[0-9A-Fa-f]{32}", expected):
            raise InputError("Upload checksum is invalid")
        actual = hashlib.md5(data, usedforsecurity=False).hexdigest()
        if not hmac.compare_digest(actual, expected.lower()):
            raise InputError("Upload checksum does not match content")
    selector = constraints.get("mime_selector")
    if selector is not None:
        selected = selector.get("values", {}).get(str(fields.get(selector.get("field"))))
        if selected != mime:
            raise InputError("Upload file type does not match selector")


def freeze_uploads(endpoint, wire, roots, operator_limit):
    """Return scalar form fields and ordered, immutable multipart file bytes."""
    fields = dict(wire)
    files = []
    total_bytes = 0
    for field, constraints in endpoint.get("upload_fields", {}).items():
        if field not in fields:
            continue
        supplied = fields.pop(field)
        if constraints.get("multiple", False):
            if not isinstance(supplied, list):
                raise InputError("Upload field must be a list of paths")
            maximum = constraints.get("max_files")
            if type(maximum) is not int or maximum <= 0 or not 1 <= len(supplied) <= maximum:
                raise InputError("Upload file count is not permitted")
            paths = supplied
        else:
            if isinstance(supplied, list):
                raise InputError("Upload field accepts one path")
            paths = [supplied]
        configured_limit = constraints.get("max_bytes")
        if type(configured_limit) is not int or configured_limit <= 0:
            raise InputError("Upload byte limit must be a positive integer")
        limit = min(operator_limit, configured_limit)
        for path in paths:
            absolute, data = _read_file(path, roots, limit)
            total_bytes += len(data)
            if total_bytes > operator_limit:
                raise InputError("Upload total size exceeds the operator limit")
            mime = _mime(constraints, data)
            if mime not in constraints.get("mime_types", []):
                raise InputError("Upload MIME type not permitted")
            _verify_relations(constraints, fields, data, mime)
            files.append((field, (absolute.name, data, mime)))
    return fields, files
