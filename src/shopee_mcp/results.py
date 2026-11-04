"""Sanitized protocol envelopes and connection-scoped local artifacts."""
from __future__ import annotations

import fnmatch
import contextlib
import hashlib
import json
import math
import os
import re
import secrets as random_secrets
import stat
import time
from pathlib import Path
from urllib.parse import parse_qsl, quote, urlsplit

from jsonschema import Draft202012Validator

from .validation import InputError, from_wire
from .response_metadata import has_batch_failure, sanitize_embedded_json

SECRET_KEYS = {"partner_key", "access_token", "refresh_token", "sign", "signature", "x-amz-signature", "authorization"}


class ResultError(ValueError):
    pass


def _redact_text(value, secrets, *, all_urls=False):
    def url(match):
        try:
            keys = {key.lower() for key, _ in parse_qsl(urlsplit(match.group()).query)}
            sensitive = bool(keys & (SECRET_KEYS | {"code", "state"}))
        except ValueError:
            sensitive = True
        return "[REDACTED_URL]" if sensitive or all_urls else match.group()
    result = re.sub(r"https?://[^\s<>\"']+", url, value, flags=re.IGNORECASE)
    for secret in sorted(secrets, key=len, reverse=True):
        if secret:
            for spelling in {secret, quote(secret, safe="")}:
                result = result.replace(spelling, "[REDACTED]")
    return result


def redact(value, secrets, sensitive_paths=(), path="", *, all_urls=False):
    if any(fnmatch.fnmatchcase(path, pattern) for pattern in sensitive_paths):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {_redact_text(key, secrets, all_urls=all_urls): "[REDACTED]" if key.lower() in SECRET_KEYS else
                redact(item, secrets, sensitive_paths, path + "/" + key.replace("~", "~0").replace("/", "~1"), all_urls=all_urls)
                for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item, secrets, sensitive_paths, path + "/" + str(index), all_urls=all_urls) for index, item in enumerate(value)]
    if isinstance(value, str):
        return _redact_text(value, secrets, all_urls=all_urls)
    return value


class ArtifactStore:
    def __init__(self, directory: Path, *, clock=time.time, ttl=3600, max_bytes=32_000_000):
        if not math.isfinite(ttl) or ttl <= 0 or max_bytes <= 0:
            raise ValueError("Artifact limits must be positive")
        self.directory = Path(directory).resolve()
        self.clock, self.ttl, self.max_bytes = clock, ttl, max_bytes
        self.session = random_secrets.token_hex(16)
        self.records = {}
        self.cleanup()

    @staticmethod
    @contextlib.contextmanager
    def _directory_fd(path, *, parent=None):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            info = os.fstat(fd)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o022:
                raise ResultError("Artifact directory must be owned and not writable by others")
            yield fd
        finally:
            os.close(fd)

    def save(self, content: bytes, mime_type: str):
        if not isinstance(content, bytes):
            raise ResultError("Artifact content must be bytes")
        self.cleanup()
        if len(self.records) >= 1024 or len(content) + sum(record["size"] for record in self.records.values()) > self.max_bytes:
            raise ResultError("artifact_capacity_exceeded")
        artifact_id = random_secrets.token_hex(16)
        expiry_ms = math.ceil((self.clock() + self.ttl) * 1000)
        directory_name = "session-" + self.session
        filename = f"{expiry_ms}-{artifact_id}"
        path = self.directory / directory_name / filename
        try:
            self.directory.mkdir(parents=True, mode=0o700, exist_ok=True)
            with self._directory_fd(self.directory) as root:
                try:
                    os.mkdir(directory_name, mode=0o700, dir_fd=root)
                except FileExistsError:
                    pass
                with self._directory_fd(directory_name, parent=root) as session:
                    fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=session)
                    try:
                        with os.fdopen(fd, "wb") as stream:
                            stream.write(content)
                            stream.flush()
                            os.fsync(stream.fileno())
                    except OSError:
                        os.unlink(filename, dir_fd=session)
                        raise
        except OSError:
            raise ResultError("artifact_persistence_failed") from None
        uri = f"shopee-artifact://{self.session}/{artifact_id}"
        record = {"uri": uri, "path": str(path), "size": len(content), "mime_type": mime_type,
                  "expires_at": expiry_ms / 1000, "sha256": hashlib.sha256(content).hexdigest()}
        self.records[uri] = record
        return dict(record)

    def read(self, uri):
        record = self.records.get(str(uri))
        if record is None or record["expires_at"] <= self.clock():
            self.cleanup()
            raise ResultError("Unknown or expired artifact")
        try:
            with self._directory_fd(self.directory) as root, self._directory_fd("session-" + self.session, parent=root) as session:
                fd = os.open(Path(record["path"]).name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=session)
                with os.fdopen(fd, "rb") as stream:
                    info = os.fstat(fd)
                    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
                        raise ResultError("Artifact changed")
                    content = stream.read(record["size"] + 1)
            if len(content) != record["size"] or hashlib.sha256(content).hexdigest() != record["sha256"]:
                raise ResultError("Artifact changed")
            return content, record["mime_type"]
        except OSError:
            raise ResultError("Artifact unavailable") from None

    def cleanup(self, *, all_records=False):
        if not self.directory.exists():
            return
        for uri, record in list(self.records.items()):
            if all_records or record["expires_at"] <= self.clock():
                try:
                    with self._directory_fd(self.directory) as root, self._directory_fd("session-" + self.session, parent=root) as session:
                        os.unlink(Path(record["path"]).name, dir_fd=session)
                except FileNotFoundError:
                    pass
                del self.records[uri]
        # Expiry is persisted in the filename so a later process can reap files
        # left by a crash. Never follow links or touch arbitrary directory names.
        budget = 4096
        try:
            with self._directory_fd(self.directory) as root, os.scandir(root) as sessions:
                for entry in sessions:
                    budget -= 1
                    if budget <= 0:
                        break
                    if not re.fullmatch(r"session-[0-9a-f]{32}", entry.name):
                        continue
                    try:
                        with self._directory_fd(entry.name, parent=root) as session, os.scandir(session) as files:
                            for file in files:
                                budget -= 1
                                if budget <= 0:
                                    break
                                match = re.fullmatch(r"([0-9]{1,17})-[0-9a-f]{32}", file.name)
                                if not match or int(match[1]) > self.clock() * 1000:
                                    continue
                                info = file.stat(follow_symlinks=False)
                                if stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600:
                                    os.unlink(file.name, dir_fd=session)
                        try:
                            os.rmdir(entry.name, dir_fd=root)
                        except OSError:
                            pass  # Still contains unexpired or unrelated files.
                    except (OSError, ResultError):
                        continue
        except FileNotFoundError:
            pass


def _unknown_fields(value, schema, path=""):
    found = []
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        for key, item in value.items():
            pointer = path + "/" + key.replace("~", "~0").replace("/", "~1")
            if key not in properties:
                found.append(pointer)
            else:
                found.extend(_unknown_fields(item, properties[key], pointer))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found.extend(_unknown_fields(item, schema.get("items", {}), path + "/" + str(index)))
    return found


def error_result(endpoint, context, version, kind, *, outcome="failed", retryable=False, status=None):
    return {"ok": False, "meta": {"api": endpoint["api_name"], "context": context, "catalog_version": version,
            "request_id": None, "outcome": outcome, "partial": False}, "data": None,
            "error": {"kind": kind, "code": None, "message": kind, "retryable": retryable, "http_status": status}}


def _bounded(result, artifacts, inline_bytes):
    raw = json.dumps(result, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()
    # The envelope has irreducible overhead even when inline data is disabled.
    if len(raw) <= max(2048, inline_bytes):
        return result
    artifact = artifacts.save(raw, "application/json")
    artifact["content"] = "response_envelope"
    previous = result["meta"]
    meta = {key: previous[key] for key in ("api", "context", "catalog_version", "outcome")}
    request_id = previous.get("request_id")
    meta.update(partial=True, metadata_in_artifact=True,
                request_id=request_id if isinstance(request_id, str) and len(request_id) <= 256 else None)
    error = result["error"]
    if error:
        code = error.get("code")
        error = {"kind": error["kind"], "code": code if isinstance(code, str) and len(code) <= 128 else None,
                 "message": "Full error details are available in the artifact", "retryable": error.get("retryable", False)}
    return {"ok": result["ok"], "meta": meta, "data": {"artifact": artifact}, "error": error}


def build_result(endpoint, payload, context, version, output, secrets, artifacts, *, inline_bytes=24_000):
    if not isinstance(payload, dict):
        raise ResultError("invalid_response")
    meta = {"api": endpoint["api_name"], "context": context, "catalog_version": version,
            "request_id": payload.get("request_id"), "outcome": "succeeded", "partial": False}
    error_code, message = payload.get("error"), payload.get("message", "")
    if error_code and not message and "error_message_field" in endpoint:
        message = payload.get(endpoint["error_message_field"], "")
    if not error_code and "business_status" in endpoint:
        status = endpoint["business_status"]
        code = payload.get(status["code_field"])
        if type(code) is not int:
            raise ResultError("invalid_response: malformed business status")
        if code != status["success_value"]:
            error_code, message = str(code), payload.get(status["message_field"], "")
    if error_code:
        if not isinstance(message, str):
            raise ResultError("invalid_response: malformed error message")
        meta["outcome"] = "failed"
        result = {"ok": False, "meta": meta, "data": None, "error": {
            "kind": "shopee_error", "code": error_code,
            "message": _redact_text(str(message), secrets, all_urls=True), "retryable": False}}
        return _bounded(redact(result, secrets, endpoint.get("sensitive_paths", [])), artifacts, inline_bytes)
    if endpoint["encoding"] == "binary" and "_binary" in payload:
        data = {"artifact": artifacts.save(payload["_binary"], payload["_mime_type"])}
        return {"ok": True, "meta": meta, "data": data, "error": None}
    key = endpoint["response_key"]
    if key is None:
        data = {k: v for k, v in payload.items() if k not in {"error", "message", "request_id", "warning"}}
    elif key not in payload:
        raise ResultError("invalid_response: missing response object")
    else:
        data = payload[key]
    try:
        data = from_wire(data, endpoint["response_schema"])
    except InputError:
        raise ResultError("invalid_response: malformed identifier") from None
    if not Draft202012Validator(endpoint["response_schema"]).is_valid(data):
        raise ResultError("invalid_response: response schema mismatch")
    try:
        data = sanitize_embedded_json(data, endpoint.get("embedded_json_paths", []),
                                     lambda value: redact(value, secrets))
    except (ValueError, TypeError, RecursionError):
        raise ResultError("invalid_response: malformed embedded JSON") from None
    data = redact(data, secrets, endpoint.get("sensitive_paths", []))
    unknown = _unknown_fields(data, endpoint["response_schema"])
    if unknown:
        meta["unknown_fields"] = unknown[:100]
        meta["unknown_field_count"] = len(unknown)
    if payload.get("warning"):
        # Some first-party envelopes document object[] warnings. Preserve the
        # structure so key-based redaction still sees newly returned secrets.
        meta["warning"] = redact(payload["warning"], secrets, all_urls=True)
    failed_fields = endpoint.get("batch_failure_fields", [])
    failed_paths = endpoint.get("batch_failure_paths", [])
    if any(data.get(field) for field in failed_fields) or has_batch_failure(data, failed_paths):
        meta.update(outcome="partial", partial=True)
    if output.get("fields"):
        keep = set(output["fields"]) | set(endpoint.get("pagination_fields", [])) | set(failed_fields)
        keep.update(path.split("/")[1] for path in failed_paths)
        data = {k: v for k, v in data.items() if k in keep}
        meta["partial"] = True
    raw = json.dumps(data, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()
    if len(raw) > inline_bytes:
        artifact = artifacts.save(raw, "application/json")
        counts = {key: len(value) for key, value in data.items() if isinstance(value, list)}
        summary = {key: data[key] for key in endpoint.get("pagination_fields", []) if key in data}
        data = {"artifact": artifact, "counts": counts, "pagination": summary}
        meta["partial"] = True
    result = {"ok": True, "meta": meta, "data": data, "error": None}
    return _bounded(redact(result, secrets), artifacts, inline_bytes)
