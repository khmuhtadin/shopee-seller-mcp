"""Stdlib-only credential transactions shared by the CLI and MCP.

Lock files are never replaced/unlinked: flock protects a stable inode. Their
durable, non-secret generation marker survives crashes during remote rotation.
"""
from __future__ import annotations

import asyncio
import contextlib
import fcntl
import hashlib
import json
import os
import stat
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

BASE_URLS = {
    "sandbox": "https://openplatform.sandbox.test-stable.shopee.sg",
    "production": "https://partner.shopeemobile.com",
}

# The legacy shop keys intentionally retain their established names. Tokens
# for other subjects never fall back to that shop or share its persistence keys.
SCOPE_PREFIXES = {
    "shop": "SHOPEE_",
    "merchant": "SHOPEE_MERCHANT_",
    "supplier": "SHOPEE_SUPPLIER_",
    "user": "SHOPEE_USER_",
    "principal": "SHOPEE_PRINCIPAL_",
}

REFRESH_NOT_SENT_REASONS = frozenset({"connect_error", "connect_timeout", "pool_timeout"})


class CredentialError(ValueError):
    """Safe, non-secret diagnostic suitable for the protocol boundary."""


class RefreshNotSent(CredentialError):
    """Marker for a refresh request that definitely did not reach Shopee."""


@dataclass(frozen=True)
class CredentialSnapshot:
    env: str
    base_url: str
    partner_id: int
    partner_key: str = field(repr=False)
    scope: str = "public"
    subject_id: int | None = None
    access_token: str = field(default="", repr=False)
    refresh_token: str = field(default="", repr=False)
    access_token_expires_at: int = 0
    refresh_token_expires_at: int = 0
    auth_expires_at: int = 0

    @property
    def secrets(self) -> set[str]:
        return {value for value in (self.partner_key, self.access_token, self.refresh_token) if value}

    @property
    def binding(self) -> tuple:
        return self.env, self.base_url, self.partner_id, self.scope, self.subject_id


@dataclass(frozen=True)
class TokenUpdate:
    access_token: str = field(repr=False)
    refresh_token: str = field(repr=False)
    access_token_expires_at: int
    refresh_token_expires_at: int


class LocalUpdateTransaction:
    """Owner-locked local environment update shared by CLI and token rotation."""

    def __init__(self, path: Path):
        self.path = path

    def read_values(self) -> dict[str, str]:
        return read_values(self.path)

    def update(self, replacements: dict[str, str]) -> None:
        atomic_update(self.path, replacements)


def read_values(path: Path) -> dict[str, str]:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "r", encoding="utf-8") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.getuid():
                raise CredentialError("Environment file must be an owner-owned regular file with permissions 0600")
            values = {}
            for number, raw in enumerate(stream, 1):
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    raise CredentialError(f"Invalid environment line {number}")
                key, value = line.split("=", 1)
                key, value = key.strip(), value.strip()
                if key in values:
                    raise CredentialError(f"Duplicate environment key on line {number}")
                values[key] = value
            return values
    except (OSError, UnicodeError):
        raise CredentialError("Unable to read environment file") from None


def _positive(values, key, *, optional=False):
    raw = values.get(key, "")
    if not raw or not raw.isascii() or not raw.isdecimal() or int(raw) <= 0:
        if optional:
            return 0  # Unknown access expiry requires refresh; never assumed valid.
        raise CredentialError(f"{key} must be a positive integer")
    return int(raw)


def _secret(values, key):
    value = values.get(key, "")
    if not value or value.strip() != value or value.splitlines() != [value]:
        raise CredentialError(f"Missing or invalid {key}")
    return value


def atomic_update(path: Path, replacements: dict[str, str]) -> None:
    """Preserve unrelated lines; caller must hold the credential transaction lock."""
    read_values(path)
    lines = path.read_text(encoding="utf-8").splitlines()
    seen = set()
    updated = []
    for line in lines:
        key = line.split("=", 1)[0].strip() if "=" in line and not line.lstrip().startswith("#") else ""
        if key in replacements:
            updated.append(f"{key}={replacements[key]}")
            seen.add(key)
        else:
            updated.append(line)
    updated.extend(f"{key}={value}" for key, value in replacements.items() if key not in seen)
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write("\n".join(updated) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(name).unlink(missing_ok=True)


class CredentialStore:
    def __init__(self, path: Path, *, clock: Callable = time.time):
        if path.is_symlink():
            raise CredentialError("Environment file must not be a symlink")
        self.path = path.resolve(strict=True)
        self.clock = clock
        self._bindings = {}
        self._pending = {}
        initial = self.snapshot("public")
        self._partner_binding = initial.binding[:3]
        # Canonical file path means different spellings share one lock namespace.
        digest = hashlib.sha256(os.fsencode(self.path)).hexdigest()
        self.lock_path = self.path.parent / "local-data/shopee-mcp/locks" / f"{digest}.lock"

    def snapshot(self, scope="shop") -> CredentialSnapshot:
        if scope != "public" and scope not in SCOPE_PREFIXES:
            raise CredentialError("Unsupported credential scope")
        values = read_values(self.path)
        env = values.get("SHOPEE_ENV")
        if env not in BASE_URLS or values.get("SHOPEE_BASE_URL", "").rstrip("/") != BASE_URLS[env]:
            raise CredentialError("SHOPEE_BASE_URL does not match SHOPEE_ENV")
        common = dict(env=env, base_url=BASE_URLS[env], partner_id=_positive(values, "SHOPEE_PARTNER_ID"),
                      partner_key=_secret(values, "SHOPEE_PARTNER_KEY"), scope=scope)
        if scope != "public":
            prefix = SCOPE_PREFIXES[scope]
            common.update(subject_id=_positive(values, f"SHOPEE_{scope.upper()}_ID"),
                          access_token=_secret(values, prefix + "ACCESS_TOKEN"),
                          refresh_token=_secret(values, prefix + "REFRESH_TOKEN"),
                          access_token_expires_at=_positive(values, prefix + "ACCESS_TOKEN_EXPIRES_AT", optional=True),
                          refresh_token_expires_at=_positive(values, prefix + "REFRESH_TOKEN_EXPIRES_AT"),
                          auth_expires_at=_positive(values, prefix + "AUTH_EXPIRES_AT"))
        snapshot = CredentialSnapshot(**common)
        if hasattr(self, "_partner_binding") and snapshot.binding[:3] != self._partner_binding:
            raise CredentialError("credential_binding_changed: restart after reviewing configuration")
        previous = self._bindings.setdefault(scope, snapshot.binding)
        if previous != snapshot.binding:
            raise CredentialError("credential_binding_changed: restart after reviewing configuration")
        return snapshot

    @contextlib.contextmanager
    def _locked(self):
        self.lock_path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "r+", encoding="utf-8") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
                raise CredentialError("Unsafe credential lock")
            fcntl.flock(stream, fcntl.LOCK_EX)
            try:
                raw = stream.read()
                try:
                    state = json.loads(raw) if raw else {}
                    if not isinstance(state, dict):
                        raise ValueError()
                except ValueError:
                    raise CredentialError("credential_quarantined: invalid recovery marker") from None
                yield stream, state
            finally:
                fcntl.flock(stream, fcntl.LOCK_UN)

    @staticmethod
    def _mark(stream, state):
        stream.seek(0)
        stream.write(json.dumps(state))
        stream.truncate()
        stream.flush()
        os.fsync(stream.fileno())

    @staticmethod
    def _generation(snapshot):
        return hashlib.sha256(snapshot.refresh_token.encode()).hexdigest()

    @staticmethod
    def _marker_generations(marker):
        if isinstance(marker, str):
            generations = (marker,)
        elif (isinstance(marker, list) and len(marker) == 2
              and all(isinstance(value, str) for value in marker)):
            generations = tuple(marker)
        else:
            raise CredentialError("credential_quarantined: invalid recovery marker")
        if any(len(value) != 64 or any(character not in "0123456789abcdef" for character in value)
               for value in generations):
            raise CredentialError("credential_quarantined: invalid recovery marker")
        return generations

    def _save(self, update, scope):
        prefix = SCOPE_PREFIXES[scope]
        atomic_update(self.path, {prefix + "ACCESS_TOKEN": update.access_token,
                                 prefix + "REFRESH_TOKEN": update.refresh_token,
                                 prefix + "ACCESS_TOKEN_EXPIRES_AT": str(update.access_token_expires_at),
                                 prefix + "REFRESH_TOKEN_EXPIRES_AT": str(update.refresh_token_expires_at)})

    @contextlib.contextmanager
    def local_update(self):
        """Hold the credential lock across a local read/validate/update transaction."""
        with self._locked():
            yield LocalUpdateTransaction(self.path)

    def update_local(self, replacements: dict[str, str]) -> None:
        """Atomically update local fields in the shared credential lock namespace."""
        with self.local_update() as transaction:
            transaction.update(replacements)

    def ensure(self, refresh: Callable, *, scope="shop", force=False, safety_seconds=300,
               rejected_snapshot: CredentialSnapshot | None = None):
        initial = self.snapshot(scope)
        if scope == "public":
            return initial
        with self._locked() as (stream, state):
            current = self.snapshot(scope)
            generation = self._generation(current)
            if rejected_snapshot is not None and (
                    rejected_snapshot.scope != scope or rejected_snapshot.binding != current.binding):
                raise CredentialError("credential_binding_mismatch: rejected snapshot does not match current scope")
            if scope in state:
                if generation in self._marker_generations(state[scope]):
                    raise CredentialError("credential_quarantined: verify rotation or reauthorize; do not retry old token")
                # New externally authorized generation is not the uncertain one.
                state.pop(scope)
                self._mark(stream, state)
            now = int(self.clock())
            if now >= min(current.auth_expires_at, current.refresh_token_expires_at):
                raise CredentialError("Shopee authorization expired; reauthorize the configured credential scope")
            if current.access_token_expires_at > now + safety_seconds:
                if not force:
                    return current
                if rejected_snapshot is not None:
                    if (current.access_token != rejected_snapshot.access_token
                            or generation != self._generation(rejected_snapshot)):
                        return current
                elif generation != self._generation(initial):
                    return current
            for attempt in range(2):
                state[scope] = generation
                self._mark(stream, state)  # Durable BEFORE every possible remote mutation.
                try:
                    update = refresh(current)
                    for key in ("access_token", "refresh_token"):
                        value = getattr(update, key)
                        _secret({key: value}, key)
                    if any(type(getattr(update, key)) is not int or getattr(update, key) <= now
                           for key in ("access_token_expires_at", "refresh_token_expires_at")):
                        raise CredentialError("Invalid refresh expiry")
                except RefreshNotSent as error:
                    state.pop(scope, None)
                    self._mark(stream, state)
                    if attempt == 0:
                        continue
                    reason = str(error)
                    detail = f": {reason}" if reason in REFRESH_NOT_SENT_REASONS else ""
                    raise CredentialError(f"refresh_not_sent{detail}") from None
                except Exception:
                    raise CredentialError("refresh_outcome_unknown: credential quarantined; verify rotation or reauthorize") from None
                break
            new_generation = self._generation(update)
            self._pending[scope] = (generation, new_generation, update)
            try:
                state[scope] = [generation, new_generation]
                self._mark(stream, state)
                self._save(update, scope)
            except Exception:
                raise CredentialError("credential_persistence_failed: retry local save or reauthorize") from None
            state.pop(scope, None)
            self._mark(stream, state)
            self._pending.pop(scope, None)
            return self.snapshot(scope)

    async def ensure_async(self, refresh: Callable, **kwargs):
        # Cancellation cannot interrupt a thread holding the refresh lock. The
        # transaction safely finishes persistence; no business call follows it.
        return await asyncio.to_thread(self.ensure, refresh, **kwargs)

    def retry_save(self, scope="shop"):
        if scope not in self._pending:
            raise CredentialError("No pending in-memory rotation to save")
        old_generation, new_generation, update = self._pending[scope]
        with self._locked() as (stream, state):
            marker = state.get(scope)
            if marker is None:
                raise CredentialError("credential_generation_changed: refusing stale save")
            marker_generations = self._marker_generations(marker)
            current_generation = self._generation(self.snapshot(scope))
            if (marker_generations != (old_generation, new_generation)
                    or current_generation not in marker_generations):
                raise CredentialError("credential_generation_changed: refusing stale save")
            try:
                self._save(update, scope)
            except Exception:
                raise CredentialError("credential_persistence_failed") from None
            state.pop(scope)
            self._mark(stream, state)
            self._pending.pop(scope, None)
            return self.snapshot(scope)
