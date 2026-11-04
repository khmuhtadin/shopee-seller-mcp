"""Web-based shop onboarding for the remote HTTP mode (operator only).

The HTTP app owns the browser flow (passphrase login, CSRF, throttling); this
module owns the file side:

* Partner credentials come only from the server environment
  (``SHOPEE_PARTNER_ID``/``SHOPEE_PARTNER_KEY`` and optionally
  ``SHOPEE_SANDBOX_PARTNER_ID``/``SHOPEE_SANDBOX_PARTNER_KEY``). They are never
  entered in, or sent to, the browser.
* ``start`` creates a single-use, expiring authorization ``state`` bound to the
  admin session and returns the Shopee authorization URL.
* ``complete`` exchanges the authorization code by reusing the CLI exchange
  logic (``auth_cli.exchange_authorization_code``) against a freshly created,
  owner-only env file in ``<data-dir>/shops/``.
* ``write_config`` replaces the shops JSON atomically (temp file + rename).

Nothing here logs or returns authorization codes, tokens or partner keys.
"""
from __future__ import annotations

import contextlib
import hmac
import json
import os
import secrets
import stat
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Mapping
from urllib.parse import urlencode

from .auth_cli import (ALLOWED_BASE_URLS, ConfigError, PartnerConfig, ShopeeAPIError, _atomic_write,
                       _open_without_redirects, _validate_redirect_url, build_authorization_url,
                       exchange_authorization_code, load_partner_config)
from .credentials import CredentialError, CredentialStore
from .multi_shop import MAX_SHOPS, _valid_alias, load_shop_config

ENVIRONMENTS = ("sandbox", "production")
AUTHORIZATION_DAYS = (7, 30, 90, 180, 365)
DEFAULT_AUTHORIZATION_DAYS = 365
PENDING_TTL = 900          # seconds a started "Add shop" flow stays valid
MAX_PENDING = 64
SHOPS_SUBDIR = "shops"


class ShopAdminError(ValueError):
    """Safe, secret-free and path-free message suitable for the admin page."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class PartnerCredentials:
    partner_id: int
    partner_key: str = field(repr=False)


@dataclass(frozen=True)
class PendingAuthorization:
    alias: str
    env: str
    session: str = field(repr=False)   # hash of the admin session that started the flow
    expires_at: float
    days: int


def partner_credentials_from_env(environ: Mapping[str, str] | None = None) -> dict[str, PartnerCredentials]:
    """``{"production": ..., "sandbox": ...}`` from server environment variables.

    ``SHOPEE_PARTNER_ID``/``SHOPEE_PARTNER_KEY`` are used for production. The
    sandbox uses ``SHOPEE_SANDBOX_PARTNER_ID``/``SHOPEE_SANDBOX_PARTNER_KEY`` when
    set and otherwise falls back to the main pair (for operators whose only app
    is a sandbox test app).
    """
    environ = os.environ if environ is None else environ

    def pair(id_key: str, key_key: str) -> PartnerCredentials | None:
        partner_id = (environ.get(id_key) or "").strip()
        partner_key = (environ.get(key_key) or "").strip()
        if not partner_id and not partner_key:
            return None
        if not partner_id or not partner_key:
            raise ShopAdminError(f"{id_key} and {key_key} must be set together")
        if not partner_id.isascii() or not partner_id.isdecimal() or int(partner_id) <= 0:
            raise ShopAdminError(f"{id_key} must be a positive integer")
        if partner_key.splitlines() != [partner_key]:
            raise ShopAdminError(f"{key_key} must be a single line")
        return PartnerCredentials(int(partner_id), partner_key)

    main = pair("SHOPEE_PARTNER_ID", "SHOPEE_PARTNER_KEY")
    sandbox = pair("SHOPEE_SANDBOX_PARTNER_ID", "SHOPEE_SANDBOX_PARTNER_KEY")
    result = {}
    if main is not None:
        result["production"] = main
    if sandbox is not None or main is not None:
        result["sandbox"] = sandbox or main
    return result


def _fsync_directory(directory: Path) -> None:
    with contextlib.suppress(OSError):
        fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


class ShopManager:
    """File-side operations for adding/removing shops. Thread-safe only under the caller's lock."""

    def __init__(self, shops_file: Path | str, data_dir: Path | str, public_url: str | None,
                 partners: Mapping[str, PartnerCredentials], *, opener: Callable = _open_without_redirects,
                 clock: Callable[[], float] = time.time):
        self.shops_file = Path(os.fspath(shops_file))
        self.data_dir = Path(os.fspath(data_dir))
        for path in (self.shops_file, self.data_dir):
            raw = os.fspath(path)
            if not os.path.isabs(raw) or os.path.normpath(raw) != raw:
                raise ShopAdminError("shops file and data directory must be absolute, normalized paths")
        self.shops_dir = self.data_dir / SHOPS_SUBDIR
        self.redirect_url: str | None = None
        if public_url:
            try:
                self.redirect_url = _validate_redirect_url(public_url.rstrip("/") + "/callback")
            except ConfigError:
                self.redirect_url = None  # http/loopback testing: onboarding disabled, listing still works
        self.partners = {env: creds for env, creds in partners.items() if env in ENVIRONMENTS}
        self.opener = opener
        self.clock = clock
        self._pending: dict[str, PendingAuthorization] = {}

    # ----------------------------------------------------------- reading

    def available_environments(self) -> list[str]:
        if self.redirect_url is None:
            return []
        return [env for env in ENVIRONMENTS if env in self.partners]

    def read_config(self) -> dict[str, Path]:
        return load_shop_config(self.shops_file)

    def describe(self) -> list[dict]:
        """Alias, environment and authorization expiry only. No ids, paths or secrets."""
        now = int(self.clock())
        rows = []
        for alias, path in sorted(self.read_config().items()):
            row = {"alias": alias, "env": "unknown", "expires_at": None, "status": "invalid"}
            try:
                snapshot = CredentialStore(path).snapshot("shop")
                expires = min(snapshot.auth_expires_at, snapshot.refresh_token_expires_at)
                row.update(env=snapshot.env, expires_at=expires, status="expired" if expires <= now else "ok")
            except (CredentialError, OSError):
                pass
            rows.append(row)
        return rows

    # ------------------------------------------------------------- flows

    def _prune(self) -> None:
        now = self.clock()
        for state in [key for key, value in self._pending.items() if value.expires_at <= now]:
            del self._pending[state]

    def start(self, alias: str, env: str, session: str, days: int = DEFAULT_AUTHORIZATION_DAYS) -> str:
        """Register a single-use pending state and return the Shopee authorization URL."""
        if not _valid_alias(alias):
            raise ShopAdminError("Alias must be 1-32 characters: lowercase letters, digits, '-' or '_', "
                                 "starting with a letter or digit.")
        if env not in self.available_environments():
            raise ShopAdminError("That environment is not configured on the server.")
        if days not in AUTHORIZATION_DAYS:
            raise ShopAdminError("Unsupported authorization period.")
        if not session:
            raise ShopAdminError("Admin session required.", status=403)
        try:
            shops = self.read_config()
        except CredentialError:
            raise ShopAdminError("The shops file is invalid; fix it before adding shops.", status=500) from None
        if alias in shops:
            raise ShopAdminError("That alias is already in use.")
        if len(shops) >= MAX_SHOPS:
            raise ShopAdminError("The maximum number of shops is already configured.")
        self._prune()
        if len(self._pending) >= MAX_PENDING:
            raise ShopAdminError("Too many authorizations in progress; try again later.", status=429)
        state = secrets.token_urlsafe(32)
        self._pending[state] = PendingAuthorization(alias, env, session, self.clock() + PENDING_TTL, days)
        creds = self.partners[env]
        config = PartnerConfig(env, ALLOWED_BASE_URLS[env], creds.partner_id, creds.partner_key,
                               self.redirect_url, state, self.shops_dir / "unused.env")
        return build_authorization_url(config, state)

    def take_pending(self, state: str | None) -> PendingAuthorization | None:
        """Single use: the state is consumed whether or not the callback succeeds."""
        if not isinstance(state, str) or not state or len(state) > 200:
            return None
        self._prune()
        for known in list(self._pending):
            if hmac.compare_digest(known, state):
                return self._pending.pop(known)
        return None

    def _ensure_shops_dir(self) -> None:
        try:
            self.shops_dir.mkdir(mode=0o700, parents=False, exist_ok=True)
            info = os.lstat(self.shops_dir)
        except OSError:
            raise ShopAdminError("The data directory is not writable.", status=500) from None
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077):
            raise ShopAdminError("The shops directory must be owned by the server user with mode 0700.", status=500)

    def complete(self, pending: PendingAuthorization, code: str, shop_id: str, state: str) -> Path:
        """Exchange the code into a new owner-only env file. Returns its path (not yet in the config)."""
        if self.redirect_url is None or pending.env not in self.partners:
            raise ShopAdminError("Shop onboarding is not configured.", status=500)
        self._ensure_shops_dir()
        final = self.shops_dir / f"{pending.alias}.env"
        if os.path.lexists(final):
            raise ShopAdminError("A credential file for this alias already exists; remove the shop first.", status=409)
        creds = self.partners[pending.env]
        staging = self.shops_dir / f".pending-{pending.alias}-{secrets.token_hex(6)}.env"
        values = {
            "SHOPEE_ENV": pending.env,
            "SHOPEE_BASE_URL": ALLOWED_BASE_URLS[pending.env],
            "SHOPEE_PARTNER_ID": str(creds.partner_id),
            "SHOPEE_PARTNER_KEY": creds.partner_key,
            "SHOPEE_REDIRECT_URL": self.redirect_url,
            "SHOPEE_AUTH_STATE": state,
        }
        callback_url = self.redirect_url + "?" + urlencode({"code": code, "shop_id": shop_id, "state": state})
        try:
            try:
                _atomic_write(staging, "".join(f"{k}={v}\n" for k, v in values.items()), replace=False,
                              failure_message="Unable to create the shop credential file")
                exchange_authorization_code(load_partner_config(staging), callback_url, pending.days,
                                            opener=self.opener, clock=self.clock)
            except ShopeeAPIError as error:
                code_text = error.code if isinstance(error.code, str) and error.code.isprintable() else None
                detail = f" (Shopee error: {code_text[:64]})" if code_text else ""
                raise ShopAdminError(f"Shopee did not accept the authorization{detail}. Start again.", status=502) from None
            except (ConfigError, CredentialError, OSError):
                raise ShopAdminError("The authorization response was invalid. Start again.", status=400) from None
            try:
                os.link(staging, final)
            except FileExistsError:
                raise ShopAdminError("A credential file for this alias already exists; remove the shop first.",
                                     status=409) from None
            except OSError:
                raise ShopAdminError("Unable to save the shop credential file.", status=500) from None
        finally:
            with contextlib.suppress(OSError):
                staging.unlink()
        _fsync_directory(self.shops_dir)
        return final

    # ------------------------------------------------------------ writes

    def write_config(self, shops: Mapping[str, Path]) -> None:
        """Atomically replace the shops JSON (owner-only, same directory, fsync + rename)."""
        body = json.dumps({"shops": {alias: os.fspath(path) for alias, path in sorted(shops.items())}}, indent=2) + "\n"
        directory = self.shops_file.parent
        try:
            fd, name = tempfile.mkstemp(dir=directory, prefix=f".{self.shops_file.name}.")
        except OSError:
            raise ShopAdminError("Unable to update the shops file.", status=500) from None
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(body)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, self.shops_file)
        except OSError:
            raise ShopAdminError("Unable to update the shops file.", status=500) from None
        finally:
            with contextlib.suppress(OSError):
                os.unlink(name)
        _fsync_directory(directory)

    def is_managed(self, path: Path) -> bool:
        """True for env files this manager created (only those are deleted on removal)."""
        return Path(os.fspath(path)).parent == self.shops_dir and Path(path).suffix == ".env"

    def delete_env_file(self, path: Path) -> None:
        if self.is_managed(path):
            with contextlib.suppress(OSError):
                os.unlink(path)
            _fsync_directory(self.shops_dir)


def create_empty_shops_file(path: Path) -> None:
    """``{"shops": {}}`` with mode 0600 if the file does not exist yet."""
    with contextlib.suppress(FileExistsError):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write('{"shops": {}}\n')
