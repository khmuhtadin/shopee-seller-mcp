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
* ``complete_main_account`` handles a *main account* callback (``code`` +
  ``main_account_id``): it exchanges the code once, keeps the result in memory
  (bound to the admin session, single use, 15 minutes) and lets the operator
  pick shops and aliases. ``add_main_account_shops`` then refreshes each chosen
  shop separately (Shopee refreshes per ``shop_id``) so every shop gets its own
  independent token pair in its own env file.
* ``write_config`` replaces the shops JSON atomically (temp file + rename).
* ``InviteStore`` keeps operator-created *invite links* in an owner-only JSON
  file in the data directory (only a SHA-256 hash of each invite token is
  stored). ``start_invite`` / ``complete_invite`` let a remote seller authorize
  shops through an invite without the admin passphrase; shops are added with
  automatic aliases that the operator can rename later.

Nothing here logs or returns authorization codes, tokens or partner keys.
"""
from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import os
import secrets
import stat
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Mapping
from urllib.parse import urlencode

from .auth_cli import (ALLOWED_BASE_URLS, ConfigError, PartnerConfig, ShopeeAPIError, _atomic_write,
                       _open_without_redirects, _validate_redirect_url, build_authorization_url,
                       exchange_authorization_code, exchange_main_account_code, fetch_shop_name,
                       load_partner_config, parse_positive_id, refresh_shop_token, shop_env_text)
from .credentials import CredentialError, CredentialStore
from .multi_shop import MAX_SHOPS, _valid_alias, load_shop_config

ENVIRONMENTS = ("sandbox", "production")
AUTHORIZATION_DAYS = (7, 30, 90, 180, 365)
DEFAULT_AUTHORIZATION_DAYS = 365
PENDING_TTL = 900          # seconds a started "Add shop" flow stays valid
MAX_PENDING = 64
SHOPS_SUBDIR = "shops"


MAX_MAIN_GRANTS = 16
INVITES_FILE = "invites.json"
INVITE_TTLS = {"1h": 3600, "24h": 86400, "72h": 3 * 86400, "7d": 7 * 86400}
DEFAULT_INVITE_TTL = "24h"
MAX_ACTIVE_INVITES = 20
MAX_INVITE_RECORDS = 100     # used/revoked/expired records kept for display, newest first
INVITE_RECORD_RETENTION = 30 * 86400
INVITE_LABEL_MAX = 40


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
    invite: str | None = None          # invite id when the flow was started from an invite link


@dataclass
class InviteResult:
    """Outcome of an invite authorization. Aliases and names only; no ids or tokens leave this module."""
    added: dict[str, Path]
    names: dict[str, str | None]
    already_connected: int = 0
    failed: int = 0


@dataclass
class MainAccountGrant:
    """In-memory result of a main-account exchange awaiting the operator's shop selection."""
    grant_id: str = field(repr=False)
    session: str = field(repr=False)
    env: str
    days: int
    alias_prefix: str
    main_account_id: int
    shop_ids: tuple[int, ...]
    names: dict[int, str | None]
    refresh_token: str = field(repr=False)
    auth_expires_at: int
    expires_at: float


def _slug(name: str | None) -> str:
    if not name:
        return ""
    out, dash = [], False
    for char in name.lower():
        if char.isascii() and char.isalnum():
            out.append(char)
            dash = False
        elif out and not dash:
            out.append("-")
            dash = True
    return "".join(out).strip("-")[:32].strip("-")


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


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _clean_label(label: str | None) -> str:
    label = (label or "").strip()
    if len(label) > INVITE_LABEL_MAX or not label.isprintable():
        raise ShopAdminError(f"The label must be at most {INVITE_LABEL_MAX} printable characters.")
    return label


class InviteStore:
    """Invite links in an owner-only JSON file. Stores ``sha256(token)``, never the token.

    Every operation reads the file, changes it in memory and replaces it
    atomically, under a process-wide lock (the server runs one instance per data
    directory).
    """

    def __init__(self, path: Path, clock: Callable[[], float] = time.time):
        self.path = path
        self.clock = clock
        self._lock = threading.Lock()

    # -------------------------------------------------------------- io

    def _load(self) -> list[dict]:
        try:
            fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return []
        except OSError:
            raise ShopAdminError("The invites file could not be read.", status=500) from None
        try:
            with os.fdopen(fd, "r", encoding="utf-8") as stream:
                info = os.fstat(stream.fileno())
                if info.st_uid != os.getuid() or info.st_mode & 0o077:
                    raise ShopAdminError("The invites file must be owned by the server user with mode 0600.",
                                         status=500)
                data = json.load(stream)
        except (OSError, ValueError):
            raise ShopAdminError("The invites file could not be read.", status=500) from None
        records = data.get("invites") if isinstance(data, dict) else None
        if not isinstance(records, list):
            raise ShopAdminError("The invites file is invalid.", status=500)
        return [record for record in records if isinstance(record, dict) and isinstance(record.get("id"), str)
                and isinstance(record.get("hash"), str)]

    def _save(self, records: list[dict]) -> None:
        body = json.dumps({"invites": records}, indent=2, sort_keys=True) + "\n"
        directory = self.path.parent
        try:
            fd, name = tempfile.mkstemp(dir=directory, prefix=f".{self.path.name}.")
        except OSError:
            raise ShopAdminError("Unable to update the invites file.", status=500) from None
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(body)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, self.path)
        except OSError:
            raise ShopAdminError("Unable to update the invites file.", status=500) from None
        finally:
            with contextlib.suppress(OSError):
                os.unlink(name)
        _fsync_directory(directory)

    # ----------------------------------------------------------- helpers

    @staticmethod
    def status(record: Mapping, now: float) -> str:
        if record.get("revoked_at"):
            return "revoked"
        if record.get("used_at"):
            return "used"
        expires = record.get("expires_at")
        if not isinstance(expires, (int, float)) or expires <= now:
            return "expired"
        return "active"

    def _prune(self, records: list[dict], now: float) -> list[dict]:
        keep = []
        for record in records:
            if self.status(record, now) != "active":
                ended = max(float(record.get(key) or 0) for key in ("expires_at", "used_at", "revoked_at"))
                if ended + INVITE_RECORD_RETENTION <= now:
                    continue
            keep.append(record)
        keep.sort(key=lambda record: record.get("created_at") or 0, reverse=True)
        return keep[:MAX_INVITE_RECORDS]

    @staticmethod
    def _public(record: Mapping, now: float) -> dict:
        return {"id": record["id"], "label": record.get("label") or "", "env": record.get("env") or "",
                "created_at": record.get("created_at"), "expires_at": record.get("expires_at"),
                "used_at": record.get("used_at"), "status": InviteStore.status(record, now),
                "shops": list(record.get("shops") or [])}

    # --------------------------------------------------------- operations

    def create(self, env: str, ttl: str, label: str | None) -> tuple[str, dict]:
        """Returns ``(token, public record)``. The token is shown once and never stored."""
        if ttl not in INVITE_TTLS:
            raise ShopAdminError("Unsupported invite lifetime.")
        label = _clean_label(label)
        with self._lock:
            now = self.clock()
            records = self._prune(self._load(), now)
            if sum(1 for record in records if self.status(record, now) == "active") >= MAX_ACTIVE_INVITES:
                raise ShopAdminError("Too many active invite links; revoke one first.", status=429)
            token = secrets.token_urlsafe(32)
            record = {"id": secrets.token_hex(8), "hash": _hash_token(token), "label": label, "env": env,
                      "created_at": int(now), "expires_at": int(now) + INVITE_TTLS[ttl], "used_at": None,
                      "revoked_at": None, "shops": []}
            records.insert(0, record)
            self._save(records[:MAX_INVITE_RECORDS])
            return token, self._public(record, now)

    def list_invites(self) -> list[dict]:
        with self._lock:
            now = self.clock()
            return [self._public(record, now) for record in self._prune(self._load(), now)]

    def find_active(self, token: object) -> dict | None:
        """Active invite for a presented token (constant-time hash comparison), else ``None``."""
        if not isinstance(token, str) or not 20 <= len(token) <= 100:
            return None
        digest = _hash_token(token)
        with self._lock:
            now = self.clock()
            found = None
            for record in self._load():
                if hmac.compare_digest(record["hash"], digest):
                    found = record
            if found is None or self.status(found, now) != "active":
                return None
            return self._public(found, now)

    def get(self, invite_id: str | None) -> dict | None:
        if not isinstance(invite_id, str) or not invite_id or len(invite_id) > 64:
            return None
        with self._lock:
            now = self.clock()
            for record in self._load():
                if hmac.compare_digest(record["id"], invite_id):
                    return self._public(record, now)
        return None

    def _update(self, invite_id: str, change: Callable[[dict, float], bool]) -> bool:
        with self._lock:
            now = self.clock()
            records = self._load()
            for record in records:
                if hmac.compare_digest(record["id"], invite_id):
                    if not change(record, now):
                        return False
                    self._save(self._prune(records, now))
                    return True
        return False

    def revoke(self, invite_id: str | None) -> bool:
        if not isinstance(invite_id, str) or not invite_id or len(invite_id) > 64:
            return False

        def change(record, now):
            if self.status(record, now) != "active":
                return False
            record["revoked_at"] = int(now)
            return True
        return self._update(invite_id, change)

    def mark_used(self, invite_id: str, aliases: list[str]) -> bool:
        def change(record, now):
            if record.get("used_at") or record.get("revoked_at"):
                return False
            record["used_at"] = int(now)
            record["shops"] = sorted(set(aliases))
            return True
        return self._update(invite_id, change)

    def rename_alias(self, old: str, new: str) -> None:
        with self._lock:
            now = self.clock()
            records = self._load()
            changed = False
            for record in records:
                shops = record.get("shops") or []
                if old in shops:
                    record["shops"] = sorted({new if alias == old else alias for alias in shops})
                    changed = True
            if changed:
                self._save(self._prune(records, now))

    def sources(self) -> dict[str, str]:
        """``{alias: invite label}`` for shops that were added through an invite."""
        result = {}
        for record in reversed(self.list_invites()):
            for alias in record["shops"]:
                result[alias] = record["label"] or "(invite)"
        return result


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
        self._grants: dict[str, MainAccountGrant] = {}
        self.invites = InviteStore(self.data_dir / INVITES_FILE, clock)

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
        for grant_id in [key for key, value in self._grants.items() if value.expires_at <= now]:
            del self._grants[grant_id]

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
        return self._register_pending(PendingAuthorization(alias, env, session, self.clock() + PENDING_TTL, days))

    def _register_pending(self, pending: PendingAuthorization) -> str:
        self._prune()
        if len(self._pending) >= MAX_PENDING:
            raise ShopAdminError("Too many authorizations in progress; try again later.", status=429)
        state = secrets.token_urlsafe(32)
        self._pending[state] = pending
        creds = self.partners[pending.env]
        config = PartnerConfig(pending.env, ALLOWED_BASE_URLS[pending.env], creds.partner_id, creds.partner_key,
                               self.redirect_url, state, self.shops_dir / "unused.env")
        return build_authorization_url(config, state)

    def start_invite(self, invite_id: str, env: str, session: str) -> str:
        """Fresh pending state bound to an invite and the invitee's browser. Does not consume the invite."""
        if env not in self.available_environments():
            raise ShopAdminError("That environment is not configured on the server.")
        if not session or not invite_id:
            raise ShopAdminError("Browser session required.", status=403)
        return self._register_pending(PendingAuthorization("", env, session, self.clock() + PENDING_TTL,
                                                           DEFAULT_AUTHORIZATION_DAYS, invite_id))

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

    # ------------------------------------------------- main account flow

    def _partner_config(self, env: str, env_file: Path | None = None) -> PartnerConfig:
        creds = self.partners[env]
        return PartnerConfig(env, ALLOWED_BASE_URLS[env], creds.partner_id, creds.partner_key, self.redirect_url,
                             "", env_file or self.shops_dir / "unused.env")

    def complete_main_account(self, pending: PendingAuthorization, code: str, main_account_id: str) -> MainAccountGrant:
        """Exchange a main-account code once; nothing is written until the operator picks shops."""
        if self.redirect_url is None or pending.env not in self.partners:
            raise ShopAdminError("Shop onboarding is not configured.", status=500)
        try:
            account = parse_positive_id(main_account_id, "main_account_id")
            config = self._partner_config(pending.env)
            tokens = exchange_main_account_code(config, code, account, opener=self.opener, clock=self.clock)
        except ShopeeAPIError as error:
            code_text = error.code if isinstance(error.code, str) and error.code.isprintable() else None
            detail = f" (Shopee error: {code_text[:64]})" if code_text else ""
            raise ShopAdminError(f"Shopee did not accept the authorization{detail}. Start again.", status=502) from None
        except ConfigError:
            raise ShopAdminError("The authorization response was invalid. Start again.", status=400) from None
        if len(tokens.shop_ids) > MAX_SHOPS:
            raise ShopAdminError("The main account authorized more shops than this server supports.", status=400)
        names = {shop_id: fetch_shop_name(config, shop_id, tokens.update.access_token, opener=self.opener,
                                          clock=self.clock) for shop_id in tokens.shop_ids}
        self._prune()
        while len(self._grants) >= MAX_MAIN_GRANTS:
            self._grants.pop(next(iter(self._grants)))
        grant = MainAccountGrant(secrets.token_urlsafe(24), pending.session, pending.env, pending.days, pending.alias,
                                 account, tokens.shop_ids, names, tokens.update.refresh_token,
                                 int(self.clock()) + pending.days * 24 * 60 * 60, self.clock() + PENDING_TTL)
        self._grants[grant.grant_id] = grant
        return grant

    def peek_grant(self, grant_id: str | None, session: str | None) -> MainAccountGrant | None:
        if not isinstance(grant_id, str) or not grant_id or len(grant_id) > 200 or not session:
            return None
        self._prune()
        for known, grant in self._grants.items():
            if hmac.compare_digest(known, grant_id):
                return grant if hmac.compare_digest(grant.session, session) else None
        return None

    def discard_grant(self, grant: MainAccountGrant) -> None:
        self._grants.pop(grant.grant_id, None)

    def _connected_shop_ids(self, shops: Mapping[str, Path]) -> dict[int, str]:
        connected = {}
        for alias, path in shops.items():
            with contextlib.suppress(CredentialError, OSError):
                connected[CredentialStore(path).snapshot("shop").subject_id] = alias
        return connected

    def suggest_aliases(self, grant: MainAccountGrant) -> dict[int, str]:
        """Unique, valid default aliases: shop-name slug, else ``<alias>-<n>``."""
        try:
            taken = set(self.read_config())
        except CredentialError:
            taken = set()
        result: dict[int, str] = {}
        for index, shop_id in enumerate(grant.shop_ids, start=1):
            candidate = _slug(grant.names.get(shop_id))
            if not _valid_alias(candidate) or candidate in taken:
                candidate = f"{grant.alias_prefix}-{index}"[:32] if len(grant.shop_ids) > 1 else grant.alias_prefix
            if not _valid_alias(candidate) or candidate in taken:
                candidate = f"shop-{shop_id}"[:32]
            taken.add(candidate)
            result[shop_id] = candidate
        return result

    def validate_selection(self, grant: MainAccountGrant, selection: Mapping[int, str]) -> None:
        if not selection:
            raise ShopAdminError("Select at least one shop.")
        if not set(selection) <= set(grant.shop_ids):
            raise ShopAdminError("Unknown shop in the selection.")
        try:
            shops = self.read_config()
        except CredentialError:
            raise ShopAdminError("The shops file is invalid; fix it before adding shops.", status=500) from None
        aliases = list(selection.values())
        for alias in aliases:
            if not _valid_alias(alias):
                raise ShopAdminError("Each alias must be 1-32 characters: lowercase letters, digits, '-' or '_', "
                                     "starting with a letter or digit.")
            if alias in shops:
                raise ShopAdminError(f"The alias {alias} is already in use.")
        if len(set(aliases)) != len(aliases):
            raise ShopAdminError("Each selected shop needs a different alias.")
        if len(shops) + len(selection) > MAX_SHOPS:
            raise ShopAdminError("That would exceed the maximum number of shops.")
        connected = self._connected_shop_ids(shops)
        for shop_id in selection:
            if shop_id in connected:
                raise ShopAdminError(f"Shop {shop_id} is already connected as {connected[shop_id]}.", status=409)
        for alias in aliases:
            if os.path.lexists(self.shops_dir / f"{alias}.env"):
                raise ShopAdminError(f"A credential file for {alias} already exists; remove that shop first.",
                                     status=409)

    def add_main_account_shops(self, grant: MainAccountGrant,
                               selection: Mapping[int, str]) -> tuple[dict[str, Path], list[int]]:
        """Refresh each selected shop separately and write its own env file.

        Shops are processed one at a time. A shop whose refresh fails is skipped
        (reported in the second return value); shops already written stay.
        """
        self.validate_selection(grant, selection)
        self._ensure_shops_dir()
        self.discard_grant(grant)  # single use from here on
        config = self._partner_config(grant.env)
        added: dict[str, Path] = {}
        failed: list[int] = []
        for shop_id, alias in selection.items():
            final = self.shops_dir / f"{alias}.env"
            try:
                update = refresh_shop_token(config, shop_id, grant.refresh_token, opener=self.opener, clock=self.clock)
                _atomic_write(final, shop_env_text(config, shop_id, update, grant.auth_expires_at), replace=False,
                              failure_message="Unable to save the shop credential file")
            except (ShopeeAPIError, ConfigError, OSError):
                failed.append(shop_id)
                continue
            added[alias] = final
        _fsync_directory(self.shops_dir)
        return added, failed

    # ------------------------------------------------------- invite flow

    def _auto_alias(self, name: str | None, shop_id: int, taken: set[str]) -> str:
        """Shop-name slug if valid and free, else ``shop-<id>`` (with a numeric suffix if needed)."""
        def free(alias: str) -> bool:
            return _valid_alias(alias) and alias not in taken and not os.path.lexists(self.shops_dir / f"{alias}.env")
        candidate = _slug(name)
        if free(candidate):
            return candidate
        base = f"shop-{shop_id}"[:28]
        candidate, number = base, 2
        while not free(candidate):
            candidate = f"{base}-{number}"
            number += 1
        return candidate

    def complete_invite(self, pending: PendingAuthorization, code: str, state: str, *,
                        shop_id: str | None = None, main_account_id: str | None = None) -> InviteResult:
        """Exchange an invite callback and write env files with automatic aliases (not yet in the config).

        Shops that are already connected are skipped. With a main account every
        shop is refreshed separately; a shop whose refresh fails is skipped.
        """
        if self.redirect_url is None or pending.env not in self.partners:
            raise ShopAdminError("Shop onboarding is not configured.", status=500)
        try:
            shops = self.read_config()
        except CredentialError:
            raise ShopAdminError("The server cannot accept shops right now.", status=500) from None
        connected = self._connected_shop_ids(shops)
        taken = set(shops)
        self._ensure_shops_dir()
        config = self._partner_config(pending.env)
        if shop_id is not None:
            try:
                sid = parse_positive_id(shop_id, "shop_id")
            except ConfigError:
                raise ShopAdminError("The authorization response was invalid.", status=400) from None
            if sid in connected:
                return InviteResult({}, {}, already_connected=1)
            if len(shops) >= MAX_SHOPS:
                raise ShopAdminError("This server cannot accept more shops.", status=409)
            temporary = PendingAuthorization(f"invite-{secrets.token_hex(4)}", pending.env, pending.session,
                                             pending.expires_at, pending.days)
            path = self.complete(temporary, code, shop_id, state)
            try:
                snapshot = CredentialStore(path).snapshot("shop")
                if snapshot.subject_id != sid:
                    raise ShopAdminError("The authorization response was invalid.", status=400)
                name = fetch_shop_name(config, sid, snapshot.access_token, opener=self.opener, clock=self.clock)
                alias = self._auto_alias(name, sid, taken)
                final = self.shops_dir / f"{alias}.env"
                os.link(path, final)
            except (CredentialError, OSError):
                raise ShopAdminError("Unable to save the shop credential file.", status=500) from None
            finally:
                with contextlib.suppress(OSError):
                    os.unlink(path)
            _fsync_directory(self.shops_dir)
            return InviteResult({alias: final}, {alias: name})
        try:
            account = parse_positive_id(main_account_id, "main_account_id")
            tokens = exchange_main_account_code(config, code, account, opener=self.opener, clock=self.clock)
        except ShopeeAPIError as error:
            code_text = error.code if isinstance(error.code, str) and error.code.isprintable() else None
            detail = f" (Shopee error: {code_text[:64]})" if code_text else ""
            raise ShopAdminError(f"Shopee did not accept the authorization{detail}.", status=502) from None
        except ConfigError:
            raise ShopAdminError("The authorization response was invalid.", status=400) from None
        auth_expires_at = int(self.clock()) + pending.days * 24 * 60 * 60
        result = InviteResult({}, {})
        for sid in tokens.shop_ids:
            if sid in connected:
                result.already_connected += 1
                continue
            if len(shops) + len(result.added) >= MAX_SHOPS:
                result.failed += 1
                continue
            name = fetch_shop_name(config, sid, tokens.update.access_token, opener=self.opener, clock=self.clock)
            alias = self._auto_alias(name, sid, taken)
            final = self.shops_dir / f"{alias}.env"
            try:
                update = refresh_shop_token(config, sid, tokens.update.refresh_token, opener=self.opener,
                                            clock=self.clock)
                _atomic_write(final, shop_env_text(config, sid, update, auth_expires_at), replace=False,
                              failure_message="Unable to save the shop credential file")
            except (ShopeeAPIError, ConfigError, OSError):
                result.failed += 1
                continue
            taken.add(alias)
            result.added[alias] = final
            result.names[alias] = name
        _fsync_directory(self.shops_dir)
        return result

    # ------------------------------------------------------------ rename

    def renamed_config(self, old: str, new: str) -> dict[str, Path]:
        """The shops mapping with ``old`` renamed to ``new``; the env file stays where it is."""
        if not _valid_alias(new):
            raise ShopAdminError("Alias must be 1-32 characters: lowercase letters, digits, '-' or '_', "
                                 "starting with a letter or digit.")
        try:
            shops = self.read_config()
        except CredentialError:
            raise ShopAdminError("The shops file is invalid; nothing was changed.", status=500) from None
        if old not in shops:
            raise ShopAdminError("Unknown shop alias.", status=404)
        if new == old:
            raise ShopAdminError("The new alias is the same as the current one.")
        if new in shops:
            raise ShopAdminError("That alias is already in use.", status=409)
        return {(new if alias == old else alias): path for alias, path in shops.items()}

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
