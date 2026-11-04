"""Persistent authentication state for the remote HTTP MCP mode.

Everything lives in one owner-only SQLite database (mode 0600, directory not
group/world writable). Only SHA-256 hashes of bearer tokens, OAuth access
tokens, refresh tokens and authorization codes are stored; the plaintext value
is returned exactly once to the caller that created it.

Reliability rules (a restart must never disconnect a client):

* Clients, codes, access and refresh tokens are persisted transactionally, so a
  process restart keeps every session valid.
* Refresh tokens rotate, but the previous token may be presented once more
  within ``refresh_grace`` seconds (lost responses / duplicate retries). The
  token issued by the first rotation stays valid in that case.
* Nothing is invalidated in bulk on start-up; only expired rows are pruned.
"""
from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

SCHEMA_VERSION = "1"
DEFAULT_ACCESS_TTL = 24 * 3600
DEFAULT_REFRESH_TTL = 90 * 24 * 3600
DEFAULT_CODE_TTL = 300
DEFAULT_REFRESH_GRACE = 120
MAX_CLIENTS = 1000
MAX_REDIRECT_URIS = 10
MAX_TOKEN_LENGTH = 512
MIN_PASSPHRASE_LENGTH = 12
DEFAULT_SCOPE = "mcp"
_OPENAI_PATHS = ("/connector_platform_oauth_redirect", "/aip/", "/connector/")
_ANTHROPIC_PATHS = ("/api/mcp/auth_callback",)
ALLOWED_REDIRECT_PATHS = {"chatgpt.com": _OPENAI_PATHS, "chat.openai.com": _OPENAI_PATHS,
                          "claude.ai": _ANTHROPIC_PATHS, "claude.com": _ANTHROPIC_PATHS}
ALLOWED_REDIRECT_HOSTS = frozenset(ALLOWED_REDIRECT_PATHS)
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
_VERIFIER_RE = re.compile(r"[A-Za-z0-9\-._~]{43,128}")
_CHALLENGE_RE = re.compile(r"[A-Za-z0-9_-]{43}")
_LABEL_RE = re.compile(r"[A-Za-z0-9 ._@:/-]{1,64}")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS static_tokens (
    id TEXT PRIMARY KEY, label TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL, last_used_at INTEGER, revoked_at INTEGER);
CREATE TABLE IF NOT EXISTS oauth_clients (
    client_id TEXT PRIMARY KEY, client_name TEXT NOT NULL, redirect_uris TEXT NOT NULL,
    grant_types TEXT NOT NULL, created_at INTEGER NOT NULL, revoked_at INTEGER);
CREATE TABLE IF NOT EXISTS auth_codes (
    code_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL,
    code_challenge TEXT NOT NULL, resource TEXT NOT NULL, scope TEXT NOT NULL,
    expires_at INTEGER NOT NULL, used_at INTEGER, grant_id TEXT);
CREATE TABLE IF NOT EXISTS access_tokens (
    token_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, grant_id TEXT NOT NULL,
    resource TEXT NOT NULL, scope TEXT NOT NULL, created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, grant_id TEXT NOT NULL,
    resource TEXT NOT NULL, scope TEXT NOT NULL, created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL, rotated_at INTEGER, grace_used INTEGER NOT NULL DEFAULT 0,
    revoked_at INTEGER);
CREATE INDEX IF NOT EXISTS access_tokens_grant ON access_tokens(grant_id);
CREATE INDEX IF NOT EXISTS refresh_tokens_grant ON refresh_tokens(grant_id);
CREATE INDEX IF NOT EXISTS access_tokens_client ON access_tokens(client_id);
CREATE INDEX IF NOT EXISTS refresh_tokens_client ON refresh_tokens(client_id);
"""


class AuthStoreError(Exception):
    """Path-free and secret-free diagnostic."""


class OAuthError(Exception):
    """An RFC 6749 error code plus a short, secret-free description."""

    def __init__(self, error: str, description: str = "", status: int = 400):
        super().__init__(error)
        self.error, self.description, self.status = error, description, status


@dataclass(frozen=True)
class Principal:
    kind: str           # "static" or "oauth"
    subject: str        # static token id or OAuth client_id
    resource: str
    scope: str


def hash_secret(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def pkce_s256(verifier: str) -> str:
    return _b64(hashlib.sha256(verifier.encode("ascii")).digest())


# ------------------------------------------------------------- passphrases

def hash_passphrase(passphrase: str) -> str:
    if not isinstance(passphrase, str) or len(passphrase) < MIN_PASSPHRASE_LENGTH or len(passphrase) > 1024:
        raise AuthStoreError(f"passphrase must be {MIN_PASSPHRASE_LENGTH}-1024 characters")
    salt = secrets.token_bytes(16)
    if hasattr(hashlib, "scrypt"):
        n, r, p = 2 ** 15, 8, 1
        digest = hashlib.scrypt(passphrase.encode("utf-8"), salt=salt, n=n, r=r, p=p, maxmem=64 * 1024 * 1024, dklen=32)
        return f"scrypt${n}${r}${p}${_b64(salt)}${_b64(digest)}"
    iterations = 600_000
    digest = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, iterations, dklen=32)
    return f"pbkdf2_sha256${iterations}${_b64(salt)}${_b64(digest)}"


def verify_passphrase(passphrase: str, encoded: str | None) -> bool:
    """Constant-time verification. A missing hash still costs one derivation."""
    if not isinstance(passphrase, str) or len(passphrase) > 1024:
        passphrase = ""
    candidate = passphrase.encode("utf-8")
    try:
        if not encoded:
            raise ValueError
        parts = encoded.split("$")
        if parts[0] == "scrypt" and len(parts) == 6:
            n, r, p = int(parts[1]), int(parts[2]), int(parts[3])
            if not (2 ** 14 <= n <= 2 ** 20 and 1 <= r <= 16 and 1 <= p <= 4):
                raise ValueError
            salt, expected = _unb64(parts[4]), _unb64(parts[5])
            actual = hashlib.scrypt(candidate, salt=salt, n=n, r=r, p=p, maxmem=256 * 1024 * 1024, dklen=len(expected))
        elif parts[0] == "pbkdf2_sha256" and len(parts) == 4:
            iterations = int(parts[1])
            if not 100_000 <= iterations <= 10_000_000:
                raise ValueError
            salt, expected = _unb64(parts[2]), _unb64(parts[3])
            actual = hashlib.pbkdf2_hmac("sha256", candidate, salt, iterations, dklen=len(expected))
        else:
            raise ValueError
    except (ValueError, TypeError, IndexError):
        hashlib.pbkdf2_hmac("sha256", candidate, b"shopee-mcp-dummy", 100_000)
        return False
    return hmac.compare_digest(actual, expected)


# ----------------------------------------------------------- redirect URIs

def validate_redirect_uri(uri: Any) -> str:
    """Exact-string redirect URI accepted at registration (allowlisted hosts only)."""
    if not isinstance(uri, str) or not uri or len(uri) > 2000 or any(ord(ch) < 0x21 or ord(ch) == 0x7F for ch in uri):
        raise OAuthError("invalid_redirect_uri", "redirect_uri is malformed")
    try:
        parts = urlsplit(uri)
        port = parts.port
    except ValueError:
        raise OAuthError("invalid_redirect_uri", "redirect_uri is malformed") from None
    host = (parts.hostname or "").lower()
    if parts.fragment or "#" in uri or parts.username is not None or parts.password is not None or not host:
        raise OAuthError("invalid_redirect_uri", "redirect_uri must not contain a fragment or credentials")
    if parts.scheme == "http" and host in LOOPBACK_HOSTS:
        return uri
    if parts.scheme != "https" or host not in ALLOWED_REDIRECT_HOSTS or port not in (None, 443):
        raise OAuthError("invalid_redirect_uri", "redirect_uri host is not allowed")
    path = parts.path
    segments = path.split("/")
    if "%" in path or "\\" in path or "." in segments or ".." in segments:
        raise OAuthError("invalid_redirect_uri", "redirect_uri path is not allowed")
    if not any(path.startswith(prefix) for prefix in ALLOWED_REDIRECT_PATHS[host]):
        raise OAuthError("invalid_redirect_uri", "redirect_uri path is not allowed")
    return uri


# ------------------------------------------------------------------ store

def _check_directory(directory: Path) -> None:
    try:
        info = os.stat(directory)
    except OSError:
        raise AuthStoreError("auth_file_invalid: unreadable directory") from None
    if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (os.getuid(), 0) or info.st_mode & 0o022:
        raise AuthStoreError("auth_file_invalid: directory must not be group/world writable")


def _check_file(path: Path) -> None:
    try:
        info = os.lstat(path)
    except OSError:
        raise AuthStoreError("auth_file_invalid: file is missing") from None
    if stat.S_ISLNK(info.st_mode):
        raise AuthStoreError("auth_file_invalid: file must not be a symlink")
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise AuthStoreError("auth_file_invalid: must be an owner-owned regular file with permissions 0600")


class AuthStore:
    """SQLite-backed token, client and grant storage. Thread/process safe via SQLite locking."""

    def __init__(self, path: Path | str, *, create: bool = False, clock: Callable[[], float] = time.time,
                 access_ttl: int = DEFAULT_ACCESS_TTL, refresh_ttl: int = DEFAULT_REFRESH_TTL,
                 code_ttl: int = DEFAULT_CODE_TTL, refresh_grace: int = DEFAULT_REFRESH_GRACE):
        raw = os.fspath(path)
        if not raw or "\x00" in raw or not os.path.isabs(raw) or os.path.normpath(raw) != raw:
            raise AuthStoreError("auth_file_invalid: path must be absolute and normalized")
        if min(access_ttl, refresh_ttl, code_ttl) <= 0 or refresh_grace < 0:
            raise AuthStoreError("auth_file_invalid: lifetimes must be positive")
        self.path = Path(raw)
        self.clock = clock
        self.access_ttl, self.refresh_ttl, self.code_ttl, self.refresh_grace = access_ttl, refresh_ttl, code_ttl, refresh_grace
        _check_directory(self.path.parent)
        if create and not os.path.lexists(self.path):
            try:
                fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                os.close(fd)
            except FileExistsError:
                pass
            except OSError:
                raise AuthStoreError("auth_file_invalid: unable to create file") from None
        _check_file(self.path)
        with self._connect() as db:
            # WAL is persistent in the database file; the -wal/-shm files inherit its 0600 mode.
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript(_SCHEMA)
            columns = {row["name"] for row in db.execute("PRAGMA table_info(auth_codes)")}
            if "grant_id" not in columns:
                db.execute("ALTER TABLE auth_codes ADD COLUMN grant_id TEXT")
            db.execute("INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version', ?)", (SCHEMA_VERSION,))
            db.execute("INSERT OR IGNORE INTO meta(key, value) VALUES ('server_secret', ?)", (secrets.token_hex(32),))
            row = db.execute("SELECT value FROM meta WHERE key = 'server_secret'").fetchone()
        self._server_secret = bytes.fromhex(row["value"])
        _check_file(self.path)
        self._last_prune = 0.0

    @contextlib.contextmanager
    def _connect(self, *, busy_ms: int = 3000):
        db = sqlite3.connect(self.path, timeout=busy_ms / 1000, isolation_level=None)
        try:
            db.row_factory = sqlite3.Row
            db.execute(f"PRAGMA busy_timeout={int(busy_ms)}")
            db.execute("PRAGMA synchronous=NORMAL")
            db.execute("PRAGMA foreign_keys=ON")
            yield db
        finally:
            db.close()

    @contextlib.contextmanager
    def _tx(self):
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                yield db
            except BaseException:
                db.execute("ROLLBACK")
                raise
            db.execute("COMMIT")

    def now(self) -> int:
        return int(self.clock())

    # ------------------------------------------------------------- meta

    def _meta(self, key: str) -> str | None:
        with self._connect() as db:
            row = db.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def server_secret(self) -> bytes:
        return self._server_secret  # cached at start-up; never changes

    def set_admin_passphrase(self, passphrase: str) -> None:
        encoded = hash_passphrase(passphrase)
        with self._tx() as db:
            db.execute("INSERT INTO meta(key, value) VALUES ('admin_passphrase', ?) "
                       "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (encoded,))

    def has_admin_passphrase(self) -> bool:
        return bool(self._meta("admin_passphrase"))

    def verify_admin_passphrase(self, passphrase: str) -> bool:
        return verify_passphrase(passphrase, self._meta("admin_passphrase"))

    # ---------------------------------------------------- static tokens

    def create_static_token(self, label: str) -> tuple[str, str]:
        if not isinstance(label, str) or not _LABEL_RE.fullmatch(label):
            raise AuthStoreError("label must be 1-64 characters: letters, digits, space . _ @ : / -")
        token = "smcp_" + secrets.token_urlsafe(32)
        token_id = secrets.token_hex(6)
        with self._tx() as db:
            db.execute("INSERT INTO static_tokens(id, label, token_hash, created_at) VALUES (?, ?, ?, ?)",
                       (token_id, label, hash_secret(token), self.now()))
        return token_id, token

    def list_static_tokens(self) -> list[dict]:
        with self._connect() as db:
            rows = db.execute("SELECT id, label, created_at, last_used_at, revoked_at FROM static_tokens ORDER BY created_at").fetchall()
        return [dict(row) for row in rows]

    def revoke_static_token(self, token_id: str) -> bool:
        with self._tx() as db:
            cursor = db.execute("UPDATE static_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
                                (self.now(), token_id))
            return cursor.rowcount > 0

    # ---------------------------------------------------------- clients

    def register_client(self, metadata: Any) -> dict:
        if not isinstance(metadata, dict):
            raise OAuthError("invalid_client_metadata", "body must be a JSON object")
        uris = metadata.get("redirect_uris")
        if not isinstance(uris, list) or not uris or len(uris) > MAX_REDIRECT_URIS:
            raise OAuthError("invalid_redirect_uri", "redirect_uris must be a non-empty list")
        uris = list(dict.fromkeys(validate_redirect_uri(uri) for uri in uris))
        method = metadata.get("token_endpoint_auth_method", "none")
        # Confidential methods are downgraded to a public client (RFC 7591 lets the
        # server replace requested values); PKCE protects the code exchange.
        if method not in ("none", "client_secret_post", "client_secret_basic"):
            raise OAuthError("invalid_client_metadata", "unsupported token_endpoint_auth_method")
        grant_types = metadata.get("grant_types", ["authorization_code", "refresh_token"])
        if (not isinstance(grant_types, list) or not grant_types
                or not all(isinstance(item, str) for item in grant_types)
                or not set(grant_types) <= {"authorization_code", "refresh_token"}
                or "authorization_code" not in grant_types):
            raise OAuthError("invalid_client_metadata", "unsupported grant_types")
        grant_types = sorted(set(grant_types) | {"refresh_token"})
        response_types = metadata.get("response_types", ["code"])
        if (not isinstance(response_types, list) or not all(isinstance(item, str) for item in response_types)
                or set(response_types) != {"code"}):
            raise OAuthError("invalid_client_metadata", "unsupported response_types")
        name = metadata.get("client_name", "MCP client")
        if not isinstance(name, str):
            name = "MCP client"
        name = "".join(ch for ch in name if ch.isprintable())[:100] or "MCP client"
        now = self.now()
        client_id = "smcp_c_" + secrets.token_urlsafe(18)
        with self._tx() as db:
            count = db.execute("SELECT COUNT(*) FROM oauth_clients").fetchone()[0]
            if count >= MAX_CLIENTS:
                # Drop stale registrations that never obtained a token.
                db.execute("""DELETE FROM oauth_clients WHERE created_at < ? AND client_id NOT IN
                              (SELECT client_id FROM refresh_tokens) AND client_id NOT IN
                              (SELECT client_id FROM access_tokens)""", (now - 86400,))
                count = db.execute("SELECT COUNT(*) FROM oauth_clients").fetchone()[0]
                if count >= MAX_CLIENTS:
                    raise OAuthError("invalid_client_metadata", "client registration limit reached")
            db.execute("INSERT INTO oauth_clients(client_id, client_name, redirect_uris, grant_types, created_at) "
                       "VALUES (?, ?, ?, ?, ?)", (client_id, name, json.dumps(uris), json.dumps(grant_types), now))
        return {"client_id": client_id, "client_id_issued_at": now, "client_name": name,
                "redirect_uris": uris, "grant_types": grant_types, "response_types": ["code"],
                "token_endpoint_auth_method": "none"}

    def get_client(self, client_id: Any) -> dict | None:
        if not isinstance(client_id, str) or not client_id or len(client_id) > 128:
            return None
        with self._connect() as db:
            row = db.execute("SELECT * FROM oauth_clients WHERE client_id = ? AND revoked_at IS NULL", (client_id,)).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["redirect_uris"] = json.loads(result["redirect_uris"])
        result["grant_types"] = json.loads(result["grant_types"])
        return result

    def list_clients(self) -> list[dict]:
        now = self.now()
        with self._connect() as db:
            rows = db.execute("""SELECT c.client_id, c.client_name, c.created_at, c.revoked_at,
                (SELECT COUNT(*) FROM refresh_tokens r WHERE r.client_id = c.client_id AND r.revoked_at IS NULL
                   AND r.rotated_at IS NULL AND r.expires_at > ?) AS active_refresh_tokens
                FROM oauth_clients c ORDER BY c.created_at""", (now,)).fetchall()
        return [dict(row) for row in rows]

    def revoke_client(self, client_id: str) -> bool:
        now = self.now()
        with self._tx() as db:
            cursor = db.execute("UPDATE oauth_clients SET revoked_at = ? WHERE client_id = ? AND revoked_at IS NULL", (now, client_id))
            db.execute("DELETE FROM access_tokens WHERE client_id = ?", (client_id,))
            db.execute("UPDATE refresh_tokens SET revoked_at = ? WHERE client_id = ? AND revoked_at IS NULL", (now, client_id))
            db.execute("DELETE FROM auth_codes WHERE client_id = ?", (client_id,))
            return cursor.rowcount > 0

    # ------------------------------------------------------------ codes

    def create_code(self, client_id: str, redirect_uri: str, code_challenge: str, resource: str, scope: str) -> str:
        if not _CHALLENGE_RE.fullmatch(code_challenge or ""):
            raise OAuthError("invalid_request", "invalid code_challenge")
        code = secrets.token_urlsafe(32)
        with self._tx() as db:
            db.execute("INSERT INTO auth_codes(code_hash, client_id, redirect_uri, code_challenge, resource, scope, expires_at) "
                       "VALUES (?, ?, ?, ?, ?, ?, ?)",
                       (hash_secret(code), client_id, redirect_uri, code_challenge, resource, scope, self.now() + self.code_ttl))
        self.prune()
        return code

    def exchange_code(self, code: Any, client_id: Any, redirect_uri: Any, code_verifier: Any, resource: str | None) -> dict:
        if not all(isinstance(v, str) and v for v in (code, client_id, code_verifier)):
            raise OAuthError("invalid_request", "code, client_id and code_verifier are required")
        if redirect_uri is not None and (not isinstance(redirect_uri, str) or not redirect_uri):
            raise OAuthError("invalid_request", "invalid redirect_uri")
        if len(code) > MAX_TOKEN_LENGTH or not _VERIFIER_RE.fullmatch(code_verifier):
            raise OAuthError("invalid_grant", "invalid code or code_verifier")
        client = self.get_client(client_id)
        if client is None:
            raise OAuthError("invalid_client", "unknown client", status=401)
        if redirect_uri is None:
            # Optional only when it is unambiguous.
            if len(client["redirect_uris"]) != 1:
                raise OAuthError("invalid_request", "redirect_uri is required")
            redirect_uri = client["redirect_uris"][0]
        now = self.now()
        failure = None
        with self._tx() as db:
            row = db.execute("SELECT * FROM auth_codes WHERE code_hash = ?", (hash_secret(code),)).fetchone()
            if row is None or row["expires_at"] <= now:
                raise OAuthError("invalid_grant", "authorization code is invalid or expired")
            if row["used_at"] is not None:
                # Replay of a consumed code: revoke everything issued from it (RFC 6749 4.1.2).
                if row["grant_id"]:
                    self._revoke_grant(db, row["grant_id"], now)
                failure = OAuthError("invalid_grant", "authorization code was already used")
            else:
                # Single use: the code is consumed (committed) even when the checks below fail.
                db.execute("UPDATE auth_codes SET used_at = ? WHERE code_hash = ?", (now, row["code_hash"]))
                if not hmac.compare_digest(row["client_id"], client_id) or row["redirect_uri"] != redirect_uri:
                    failure = OAuthError("invalid_grant", "client_id or redirect_uri mismatch")
                elif not hmac.compare_digest(pkce_s256(code_verifier), row["code_challenge"]):
                    failure = OAuthError("invalid_grant", "PKCE verification failed")
                elif resource is not None and resource != row["resource"]:
                    failure = OAuthError("invalid_target", "resource does not match the authorization request")
                else:
                    grant_id = secrets.token_hex(16)
                    db.execute("UPDATE auth_codes SET grant_id = ? WHERE code_hash = ?", (grant_id, row["code_hash"]))
                    return self._issue(db, client_id, grant_id, row["resource"], row["scope"], now)
        raise failure

    # ----------------------------------------------------------- tokens

    def _issue(self, db, client_id: str, grant_id: str, resource: str, scope: str, now: int) -> dict:
        access = "smcp_at_" + secrets.token_urlsafe(32)
        refresh = "smcp_rt_" + secrets.token_urlsafe(32)
        db.execute("INSERT INTO access_tokens(token_hash, client_id, grant_id, resource, scope, created_at, expires_at) "
                   "VALUES (?, ?, ?, ?, ?, ?, ?)", (hash_secret(access), client_id, grant_id, resource, scope, now, now + self.access_ttl))
        db.execute("INSERT INTO refresh_tokens(token_hash, client_id, grant_id, resource, scope, created_at, expires_at) "
                   "VALUES (?, ?, ?, ?, ?, ?, ?)", (hash_secret(refresh), client_id, grant_id, resource, scope, now, now + self.refresh_ttl))
        return {"access_token": access, "token_type": "Bearer", "expires_in": self.access_ttl,
                "refresh_token": refresh, "scope": scope}

    @staticmethod
    def _revoke_grant(db, grant_id: str, now: int) -> None:
        db.execute("UPDATE refresh_tokens SET revoked_at = ? WHERE grant_id = ? AND revoked_at IS NULL", (now, grant_id))
        db.execute("DELETE FROM access_tokens WHERE grant_id = ?", (grant_id,))

    def refresh(self, refresh_token: Any, client_id: Any, resource: str | None) -> dict:
        if not isinstance(refresh_token, str) or not refresh_token or len(refresh_token) > MAX_TOKEN_LENGTH:
            raise OAuthError("invalid_request", "refresh_token is required")
        if client_id is not None and (not isinstance(client_id, str) or not client_id):
            raise OAuthError("invalid_request", "invalid client_id")
        now = self.now()
        failure = None
        with self._tx() as db:
            row = db.execute("SELECT * FROM refresh_tokens WHERE token_hash = ?", (hash_secret(refresh_token),)).fetchone()
            if row is None or row["revoked_at"] is not None or row["expires_at"] <= now:
                raise OAuthError("invalid_grant", "refresh token is invalid or expired")
            if client_id is not None and not hmac.compare_digest(row["client_id"], client_id):
                raise OAuthError("invalid_grant", "refresh token was issued to another client")
            client = db.execute("SELECT 1 FROM oauth_clients WHERE client_id = ? AND revoked_at IS NULL",
                                (row["client_id"],)).fetchone()
            if client is None:
                raise OAuthError("invalid_grant", "client is revoked")
            if resource is not None and resource != row["resource"]:
                raise OAuthError("invalid_target", "resource does not match the grant")
            if row["rotated_at"] is None:
                db.execute("UPDATE refresh_tokens SET rotated_at = ? WHERE token_hash = ?", (now, row["token_hash"]))
            elif not row["grace_used"] and now - row["rotated_at"] <= self.refresh_grace:
                # Duplicate/retried refresh of the previous token: succeed once, and
                # keep the token issued by the first rotation valid as well.
                db.execute("UPDATE refresh_tokens SET grace_used = 1 WHERE token_hash = ?", (row["token_hash"],))
            else:
                # Reuse outside the grace allowance: treat as theft and revoke the whole grant
                # (committed before the error is returned).
                self._revoke_grant(db, row["grant_id"], now)
                failure = OAuthError("invalid_grant", "refresh token was already used; grant revoked")
            if failure is None:
                return self._issue(db, row["client_id"], row["grant_id"], row["resource"], row["scope"], now)
        raise failure

    def revoke_token(self, token: Any) -> None:
        """RFC 7009. Revoking a refresh token revokes its whole grant (all access tokens too)."""
        if not isinstance(token, str) or not token or len(token) > MAX_TOKEN_LENGTH:
            return
        digest = hash_secret(token)
        now = self.now()
        with self._tx() as db:
            row = db.execute("SELECT grant_id FROM refresh_tokens WHERE token_hash = ?", (digest,)).fetchone()
            if row is not None:
                self._revoke_grant(db, row["grant_id"], now)
            db.execute("DELETE FROM access_tokens WHERE token_hash = ?", (digest,))

    def verify_bearer(self, token: Any, resource: str) -> Principal | None:
        if not isinstance(token, str) or not token or len(token) > MAX_TOKEN_LENGTH:
            return None
        digest = hash_secret(token)
        now = self.now()
        touch = None
        with self._connect() as db:
            row = db.execute("SELECT id, token_hash, last_used_at FROM static_tokens WHERE token_hash = ? AND revoked_at IS NULL",
                             (digest,)).fetchone()
            if row is not None and hmac.compare_digest(row["token_hash"], digest):
                if row["last_used_at"] is None or now - row["last_used_at"] > 3600:
                    touch = row["id"]
                principal = Principal("static", row["id"], resource, DEFAULT_SCOPE)
            else:
                principal = None
                row = db.execute("""SELECT a.token_hash, a.client_id, a.resource, a.scope, a.expires_at FROM access_tokens a
                                    JOIN oauth_clients c ON c.client_id = a.client_id AND c.revoked_at IS NULL
                                    WHERE a.token_hash = ?""", (digest,)).fetchone()
                if (row is not None and hmac.compare_digest(row["token_hash"], digest) and row["expires_at"] > now
                        and row["resource"] == resource):  # audience binding
                    principal = Principal("oauth", row["client_id"], row["resource"], row["scope"])
        if touch is not None:
            # Best effort: never wait for a lock or fail the request for bookkeeping.
            with contextlib.suppress(sqlite3.Error), self._connect(busy_ms=0) as db:
                db.execute("UPDATE static_tokens SET last_used_at = ? WHERE id = ?", (now, touch))
        return principal

    def prune(self, *, force: bool = False) -> None:
        """Delete expired rows only. Never touches live sessions."""
        now = self.now()
        if not force and now - self._last_prune < 300:
            return
        self._last_prune = now
        with self._tx() as db:
            db.execute("DELETE FROM auth_codes WHERE expires_at <= ?", (now - 3600,))
            db.execute("DELETE FROM access_tokens WHERE expires_at <= ?", (now,))
            # Rotated refresh tokens are kept until they expire so reuse can be detected.
            db.execute("DELETE FROM refresh_tokens WHERE expires_at <= ?", (now,))
            db.execute("DELETE FROM refresh_tokens WHERE revoked_at IS NOT NULL AND revoked_at < ?", (now - 86400,))
