from __future__ import annotations

import hmac
import argparse
import contextlib
import getpass
import sys
import json
import re
import secrets
import socket
import stat
import time
import os
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from http.client import HTTPException
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from shopee_mcp.credentials import CredentialError, CredentialSnapshot, CredentialStore, RefreshNotSent
from shopee_mcp.signing import sign

ALLOWED_BASE_URLS = {
    "sandbox": "https://openplatform.sandbox.test-stable.shopee.sg",
    "production": "https://partner.shopeemobile.com",
}
AUTHORIZATION_URLS = {
    "sandbox": "https://open.sandbox.test-stable.shopee.com/auth",
    "production": "https://open.shopee.com/auth",
}
REQUIRED_ENV_KEYS = (
    "SHOPEE_ENV", "SHOPEE_BASE_URL", "SHOPEE_PARTNER_ID", "SHOPEE_PARTNER_KEY",
    "SHOPEE_SHOP_ID", "SHOPEE_ACCESS_TOKEN", "SHOPEE_REFRESH_TOKEN",
    "SHOPEE_REFRESH_TOKEN_EXPIRES_AT", "SHOPEE_AUTH_EXPIRES_AT",
)
PARTNER_REQUIRED_ENV_KEYS = (
    "SHOPEE_ENV", "SHOPEE_BASE_URL", "SHOPEE_PARTNER_ID", "SHOPEE_PARTNER_KEY",
    "SHOPEE_REDIRECT_URL",
)


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class PartnerConfig:
    env: str
    base_url: str
    partner_id: int
    partner_key: str
    redirect_url: str
    auth_state: str
    env_file: Path


@dataclass(frozen=True)
class ShopeeConfig:
    env: str
    base_url: str
    partner_id: int
    partner_key: str
    shop_id: int
    access_token: str
    refresh_token: str
    access_token_expires_at: int
    refresh_token_expires_at: int
    auth_expires_at: int
    env_file: Path


def parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ConfigError(f"Invalid environment line {line_number}")
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def _positive_int(values: dict[str, str], key: str) -> int:
    try:
        value = int(values[key])
    except (KeyError, ValueError) as error:
        raise ConfigError(f"{key} must be a positive integer") from error
    if value <= 0:
        raise ConfigError(f"{key} must be a positive integer")
    return value


def _optional_epoch(value: str | None) -> int:
    try:
        return int(value or 0)
    except ValueError:
        return 0


def _load_env_values(path: Path) -> dict[str, str]:
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise ConfigError("Environment file must be a regular file owned by this user")
        mode = stat.S_IMODE(info.st_mode)
        if mode != 0o600:
            raise ConfigError("Environment file permissions must be 0600")
        return parse_env_file(path)
    except ConfigError:
        raise
    except OSError as error:
        raise ConfigError("Unable to read environment file") from error


def _validated_environment(values: dict[str, str], required: tuple[str, ...]) -> tuple[str, str]:
    missing = [key for key in required if not values.get(key)]
    if missing:
        raise ConfigError("Missing required settings: " + ", ".join(missing))
    env = values["SHOPEE_ENV"]
    if env not in ALLOWED_BASE_URLS:
        raise ConfigError("SHOPEE_ENV must be sandbox or production")
    base_url = values["SHOPEE_BASE_URL"].rstrip("/")
    if base_url != ALLOWED_BASE_URLS[env]:
        raise ConfigError("SHOPEE_BASE_URL does not match SHOPEE_ENV")
    return env, base_url


def _validate_single_line(value: str, label: str) -> str:
    if not value or value.strip() != value or value.splitlines() != [value]:
        raise ConfigError(f"{label} must be a non-empty single-line value")
    return value


def _validate_redirect_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise ConfigError("SHOPEE_REDIRECT_URL must be a valid HTTPS URL") from error
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or port not in (None, 443)):
        raise ConfigError("SHOPEE_REDIRECT_URL must be a public HTTPS URL without query or fragment")
    return value


def load_partner_config(path: Path) -> PartnerConfig:
    values = _load_env_values(path)
    env, base_url = _validated_environment(values, PARTNER_REQUIRED_ENV_KEYS)
    return PartnerConfig(
        env, base_url, _positive_int(values, "SHOPEE_PARTNER_ID"),
        _validate_single_line(values["SHOPEE_PARTNER_KEY"], "SHOPEE_PARTNER_KEY"),
        _validate_redirect_url(values["SHOPEE_REDIRECT_URL"]),
        values.get("SHOPEE_AUTH_STATE", ""), path,
    )


def load_config(path: Path) -> ShopeeConfig:
    values = _load_env_values(path)
    env, base_url = _validated_environment(values, REQUIRED_ENV_KEYS)
    missing = [key for key in REQUIRED_ENV_KEYS if not values.get(key)]
    if missing:
        raise ConfigError("Missing required settings: " + ", ".join(missing))
    return ShopeeConfig(env, base_url, _positive_int(values, "SHOPEE_PARTNER_ID"), values["SHOPEE_PARTNER_KEY"], _positive_int(values, "SHOPEE_SHOP_ID"), values["SHOPEE_ACCESS_TOKEN"], values["SHOPEE_REFRESH_TOKEN"], _optional_epoch(values.get("SHOPEE_ACCESS_TOKEN_EXPIRES_AT")), _positive_int(values, "SHOPEE_REFRESH_TOKEN_EXPIRES_AT"), _positive_int(values, "SHOPEE_AUTH_EXPIRES_AT"), path)


def _sign(key: str, base_string: str) -> str:
    return sign(key, base_string)


def build_public_signature(config: ShopeeConfig | PartnerConfig, api_path: str, timestamp: int) -> str:
    return _sign(config.partner_key, f"{config.partner_id}{api_path}{timestamp}")


def build_shop_signature(config: ShopeeConfig, api_path: str, timestamp: int) -> str:
    return _sign(config.partner_key, f"{config.partner_id}{api_path}{timestamp}{config.access_token}{config.shop_id}")


class ShopeeAPIError(RuntimeError):
    def __init__(self, message, *, code=None, api_path=None):
        super().__init__(message)
        self.code = code
        self.api_path = api_path


class ShopeeRequestNotSent(ShopeeAPIError):
    """The opener failed DNS resolution or refused connection before dispatch."""


class StockWriteUnknown(ShopeeAPIError):
    """A write may have reached Shopee; never retry it automatically."""


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ShopeeAPIError("Shopee API redirect refused")


def _open_without_redirects(request: Request, timeout: int):
    return build_opener(_RejectRedirects()).open(request, timeout=timeout)


SENSITIVE_KEYS = {
    "partner_key", "access_token", "refresh_token", "sign", "signature", "x-amz-signature",
    "code", "state",
}


def _redact_text(value: str, secrets: set[str], *, all_urls: bool = False) -> str:
    def redact_url(match: re.Match) -> str:
        url = match.group(0)
        try:
            sensitive = any(key.lower() in SENSITIVE_KEYS for key, _ in parse_qsl(urlsplit(url).query))
        except ValueError:
            sensitive = True
        return "[REDACTED_URL]" if all_urls or sensitive else url

    value = re.sub(r"https?://\S+", redact_url, value, flags=re.IGNORECASE)
    for secret in sorted(secrets, key=len, reverse=True):
        if secret:
            value = value.replace(secret, "[REDACTED]")
    return value


def _sanitize_payload(payload: object, secrets: set[str]) -> object:
    if isinstance(payload, dict):
        return {
            key: "[REDACTED]" if key.lower() in SENSITIVE_KEYS else _sanitize_payload(value, secrets)
            for key, value in payload.items()
        }
    if isinstance(payload, list):
        return [_sanitize_payload(value, secrets) for value in payload]
    if isinstance(payload, str):
        return _redact_text(payload, secrets)
    return payload


REFRESH_TOKEN_LIFETIME_SECONDS = 30 * 24 * 60 * 60

@dataclass(frozen=True)
class TokenUpdate:
    access_token: str
    refresh_token: str
    access_token_expires_at: int
    refresh_token_expires_at: int


def _atomic_write(path: Path, text: str, *, replace: bool, failure_message: str) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
        tmp = Path(name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(text)
                stream.flush()
                os.fsync(stream.fileno())
            tmp.chmod(0o600)
            if replace:
                os.replace(tmp, path)
            else:
                os.link(tmp, path)
        finally:
            tmp.unlink(missing_ok=True)
    except FileExistsError:
        raise ShopeeAPIError("Environment file already exists; refusing to overwrite it") from None
    except OSError:
        raise ShopeeAPIError(failure_message) from None


def update_env_values(path: Path, replacements: dict[str, str], *, failure_message: str) -> None:
    try:
        CredentialStore(path).update_local(replacements)
    except (CredentialError, OSError):
        raise ShopeeAPIError(failure_message) from None


def update_env_tokens(path: Path, update: TokenUpdate) -> None:
    update_env_values(
        path,
        {
            "SHOPEE_ACCESS_TOKEN": update.access_token,
            "SHOPEE_REFRESH_TOKEN": update.refresh_token,
            "SHOPEE_ACCESS_TOKEN_EXPIRES_AT": str(update.access_token_expires_at),
            "SHOPEE_REFRESH_TOKEN_EXPIRES_AT": str(update.refresh_token_expires_at),
        },
        failure_message="Unable to save refreshed Shopee credentials",
    )


def create_production_env(path: Path, partner_id: int, partner_key: str, redirect_url: str) -> None:
    if partner_id <= 0:
        raise ConfigError("partner-id must be a positive integer")
    partner_key = _validate_single_line(partner_key, "Partner Key")
    redirect_url = _validate_redirect_url(redirect_url)
    values = {
        "SHOPEE_ENV": "production",
        "SHOPEE_BASE_URL": ALLOWED_BASE_URLS["production"],
        "SHOPEE_PARTNER_ID": str(partner_id),
        "SHOPEE_PARTNER_KEY": partner_key,
        "SHOPEE_REDIRECT_URL": redirect_url,
        "SHOPEE_AUTH_STATE": "",
        "SHOPEE_SHOP_ID": "",
        "SHOPEE_ACCESS_TOKEN": "",
        "SHOPEE_REFRESH_TOKEN": "",
        "SHOPEE_ACCESS_TOKEN_EXPIRES_AT": "",
        "SHOPEE_REFRESH_TOKEN_EXPIRES_AT": "",
        "SHOPEE_AUTH_EXPIRES_AT": "",
    }
    text = "".join(f"{key}={value}\n" for key, value in values.items())
    _atomic_write(path, text, replace=False, failure_message="Unable to save production Shopee credentials")


def build_authorization_url(config: PartnerConfig, state: str) -> str:
    state = _validate_single_line(state, "authorization state")
    return f"{AUTHORIZATION_URLS[config.env]}?{urlencode({
        'partner_id': config.partner_id,
        'auth_type': 'seller',
        'redirect_uri': config.redirect_url,
        'response_type': 'code',
        'state': state,
    })}"


@dataclass(frozen=True)
class AuthorizationCallback:
    code: str
    shop_id: int


def parse_authorization_callback(config: PartnerConfig, callback_url: str) -> AuthorizationCallback:
    callback_url = _validate_single_line(callback_url, "callback URL")
    try:
        actual = urlsplit(callback_url)
        expected = urlsplit(config.redirect_url)
        actual_port = actual.port or 443
        expected_port = expected.port or 443
    except ValueError as error:
        raise ConfigError("Callback URL is invalid") from error
    actual_endpoint = (actual.scheme, actual.hostname, actual_port, actual.path or "/")
    expected_endpoint = (expected.scheme, expected.hostname, expected_port, expected.path or "/")
    if actual_endpoint != expected_endpoint or actual.fragment:
        raise ConfigError("Callback URL does not match SHOPEE_REDIRECT_URL")
    pairs = parse_qsl(actual.query, keep_blank_values=True)
    parameters: dict[str, str] = {}
    for name in ("code", "shop_id", "state"):
        matches = [value for key, value in pairs if key == name]
        if len(matches) != 1 or not matches[0]:
            raise ConfigError(f"Callback URL must contain exactly one {name}")
        parameters[name] = matches[0]
    if not config.auth_state or not hmac.compare_digest(parameters["state"], config.auth_state):
        raise ConfigError("Callback state does not match the saved authorization state")
    code = _validate_single_line(parameters["code"], "authorization code")
    try:
        shop_id = int(parameters["shop_id"])
    except ValueError as error:
        raise ConfigError("Callback shop_id must be a positive integer") from error
    if shop_id <= 0:
        raise ConfigError("Callback shop_id must be a positive integer")
    return AuthorizationCallback(code, shop_id)


class ShopeePartnerClient:
    def __init__(self, config: ShopeeConfig | PartnerConfig, *, opener: Callable = _open_without_redirects,
                 clock: Callable[[], float] = time.time) -> None:
        self.config = config
        self.opener = opener
        self.clock = clock
        self.secrets = {config.partner_key}

    def _decode(self, response, api_path: str) -> dict[str, object]:
        try:
            payload = json.loads(response.read())
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ShopeeAPIError(f"Invalid JSON response from {api_path}") from error
        if not isinstance(payload, dict):
            raise ShopeeAPIError(f"Expected JSON object from {api_path}")
        if payload.get("error"):
            message = (f"Shopee API error at {api_path}: error={payload.get('error')!s} "
                       f"message={payload.get('message')!s} request_id={payload.get('request_id')!s}")
            raise ShopeeAPIError(_redact_text(message, self.secrets, all_urls=True),
                                 code=payload.get("error"), api_path=api_path)
        return payload

    def _open(self, request: Request, api_path: str) -> dict[str, object]:
        try:
            response = self.opener(request, timeout=30)
        except HTTPError as error:
            raise ShopeeAPIError(f"HTTP {error.code} from Shopee API at {api_path}") from error
        except URLError as error:
            # urllib retains the concrete connect failure in reason. Do not
            # infer dispatch status from text, generic OSError, or timeouts.
            if isinstance(error.reason, (socket.gaierror, ConnectionRefusedError)):
                raise ShopeeRequestNotSent(f"Network error at {api_path}") from None
            raise ShopeeAPIError(f"Network error at {api_path}") from None
        except (socket.gaierror, ConnectionRefusedError):
            raise ShopeeRequestNotSent(f"Network error at {api_path}") from None
        except (OSError, HTTPException):
            raise ShopeeAPIError(f"Network error at {api_path}") from None
        try:
            with response as opened_response:
                return self._decode(opened_response, api_path)
        except (URLError, OSError, HTTPException):
            # Once a response exists the request was dispatched, even if its
            # body later fails with an exception resembling a connect failure.
            raise ShopeeAPIError(f"Network error at {api_path}") from None

    def public_post(self, api_path: str, body: dict[str, object]) -> dict[str, object]:
        timestamp = int(self.clock())
        query = urlencode({"partner_id": self.config.partner_id, "timestamp": timestamp,
                           "sign": build_public_signature(self.config, api_path, timestamp)})
        request = Request(f"{self.config.base_url}{api_path}?{query}",
                          data=json.dumps(body).encode("utf-8"),
                          headers={"Content-Type": "application/json"}, method="POST")
        return self._open(request, api_path)


def _shop_config_from_snapshot(snapshot: CredentialSnapshot, env_file: Path) -> ShopeeConfig:
    if snapshot.scope != "shop" or snapshot.subject_id is None:
        raise ConfigError("Credential snapshot is not bound to a shop")
    return ShopeeConfig(
        snapshot.env,
        snapshot.base_url,
        snapshot.partner_id,
        snapshot.partner_key,
        snapshot.subject_id,
        snapshot.access_token,
        snapshot.refresh_token,
        snapshot.access_token_expires_at,
        snapshot.refresh_token_expires_at,
        snapshot.auth_expires_at,
        env_file,
    )


class StockWritePreconditionFailed(ShopeeAPIError):
    """The stock request was not dispatched because its evidence expired."""


class ShopeeClient(ShopeePartnerClient):
    def __init__(self, config: ShopeeConfig, *, opener: Callable = _open_without_redirects,
                 clock: Callable[[], float] = time.time, lock_root: Path | None = None) -> None:
        # ``lock_root`` remains accepted for callers that used the legacy API,
        # but credential coordination must use the canonical env-file namespace.
        credential_store = CredentialStore(config.env_file, clock=clock)
        snapshot = credential_store.snapshot("shop")
        expected_binding = (config.env, config.base_url, config.partner_id, "shop", config.shop_id)
        if snapshot.binding != expected_binding:
            raise ConfigError("Credential identity changed; restart with the intended shop")
        super().__init__(config, opener=opener, clock=clock)
        self.credential_store = credential_store
        self.config = _shop_config_from_snapshot(snapshot, config.env_file)
        self.secrets.update((config.access_token, config.refresh_token))
        self.secrets.update(snapshot.secrets)

    def shop_get(self, api_path: str, params: dict[str, object] | None = None) -> dict[str, object]:
        reserved = {"partner_id", "timestamp", "sign", "access_token", "shop_id"}
        conflicting = reserved.intersection(params or {})
        if conflicting:
            raise ValueError("params contains reserved signed query parameter")
        self.ensure_access_token()
        timestamp = int(self.clock())
        query_values: dict[str, object] = {
            "partner_id": self.config.partner_id, "timestamp": timestamp,
            "sign": build_shop_signature(self.config, api_path, timestamp),
            "access_token": self.config.access_token, "shop_id": self.config.shop_id,
        }
        query_values.update(params or {})
        request = Request(f"{self.config.base_url}{api_path}?{urlencode(query_values)}", method="GET")
        return self._open(request, api_path)

    def shop_post(self, api_path: str, body: dict[str, object], *, before_dispatch=None) -> dict[str, object]:
        if api_path != "/api/v2/product/update_stock":
            raise ValueError("Only the verified inventory write endpoint is supported")
        if {"partner_id", "timestamp", "sign", "access_token", "shop_id"}.intersection(body):
            raise ValueError("body contains reserved signed parameter")
        self.ensure_access_token()
        timestamp = int(self.clock())
        query = urlencode({"partner_id": self.config.partner_id, "timestamp": timestamp,
                           "sign": build_shop_signature(self.config, api_path, timestamp),
                           "access_token": self.config.access_token, "shop_id": self.config.shop_id})
        request = Request(f"{self.config.base_url}{api_path}?{query}", data=json.dumps(body, allow_nan=False).encode(),
                          headers={"Content-Type": "application/json"}, method="POST")
        # Credential refresh/locking above can outlive a finite stock plan.
        if before_dispatch is not None and before_dispatch() is not True:
            raise StockWritePreconditionFailed("Stock write precondition changed before dispatch")
        try:
            with self.opener(request, timeout=30) as response:
                payload = json.loads(response.read())
                if not isinstance(payload, dict):
                    raise ValueError("Expected object")
                # Preserve per-model failures even when top-level error is set.
                return payload
        except (OSError, URLError, HTTPException, ValueError, ShopeeAPIError):
            raise StockWriteUnknown("Shopee stock write outcome unknown") from None

    def refresh_tokens(self) -> ShopeeConfig:
        return self._ensure_tokens(force=True)

    def _ensure_tokens(self, *, force: bool = False, safety_seconds: int = 300) -> ShopeeConfig:
        previous_secrets = set(self.secrets)

        def refresh(snapshot):
            self.config = _shop_config_from_snapshot(snapshot, self.config.env_file)
            self.secrets.update(snapshot.secrets)
            try:
                payload = self.public_post(
                    "/api/v2/auth/access_token/get",
                    {
                        "partner_id": snapshot.partner_id,
                        "shop_id": snapshot.subject_id,
                        "refresh_token": snapshot.refresh_token,
                    },
                )
            except ShopeeRequestNotSent:
                raise RefreshNotSent("connect_error") from None
            return _validated_token_update(payload, int(self.clock()))

        try:
            snapshot = self.credential_store.ensure(
                refresh,
                force=force,
                safety_seconds=safety_seconds,
            )
        except CredentialError as error:
            raise ShopeeAPIError(str(error)) from None
        self.config = _shop_config_from_snapshot(snapshot, self.config.env_file)
        self.secrets.update(previous_secrets)
        self.secrets.update(snapshot.secrets)
        return self.config

    def ensure_access_token(self, safety_seconds: int = 300) -> ShopeeConfig:
        return self._ensure_tokens(safety_seconds=safety_seconds)


def _validated_token_update(payload: dict[str, object], now: int) -> TokenUpdate:
    access = payload.get("access_token")
    refresh = payload.get("refresh_token")
    lifetime = payload.get("expire_in")
    if type(access) is not str or not access:
        raise ShopeeAPIError("Token response is missing access_token")
    if access.strip() != access or access.splitlines() != [access]:
        raise ShopeeAPIError("Token response has invalid access_token")
    if type(refresh) is not str or not refresh:
        raise ShopeeAPIError("Token response is missing refresh_token")
    if refresh.strip() != refresh or refresh.splitlines() != [refresh]:
        raise ShopeeAPIError("Token response has invalid refresh_token")
    if type(lifetime) is not int or lifetime <= 0:
        raise ShopeeAPIError("Token response has invalid expire_in")
    return TokenUpdate(
        access,
        refresh,
        now + lifetime,
        now + REFRESH_TOKEN_LIFETIME_SECONDS,
    )


def exchange_authorization_code(
    config: PartnerConfig,
    callback_url: str,
    authorization_days: int,
    *,
    opener: Callable = _open_without_redirects,
    clock: Callable[[], float] = time.time,
) -> ShopeeConfig:
    store = CredentialStore(config.env_file, clock=clock)
    try:
        with store.local_update() as transaction:
            config = load_partner_config(config.env_file)
            callback = parse_authorization_callback(config, callback_url)
            now = int(clock())
            client = ShopeePartnerClient(config, opener=opener, clock=clock)
            client.secrets.add(callback.code)
            payload = client.public_post(
                "/api/v2/auth/token/get",
                {
                    "code": callback.code,
                    "shop_id": callback.shop_id,
                    "partner_id": config.partner_id,
                },
            )
            update = _validated_token_update(payload, now)
            client.secrets.update((update.access_token, update.refresh_token))
            transaction.update(
                {
                    "SHOPEE_SHOP_ID": str(callback.shop_id),
                    "SHOPEE_ACCESS_TOKEN": update.access_token,
                    "SHOPEE_REFRESH_TOKEN": update.refresh_token,
                    "SHOPEE_ACCESS_TOKEN_EXPIRES_AT": str(update.access_token_expires_at),
                    "SHOPEE_REFRESH_TOKEN_EXPIRES_AT": str(update.refresh_token_expires_at),
                    "SHOPEE_AUTH_EXPIRES_AT": str(now + authorization_days * 24 * 60 * 60),
                    "SHOPEE_AUTH_STATE": "",
                }
            )
    except (CredentialError, OSError):
        raise ShopeeAPIError("Unable to save authorized Shopee credentials") from None
    return load_config(config.env_file)


SHOP_INFO_PATH = "/api/v2/shop/get_shop_info"
ITEM_LIST_PATH = "/api/v2/product/get_item_list"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Authorize a shop and call read-only Shopee Open APIs")
    parser.add_argument("--env-file", type=Path, required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    initialize = commands.add_parser("init-production")
    initialize.add_argument("--partner-id", type=int, required=True)
    initialize.add_argument("--redirect-url", required=True)
    initialize.add_argument("--partner-key-stdin", action="store_true")
    commands.add_parser("authorization-url")
    exchange = commands.add_parser("exchange-code")
    exchange.add_argument("--callback-url-stdin", action="store_true")
    exchange.add_argument("--authorization-days", type=int, choices=(7, 30, 90, 180, 365), default=365)
    commands.add_parser("shop-info")
    items = commands.add_parser("list-items")
    items.add_argument("--item-status", choices=("NORMAL", "BANNED", "DELETED", "UNLIST"), default="NORMAL")
    items.add_argument("--offset", type=int, default=0)
    items.add_argument("--page-size", type=int, default=20)
    commands.add_parser("refresh-token")
    return parser


def _write_json(stream, payload: dict[str, object]) -> None:
    stream.write(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")


def _read_single_value(stream, *, label: str) -> str:
    value = stream.read()
    if value.endswith("\r\n"):
        value = value[:-2]
    elif value.endswith(("\r", "\n")):
        value = value[:-1]
    return _validate_single_line(value, label)


def run(argv: list[str] | None = None, *, opener: Callable = _open_without_redirects,
        clock: Callable[[], float] = time.time, state_factory: Callable[[], str] = lambda: secrets.token_urlsafe(32),
        stdin=sys.stdin, stdout=sys.stdout, stderr=sys.stderr) -> int:
    parser = build_parser()
    try:
        with contextlib.redirect_stderr(stderr):
            args = parser.parse_args(argv)
    except SystemExit as error:
        return int(error.code)
    if args.command == "list-items" and not 1 <= args.page_size <= 100:
        stderr.write("Error: page-size must be between 1 and 100\n")
        return 2
    if args.command == "list-items" and args.offset < 0:
        stderr.write("Error: offset must be zero or greater\n")
        return 2
    try:
        if args.command == "init-production":
            if args.partner_key_stdin:
                partner_key = _read_single_value(stdin, label="Partner Key")
            else:
                partner_key = _validate_single_line(getpass.getpass("Live Partner Key: "), "Partner Key")
            create_production_env(args.env_file, args.partner_id, partner_key, args.redirect_url)
            _write_json(stdout, {"status": "initialized", "env_file": str(args.env_file),
                                 "partner_id": args.partner_id})
            return 0
        if args.command == "authorization-url":
            state = _validate_single_line(state_factory(), "authorization state")
            try:
                store = CredentialStore(args.env_file)
                with store.local_update() as transaction:
                    partner_config = load_partner_config(args.env_file)
                    authorization_url = build_authorization_url(partner_config, state)
                    transaction.update({"SHOPEE_AUTH_STATE": state})
            except (CredentialError, OSError):
                raise ShopeeAPIError("Unable to save authorization state") from None
            _write_json(stdout, {"authorization_url": authorization_url})
            return 0
        if args.command == "exchange-code":
            partner_config = load_partner_config(args.env_file)
            if args.callback_url_stdin:
                callback_url = _read_single_value(stdin, label="callback URL")
            else:
                callback_url = _validate_single_line(getpass.getpass("Callback URL: "), "callback URL")
            config = exchange_authorization_code(
                partner_config,
                callback_url,
                args.authorization_days,
                opener=opener,
                clock=clock,
            )
            _write_json(
                stdout,
                {
                    "status": "authorized",
                    "shop_id": config.shop_id,
                    "access_token_expires_at": config.access_token_expires_at,
                    "refresh_token_expires_at": config.refresh_token_expires_at,
                    "authorization_expires_at": config.auth_expires_at,
                },
            )
            return 0
        client = ShopeeClient(load_config(args.env_file), opener=opener, clock=clock)
        if args.command == "refresh-token":
            config = client.refresh_tokens()
            _write_json(stdout, {"access_token_expires_at": config.access_token_expires_at,
                                 "refresh_token_expires_at": config.refresh_token_expires_at})
            return 0
        client.ensure_access_token()
        if args.command == "shop-info":
            payload = client.shop_get(SHOP_INFO_PATH)
        else:
            payload = client.shop_get(ITEM_LIST_PATH, {"offset": args.offset, "page_size": args.page_size,
                                                        "item_status": args.item_status})
        _write_json(stdout, _sanitize_payload(payload, client.secrets))
        return 0
    except (ConfigError, ShopeeAPIError, CredentialError) as error:
        stderr.write(f"Error: {error}\n")
        return 1


def main() -> int:
    return run()


if __name__ == "__main__":
    raise SystemExit(main())
