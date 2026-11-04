"""Explicit alias -> environment-file registry for running several Shopee shops.

Each alias owns exactly one ``CredentialStore`` and (lazily) one ``Transport``.
Lookups are exact and fail closed: there is no case folding, prefix matching,
default shop or fallback to another alias. Diagnostics never contain file
paths or credential values, so they are safe to surface at the MCP boundary.

Configuration file (JSON, absolute path, owner-owned regular file, mode 0600)::

    {"shops": {"store-a": "/abs/path/store-a.env", "store-b": "/abs/path/store-b.env"}}

The legacy single-shop mode is available through ``MultiShopRegistry.from_single``
and is the only mode where an omitted alias is accepted.
"""
from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path
from typing import Any, Callable, Mapping

from .credentials import CredentialError, CredentialStore

SHOP_ARGUMENT = "shop"
ALIAS_PATTERN = r"^[a-z0-9][a-z0-9_-]{0,31}$"
_ALIAS_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,31}")
SHOP_ARGUMENT_SCHEMA = {
    "type": "string",
    "pattern": ALIAS_PATTERN,
    "description": "Configured shop alias. Required; must exactly match a configured alias.",
}
MAX_SHOPS = 64
MAX_CONFIG_BYTES = 64_000


class MultiShopError(CredentialError):
    """Safe, path-free and secret-free diagnostic."""


def _valid_alias(alias: Any) -> bool:
    return type(alias) is str and _ALIAS_RE.fullmatch(alias) is not None


def _check_parent(path: Path) -> None:
    """Refuse files whose directory can be modified by other users."""
    try:
        info = os.stat(path.parent)
    except OSError:
        raise MultiShopError("shop_config_invalid: unreadable directory") from None
    if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (os.getuid(), 0) or info.st_mode & 0o022:
        raise MultiShopError("shop_config_invalid: directory must not be group/world writable")


def _check_path_spelling(path: Any, what: str) -> Path:
    if not isinstance(path, (str, Path)) or str(path) == "" or "\x00" in str(path):
        raise MultiShopError(f"shop_config_invalid: {what} must be an absolute path")
    raw = os.fspath(path)
    path = Path(raw)
    if not path.is_absolute() or not raw.startswith(os.sep):
        raise MultiShopError(f"shop_config_invalid: {what} must be an absolute path")
    # Inspect the raw spelling: pathlib silently drops "." components.
    if any(part in (".", "..") for part in raw.split(os.sep)[1:]) or os.path.normpath(raw) != raw:
        raise MultiShopError(f"shop_config_invalid: {what} must be a normalized path")
    try:
        info = os.lstat(path)
    except OSError:
        raise MultiShopError(f"shop_config_invalid: {what} is missing") from None
    if stat.S_ISLNK(info.st_mode):
        raise MultiShopError(f"shop_config_invalid: {what} must not be a symlink")
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise MultiShopError(f"shop_config_invalid: {what} must be an owner-owned regular file with permissions 0600")
    _check_parent(path)
    return path


def load_shop_config(config_path: Path | str) -> dict[str, Path]:
    """Parse and validate the alias registry file. Never follows symlinks."""
    config_path = _check_path_spelling(config_path, "config file")
    try:
        fd = os.open(config_path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        raise MultiShopError("shop_config_invalid: unable to read config file") from None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise MultiShopError("shop_config_invalid: config file must be an owner-owned regular file with permissions 0600")
        raw = stream.read(MAX_CONFIG_BYTES + 1)
    if len(raw) > MAX_CONFIG_BYTES:
        raise MultiShopError("shop_config_invalid: config file too large")

    def no_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise MultiShopError("shop_config_invalid: duplicate key")
            result[key] = value
        return result

    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates)
    except MultiShopError:
        raise
    except (ValueError, UnicodeError):
        raise MultiShopError("shop_config_invalid: config file is not valid JSON") from None
    if not isinstance(data, dict) or set(data) != {"shops"} or not isinstance(data["shops"], dict):
        raise MultiShopError('shop_config_invalid: expected {"shops": {alias: absolute_env_path}}')
    shops = {}
    for alias, env_path in data["shops"].items():
        if not _valid_alias(alias):
            raise MultiShopError("invalid_shop_alias")
        if not isinstance(env_path, str):
            raise MultiShopError("shop_config_invalid: env file must be an absolute path")
        shops[alias] = Path(env_path)
    resolved_config = config_path.resolve(strict=True)
    for env_path in shops.values():
        _check_path_spelling(env_path, "env file")
        if env_path.resolve(strict=True) == resolved_config:
            raise MultiShopError("shop_config_invalid: env file must differ from config file")
    return shops


class MultiShopRegistry:
    """One CredentialStore and one lazily created Transport per explicit alias."""

    def __init__(self, shops: Mapping[str, Path | str], *, store_factory: Callable = CredentialStore,
                 transport_factory: Callable | None = None, implicit_single: bool = False,
                 validate: bool = True, **transport_kwargs):
        if not isinstance(shops, Mapping) or not shops:
            raise MultiShopError("shop_config_invalid: at least one shop is required")
        if len(shops) > MAX_SHOPS:
            raise MultiShopError("shop_config_invalid: too many shops")
        if implicit_single and len(shops) != 1:
            raise MultiShopError("shop_config_invalid: implicit alias requires exactly one shop")
        if transport_factory is None:
            from .transport import Transport  # Imported lazily; construction never opens connections.
            transport_factory = Transport
        self._transport_factory = transport_factory
        self._transport_kwargs = dict(transport_kwargs)
        self._implicit_single = implicit_single
        self._closed = False
        self._stores: dict[str, CredentialStore] = {}
        self._transports: dict = {}
        canonical: dict[Path, str] = {}
        for alias, env_path in shops.items():
            if not _valid_alias(alias):
                raise MultiShopError("invalid_shop_alias")
            env_path = _check_path_spelling(env_path, "env file")
            try:
                store = store_factory(env_path)
            except CredentialError as error:
                raise MultiShopError(f"shop_config_invalid: credentials for alias {alias!r} rejected") from error
            if store.path in canonical:
                raise MultiShopError("shop_config_invalid: aliases must use distinct env files")
            canonical[store.path] = alias
            self._stores[alias] = store
        if validate:
            self.validate()

    @classmethod
    def from_config_file(cls, config_path: Path | str, **kwargs) -> "MultiShopRegistry":
        if kwargs.get("implicit_single"):
            raise MultiShopError("shop_config_invalid: config files always require explicit aliases")
        return cls(load_shop_config(config_path), **kwargs)

    @classmethod
    def from_single(cls, env_file: Path | str, *, alias: str = "default", **kwargs) -> "MultiShopRegistry":
        """Legacy single-shop mode: the alias may be omitted by callers."""
        kwargs.setdefault("implicit_single", True)
        return cls({alias: env_file}, **kwargs)

    def validate(self, scope: str = "shop") -> None:
        """Local-only validation; rejects two aliases bound to the same shop identity."""
        identities = {}
        for alias, store in self._stores.items():
            try:
                binding = store.snapshot(scope).binding
            except CredentialError as error:
                raise MultiShopError(f"shop_config_invalid: credentials for alias {alias!r} rejected") from error
            if binding in identities:
                raise MultiShopError("shop_config_invalid: aliases must refer to distinct shops")
            identities[binding] = alias

    @property
    def aliases(self) -> tuple[str, ...]:
        return tuple(sorted(self._stores))

    @property
    def implicit_single(self) -> bool:
        return self._implicit_single

    def _ensure_open(self) -> None:
        if self._closed:
            raise MultiShopError("shop_registry_closed")

    def resolve_alias(self, alias: str | None) -> str:
        self._ensure_open()
        if alias is None:
            if self._implicit_single:
                return next(iter(self._stores))
            raise MultiShopError("shop_alias_required")
        if not _valid_alias(alias):
            raise MultiShopError("invalid_shop_alias")
        if alias not in self._stores:
            raise MultiShopError("unknown_shop_alias")
        return alias

    def split_arguments(self, arguments: Mapping[str, Any] | None) -> tuple[str, dict]:
        """Return (alias, endpoint arguments without the shop key); input is not mutated."""
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, Mapping):
            raise MultiShopError("invalid_shop_alias")
        remaining = dict(arguments)
        alias = remaining.pop(SHOP_ARGUMENT, None)
        return self.resolve_alias(alias), remaining

    def store(self, alias: str | None) -> CredentialStore:
        return self._stores[self.resolve_alias(alias)]

    def transport(self, alias: str | None):
        alias = self.resolve_alias(alias)
        transport = self._transports.get(alias)
        if transport is None:
            transport = self._transport_factory(self._stores[alias], **self._transport_kwargs)
            self._transports[alias] = transport
        return transport

    def describe(self) -> list[dict[str, str]]:
        """MCP-safe listing: aliases and environment only, never paths or ids."""
        self._ensure_open()
        result = []
        for alias in self.aliases:
            try:
                env = self._stores[alias].snapshot("public").env
            except CredentialError:
                env = "unavailable"
            result.append({"alias": alias, "env": env})
        return result

    @property
    def secrets(self) -> frozenset[str]:
        values = set()
        for transport in self._transports.values():
            values.update(getattr(transport, "secrets", ()) or ())
        return frozenset(values)

    @property
    def closed(self) -> bool:
        return self._closed

    async def close(self) -> None:
        """Idempotent; closes every created transport even if one close fails."""
        if self._closed:
            return
        self._closed = True
        transports, self._transports = list(self._transports.values()), {}
        failure = None
        for transport in transports:
            try:
                await transport.close()
            except Exception as error:  # Keep closing the rest.
                failure = failure or error
        if failure is not None:
            raise MultiShopError("shop_registry_close_failed") from None

    async def __aenter__(self) -> "MultiShopRegistry":
        self._ensure_open()
        return self

    async def __aexit__(self, *exc_info) -> None:
        await self.close()

    def __repr__(self) -> str:
        return f"MultiShopRegistry(aliases={self.aliases!r}, closed={self._closed})"
