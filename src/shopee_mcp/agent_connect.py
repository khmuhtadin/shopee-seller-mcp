"""``shopee-mcp-http connect <client>``: configure MCP clients for a remote server.

By default the exact snippet and its target path are printed. ``--write`` merges
the entry into the client's JSON/TOML config: a timestamped backup is made
first, only the named server entry is added or replaced (other servers and
settings are preserved) and the file is replaced atomically.

The bearer token is referenced through an environment variable wherever the
client supports it. The raw token is written only with ``--inline-token``,
which reads it from that environment variable (never from the command line).

The merge helpers (``merge_json_config``, ``merge_codex_toml``) are pure
functions so they can be tested without touching real config files.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import sys
import tempfile
import time
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

CLIENTS = ("claude-code", "codex", "cursor", "claude-desktop", "vscode", "gemini-cli", "windsurf")
DEFAULT_NAME = "shopee"
DEFAULT_TOKEN_ENV = "SHOPEE_MCP_TOKEN"
VSCODE_INPUT_ID = "shopee-mcp-token"
_NAME_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
_ENV_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
_LOOPBACK = {"localhost", "127.0.0.1", "::1"}


class ConnectError(ValueError):
    """User-facing configuration error (never contains the token)."""


@dataclass
class Plan:
    client: str
    path: Path | None                 # target config file
    fmt: str                          # "json" or "toml"
    container: str = "mcpServers"     # JSON object holding servers
    entry: Any = None                 # JSON entry or TOML block text
    inputs: list = field(default_factory=list)
    command: str | None = None        # alternative shell command (claude-code)
    notes: list[str] = field(default_factory=list)


# ------------------------------------------------------------ validation

def validate_url(url: str) -> str:
    try:
        parts = urlsplit(url.strip())
        host = (parts.hostname or "").lower()
    except ValueError:
        raise ConnectError("--url is not a valid URL") from None
    if parts.scheme == "http" and host in _LOOPBACK:
        pass
    elif parts.scheme != "https" or not host:
        raise ConnectError("--url must be an https URL, e.g. https://mcp.example.com/mcp")
    if parts.username or parts.password or parts.fragment or parts.query:
        raise ConnectError("--url must not contain credentials, a query or a fragment")
    if not parts.path or parts.path == "/":
        raise ConnectError("--url must include the MCP path, e.g. https://mcp.example.com/mcp")
    if any(ch.isspace() or ch in "\"'\\$`" for ch in url):
        raise ConnectError("--url contains characters that are not allowed")
    return url.strip()


def validate_name(name: str) -> str:
    if not _NAME_RE.fullmatch(name or ""):
        raise ConnectError("--name must be 1-64 characters: letters, digits, '-' or '_'")
    return name


def validate_env_name(name: str) -> str:
    if not _ENV_RE.fullmatch(name or ""):
        raise ConnectError("--token-env must be an environment variable name")
    return name


# ---------------------------------------------------------------- paths

def default_path(client: str, *, home: Path | None = None, cwd: Path | None = None,
                 platform: str | None = None, environ: dict | None = None) -> Path:
    home = Path.home() if home is None else home
    cwd = Path.cwd() if cwd is None else cwd
    platform = sys.platform if platform is None else platform
    environ = os.environ if environ is None else environ
    if client == "claude-code":
        return cwd / ".mcp.json"
    if client == "codex":
        return Path(environ.get("CODEX_HOME") or home / ".codex") / "config.toml"
    if client == "cursor":
        return home / ".cursor" / "mcp.json"
    if client == "vscode":
        return cwd / ".vscode" / "mcp.json"
    if client == "gemini-cli":
        return home / ".gemini" / "settings.json"
    if client == "windsurf":
        return home / ".codeium" / "windsurf" / "mcp_config.json"
    if client == "claude-desktop":
        if platform == "darwin":
            return home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
        if platform.startswith("win"):
            return Path(environ.get("APPDATA") or home / "AppData" / "Roaming") / "Claude" / "claude_desktop_config.json"
        return home / ".config" / "Claude" / "claude_desktop_config.json"
    raise ConnectError(f"unknown client {client!r}")


# ---------------------------------------------------------------- plans

def _toml_string(value: str) -> str:
    # JSON string escapes (\" \\ \n \uXXXX) are valid TOML basic-string escapes.
    return json.dumps(value, ensure_ascii=False)


def codex_block(name: str, url: str, token_env: str, token: str | None = None) -> str:
    lines = [f"[mcp_servers.{name}]", f"url = {_toml_string(url)}"]
    if token is None:
        lines.append(f"bearer_token_env_var = {_toml_string(token_env)}")
    else:
        lines.append(f"http_headers = {{ \"Authorization\" = {_toml_string('Bearer ' + token)} }}")
    return "\n".join(lines) + "\n"


def build_plan(client: str, url: str, *, name: str = DEFAULT_NAME, token_env: str = DEFAULT_TOKEN_ENV,
               token: str | None = None, path: Path | None = None, **path_kwargs) -> Plan:
    if client not in CLIENTS:
        raise ConnectError(f"client must be one of: {', '.join(CLIENTS)}")
    url, name, token_env = validate_url(url), validate_name(name), validate_env_name(token_env)
    target = path if path is not None else default_path(client, **path_kwargs)
    bearer = None if token is None else f"Bearer {token}"
    if client == "codex":
        plan = Plan(client, target, "toml", entry=codex_block(name, url, token_env, token))
        if token is None:
            plan.notes.append(f"Codex reads the token from ${token_env}; export it in the environment that starts Codex.")
        return plan
    if client == "claude-code":
        header = bearer or f"Bearer ${{{token_env}}}"
        plan = Plan(client, target, "json", entry={"type": "http", "url": url, "headers": {"Authorization": header}})
        plan.command = (f'claude mcp add --transport http {name} {url} '
                        f'--header "Authorization: Bearer ${{{token_env}}}"')
        plan.notes.append("The project .mcp.json expands ${VAR} at runtime. The 'claude mcp add' command expands the "
                          "token in your shell, so Claude Code stores its value in your user config.")
        return plan
    if client == "cursor":
        header = bearer or f"Bearer ${{env:{token_env}}}"
        return Plan(client, target, "json", entry={"url": url, "headers": {"Authorization": header}})
    if client == "windsurf":
        header = bearer or f"Bearer ${{env:{token_env}}}"
        return Plan(client, target, "json", entry={"serverUrl": url, "headers": {"Authorization": header}})
    if client == "gemini-cli":
        header = bearer or f"Bearer ${{{token_env}}}"
        return Plan(client, target, "json", entry={"httpUrl": url, "headers": {"Authorization": header}})
    if client == "vscode":
        if bearer is None:
            plan = Plan(client, target, "json", container="servers",
                        entry={"type": "http", "url": url, "headers": {"Authorization": f"Bearer ${{input:{VSCODE_INPUT_ID}}}"}},
                        inputs=[{"type": "promptString", "id": VSCODE_INPUT_ID,
                                 "description": "Shopee MCP bearer token", "password": True}])
            plan.notes.append("VS Code prompts for the token once and stores it in its secret storage.")
            return plan
        return Plan(client, target, "json", container="servers",
                    entry={"type": "http", "url": url, "headers": {"Authorization": bearer}})
    # claude-desktop: stdio bridge via mcp-remote; Claude Desktop does not expand variables.
    header_env = "SHOPEE_MCP_AUTH_HEADER"
    plan = Plan(client, target, "json", entry={
        "command": "npx", "args": ["-y", "mcp-remote", url, "--header", f"Authorization:${{{header_env}}}"],
        "env": {header_env: bearer or "Bearer <paste-your-token-here>"}})
    plan.notes.append("Claude Desktop needs the token value in its config (it does not read your shell). Use "
                      "--write --inline-token, or prefer the OAuth custom connector (Settings > Connectors).")
    return plan


# ---------------------------------------------------------------- merge

def merge_json_config(text: str | None, container: str, name: str, entry: Any,
                      inputs: list | None = None) -> tuple[str, bool]:
    """Add/replace ``data[container][name]``; every other key is preserved. Returns (text, replaced)."""
    if text is None or not text.strip():
        data: dict = {}
    else:
        try:
            data = json.loads(text)
        except ValueError:
            raise ConnectError("existing config is not plain JSON (comments?); add the snippet manually") from None
        if not isinstance(data, dict):
            raise ConnectError("existing config is not a JSON object; add the snippet manually")
    servers = data.setdefault(container, {})
    if not isinstance(servers, dict):
        raise ConnectError(f"existing config has a non-object {container!r}; add the snippet manually")
    replaced = name in servers
    servers[name] = entry
    if inputs:
        existing = data.setdefault("inputs", [])
        if not isinstance(existing, list):
            raise ConnectError("existing config has a non-list 'inputs'; add the snippet manually")
        known = {item.get("id") for item in existing if isinstance(item, dict)}
        existing.extend(item for item in inputs if item["id"] not in known)
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n", replaced


def _codex_header(line: str, name: str) -> bool | None:
    """True for our table/sub-table header, False for another header, None for a non-header line."""
    stripped = line.strip()
    if not stripped.startswith("["):
        return None
    match = re.match(r"^\[\[?\s*([^\]]+?)\s*\]\]?\s*(#.*)?$", stripped)
    if not match:
        return False
    key = [part.strip().strip('"').strip("'") for part in match.group(1).split(".")]
    return len(key) >= 2 and key[0] == "mcp_servers" and key[1] == name


def merge_codex_toml(text: str | None, name: str, block: str) -> tuple[str, bool]:
    """Replace ``[mcp_servers.<name>]`` (and its sub-tables) or append it. Returns (text, replaced)."""
    text = text or ""
    try:
        before = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        raise ConnectError("existing config.toml is not valid TOML; add the snippet manually") from None
    servers_before = before.get("mcp_servers", {})
    replaced = isinstance(servers_before, dict) and name in servers_before
    kept: list[str] = []
    skipping = False
    found_table = False
    for line in text.splitlines(keepends=True):
        header = _codex_header(line, name)
        if header is True:
            skipping, found_table = True, True
            continue
        if header is False:
            skipping = False
        if not skipping:
            kept.append(line)
    if replaced and not found_table:
        raise ConnectError(f"mcp_servers.{name} is defined inline; edit config.toml manually")
    result = "".join(kept).rstrip("\n")
    result = (result + "\n\n" if result else "") + block
    try:
        after = tomllib.loads(result)
    except tomllib.TOMLDecodeError:
        raise ConnectError("could not merge config.toml safely; add the snippet manually") from None
    expected = tomllib.loads(block)["mcp_servers"][name]
    others_before = {k: v for k, v in before.items() if k != "mcp_servers"}
    others_after = {k: v for k, v in after.items() if k != "mcp_servers"}
    servers_after = after.get("mcp_servers", {})
    unrelated_before = {k: v for k, v in (servers_before if isinstance(servers_before, dict) else {}).items() if k != name}
    unrelated_after = {k: v for k, v in servers_after.items() if k != name}
    if (servers_after.get(name) != expected or others_before != others_after or unrelated_before != unrelated_after):
        raise ConnectError("could not merge config.toml safely; add the snippet manually")
    return result, replaced


def merged_text(plan: Plan, existing: str | None, name: str) -> tuple[str, bool]:
    if plan.fmt == "toml":
        return merge_codex_toml(existing, name, plan.entry)
    return merge_json_config(existing, plan.container, name, plan.entry, plan.inputs)


def snippet(plan: Plan, name: str) -> str:
    if plan.fmt == "toml":
        return plan.entry
    body: dict = {plan.container: {name: plan.entry}}
    if plan.inputs:
        body["inputs"] = plan.inputs
    return json.dumps(body, indent=2) + "\n"


# ---------------------------------------------------------------- write

def write_config(path: Path, text: str, *, clock=time.time) -> Path | None:
    """Backup (if present) then atomically replace. Symlinks are followed to their target."""
    target = Path(os.path.realpath(path))
    backup = None
    mode = 0o600
    if target.exists():
        mode = target.stat().st_mode & 0o777
        stamp = time.strftime('%Y%m%d-%H%M%S', time.localtime(clock()))
        backup = target.with_name(f"{target.name}.bak-{stamp}")
        counter = 1
        while backup.exists():  # never overwrite an earlier backup
            backup = target.with_name(f"{target.name}.bak-{stamp}-{counter}")
            counter += 1
        shutil.copy2(target, backup)
        os.chmod(backup, 0o600)
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=target.parent, prefix=f".{target.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, target)
    finally:
        if os.path.exists(name):
            os.unlink(name)
    return backup


# ------------------------------------------------------------------ CLI

def add_connect_parser(commands) -> None:
    connect = commands.add_parser("connect", help="Print or write MCP client config for a remote server")
    connect.add_argument("client", choices=CLIENTS)
    connect.add_argument("--url", required=True, help="Remote MCP URL, e.g. https://mcp.example.com/mcp")
    connect.add_argument("--token-env", default=DEFAULT_TOKEN_ENV,
                         help=f"Environment variable holding the bearer token (default {DEFAULT_TOKEN_ENV})")
    connect.add_argument("--name", default=DEFAULT_NAME, help=f"Server name in the client config (default {DEFAULT_NAME})")
    connect.add_argument("--config", type=Path, default=None, help="Override the target config file path")
    mode = connect.add_mutually_exclusive_group()
    mode.add_argument("--print", dest="write", action="store_false", help="Print the snippet and target path (default)")
    mode.add_argument("--write", dest="write", action="store_true", help="Merge into the config file (with backup)")
    connect.add_argument("--inline-token", action="store_true",
                         help="Write the token value (read from --token-env) instead of a reference to it")
    connect.set_defaults(write=False)


def run_connect(args, *, stdout=None, stderr=None) -> int:
    stdout = sys.stdout if stdout is None else stdout
    stderr = sys.stderr if stderr is None else stderr
    token = None
    token_env = validate_env_name(args.token_env)
    if args.inline_token:
        token = os.environ.get(token_env, "").strip()
        if not token or token.splitlines() != [token] or any(ch in token for ch in "\"'\\ "):
            raise ConnectError(f"--inline-token needs a valid token in ${token_env}")
    plan = build_plan(args.client, args.url, name=args.name, token_env=token_env, token=token, path=args.config)
    if not args.write:
        stdout.write(f"# Target: {plan.path}\n")
        stdout.write(snippet(plan, args.name))
        if plan.command:
            stdout.write(f"\n# Or register it globally with the Claude Code CLI:\n{plan.command}\n")
        for note in plan.notes:
            stderr.write(f"note: {note}\n")
        if token is None:
            stderr.write(f"note: set {token_env} to a token from 'shopee-mcp-http token create'.\n")
        return 0
    if args.client == "claude-desktop" and token is None:
        raise ConnectError("claude-desktop cannot read environment variables; use --write --inline-token, "
                           "or add the server as a custom connector with OAuth")
    existing = None
    real = Path(os.path.realpath(plan.path))
    if real.exists():
        try:
            existing = real.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            raise ConnectError("unable to read the existing config file") from None
    text, replaced = merged_text(plan, existing, args.name)
    backup = write_config(plan.path, text)
    action = "replaced" if replaced else "added"
    stdout.write(f"{action} server '{args.name}' in {plan.path}\n")
    if backup:
        stdout.write(f"backup: {backup}\n")
    for note in plan.notes:
        stderr.write(f"note: {note}\n")
    return 0
