"""Pure-function tests for `shopee-mcp-http connect` (no real client config is touched)."""
import io
import json
import os
import stat
import tomllib
from pathlib import Path

import pytest

from shopee_mcp.agent_connect import (CLIENTS, ConnectError, build_plan, codex_block, default_path, merge_codex_toml,
                                      merge_json_config, merged_text, run_connect, snippet, write_config)
from shopee_mcp.http_server import parser

URL = "https://mcp.example.com/mcp"
TOKEN = "smcp_example_token_value"


def test_every_client_has_a_plan_without_raw_token():
    for client in CLIENTS:
        plan = build_plan(client, URL, home=Path("/h"), cwd=Path("/work"), platform="linux", environ={})
        text = snippet(plan, "shopee")
        assert URL in text and TOKEN not in text
        assert plan.path.is_absolute()


def test_env_references_per_client():
    def header(client):
        return build_plan(client, URL, home=Path("/h"), cwd=Path("/w"), environ={}).entry["headers"]["Authorization"]
    assert header("cursor") == "Bearer ${env:SHOPEE_MCP_TOKEN}"
    assert header("windsurf") == "Bearer ${env:SHOPEE_MCP_TOKEN}"
    assert header("gemini-cli") == "Bearer ${SHOPEE_MCP_TOKEN}"
    assert header("claude-code") == "Bearer ${SHOPEE_MCP_TOKEN}"
    assert header("vscode") == "Bearer ${input:shopee-mcp-token}"
    codex = build_plan("codex", URL, token_env="MY_TOKEN", home=Path("/h"), environ={})
    assert tomllib.loads(codex.entry)["mcp_servers"]["shopee"] == {"url": URL, "bearer_token_env_var": "MY_TOKEN"}
    claude = build_plan("claude-code", URL, cwd=Path("/w"))
    assert claude.command == ('claude mcp add --transport http shopee https://mcp.example.com/mcp '
                              '--header "Authorization: Bearer ${SHOPEE_MCP_TOKEN}"')


def test_inline_token_only_when_given():
    plan = build_plan("cursor", URL, token=TOKEN, home=Path("/h"))
    assert plan.entry["headers"]["Authorization"] == f"Bearer {TOKEN}"
    codex = tomllib.loads(codex_block("shopee", URL, "X", TOKEN))["mcp_servers"]["shopee"]
    assert codex["http_headers"] == {"Authorization": f"Bearer {TOKEN}"} and "bearer_token_env_var" not in codex
    desktop = build_plan("claude-desktop", URL, home=Path("/h"), platform="darwin")
    assert desktop.entry["args"][:3] == ["-y", "mcp-remote", URL]
    assert "Library/Application Support/Claude" in str(desktop.path)


def test_default_paths():
    home, cwd = Path("/h"), Path("/w")
    assert default_path("codex", home=home, environ={}) == Path("/h/.codex/config.toml")
    assert default_path("codex", home=home, environ={"CODEX_HOME": "/c"}) == Path("/c/config.toml")
    assert default_path("cursor", home=home) == Path("/h/.cursor/mcp.json")
    assert default_path("vscode", cwd=cwd) == Path("/w/.vscode/mcp.json")
    assert default_path("gemini-cli", home=home) == Path("/h/.gemini/settings.json")
    assert default_path("windsurf", home=home) == Path("/h/.codeium/windsurf/mcp_config.json")
    assert default_path("claude-code", cwd=cwd) == Path("/w/.mcp.json")
    assert default_path("claude-desktop", home=home, platform="linux") == Path("/h/.config/Claude/claude_desktop_config.json")


@pytest.mark.parametrize("url", ["http://mcp.example.com/mcp", "https://mcp.example.com", "https://u:p" + "@mcp.example.com/mcp",
                                 "https://mcp.example.com/mcp?x=1", "ftp://mcp.example.com/mcp", "https://mcp.example.com/m$cp"])
def test_bad_urls_rejected(url):
    with pytest.raises(ConnectError):
        build_plan("cursor", url, home=Path("/h"))


def test_bad_names_rejected():
    with pytest.raises(ConnectError):
        build_plan("cursor", URL, name="bad name", home=Path("/h"))
    with pytest.raises(ConnectError):
        build_plan("cursor", URL, token_env="1BAD", home=Path("/h"))
    assert build_plan("cursor", "http://127.0.0.1:8091/mcp", home=Path("/h")).entry["url"].startswith("http://127.0.0.1")


def test_json_merge_preserves_unrelated_servers_and_settings():
    existing = json.dumps({"theme": "dark", "mcpServers": {"other": {"url": "https://other.example.com/mcp"}}})
    text, replaced = merge_json_config(existing, "mcpServers", "shopee", {"url": URL})
    data = json.loads(text)
    assert not replaced and data["theme"] == "dark"
    assert data["mcpServers"] == {"other": {"url": "https://other.example.com/mcp"}, "shopee": {"url": URL}}
    again, replaced = merge_json_config(text, "mcpServers", "shopee", {"url": URL + "2"})
    assert replaced and json.loads(again)["mcpServers"]["other"] == {"url": "https://other.example.com/mcp"}
    fresh, _ = merge_json_config(None, "mcpServers", "shopee", {"url": URL})
    assert json.loads(fresh) == {"mcpServers": {"shopee": {"url": URL}}}


def test_json_merge_refuses_unsafe_input():
    for bad in ("// comment\n{}", "[]", '{"mcpServers": []}'):
        with pytest.raises(ConnectError):
            merge_json_config(bad, "mcpServers", "shopee", {"url": URL})


def test_vscode_inputs_are_added_once():
    plan = build_plan("vscode", URL, cwd=Path("/w"))
    existing = json.dumps({"servers": {"git": {"command": "git-mcp"}}, "inputs": [{"id": "other", "type": "promptString"}]})
    text, _ = merged_text(plan, existing, "shopee")
    text, _ = merged_text(plan, text, "shopee")
    data = json.loads(text)
    assert set(data["servers"]) == {"git", "shopee"}
    assert [item["id"] for item in data["inputs"]] == ["other", "shopee-mcp-token"]


def test_codex_merge_appends_and_replaces_only_our_table():
    existing = ('model = "o4"\n\n[mcp_servers.other]\ncommand = "other-mcp"\n\n'
                '[mcp_servers.shopee]\nurl = "https://old.example.com/mcp"\n\n[mcp_servers.shopee.env]\nA = "1"\n\n'
                '[profiles.fast]\nmodel = "o4-mini"\n')
    block = codex_block("shopee", URL, "SHOPEE_MCP_TOKEN")
    text, replaced = merge_codex_toml(existing, "shopee", block)
    data = tomllib.loads(text)
    assert replaced
    assert data["mcp_servers"]["shopee"] == {"url": URL, "bearer_token_env_var": "SHOPEE_MCP_TOKEN"}
    assert data["mcp_servers"]["other"] == {"command": "other-mcp"}
    assert data["model"] == "o4" and data["profiles"] == {"fast": {"model": "o4-mini"}}
    appended, replaced = merge_codex_toml('model = "o4"\n', "shopee", block)
    assert not replaced and tomllib.loads(appended)["mcp_servers"]["shopee"]["url"] == URL
    assert tomllib.loads(merge_codex_toml(None, "shopee", block)[0])["mcp_servers"]["shopee"]["url"] == URL


def test_codex_merge_refuses_inline_or_invalid():
    block = codex_block("shopee", URL, "SHOPEE_MCP_TOKEN")
    with pytest.raises(ConnectError):
        merge_codex_toml('[mcp_servers]\nshopee = { url = "https://old.example.com/mcp" }\n', "shopee", block)
    with pytest.raises(ConnectError):
        merge_codex_toml("not = [valid", "shopee", block)


def test_write_config_backs_up_and_keeps_mode(tmp_path):
    target = tmp_path / "mcp.json"
    target.write_text('{"mcpServers": {}}')
    target.chmod(0o640)
    backup = write_config(target, '{"mcpServers": {"shopee": {}}}\n', clock=lambda: 0)
    assert backup is not None and backup.read_text() == '{"mcpServers": {}}'
    assert stat.S_IMODE(os.stat(backup).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o640
    assert json.loads(target.read_text()) == {"mcpServers": {"shopee": {}}}
    created = tmp_path / "new" / "config.toml"
    assert write_config(created, "x = 1\n") is None and created.read_text() == "x = 1\n"


def test_cli_print_and_write(tmp_path, monkeypatch):
    target = tmp_path / "cursor.json"
    target.write_text(json.dumps({"mcpServers": {"other": {"url": "https://other.example.com/mcp"}}}))
    out, err = io.StringIO(), io.StringIO()
    args = parser().parse_args(["connect", "cursor", "--url", URL, "--config", str(target)])
    assert run_connect(args, stdout=out, stderr=err) == 0
    assert f"# Target: {target}" in out.getvalue() and "${env:SHOPEE_MCP_TOKEN}" in out.getvalue()
    assert json.loads(target.read_text())["mcpServers"] == {"other": {"url": "https://other.example.com/mcp"}}
    write = parser().parse_args(["connect", "cursor", "--url", URL, "--config", str(target), "--write"])
    assert run_connect(write, stdout=io.StringIO(), stderr=io.StringIO()) == 0
    data = json.loads(target.read_text())
    assert set(data["mcpServers"]) == {"other", "shopee"}
    assert TOKEN not in target.read_text()
    monkeypatch.setenv("SHOPEE_MCP_TOKEN", TOKEN)
    inline = parser().parse_args(["connect", "cursor", "--url", URL, "--config", str(target), "--write", "--inline-token"])
    assert run_connect(inline, stdout=io.StringIO(), stderr=io.StringIO()) == 0
    assert json.loads(target.read_text())["mcpServers"]["shopee"]["headers"]["Authorization"] == f"Bearer {TOKEN}"
    assert len(list(tmp_path.glob("cursor.json.bak-*"))) >= 1


def test_cli_claude_desktop_write_requires_inline_token(tmp_path, monkeypatch):
    monkeypatch.delenv("SHOPEE_MCP_TOKEN", raising=False)
    args = parser().parse_args(["connect", "claude-desktop", "--url", URL, "--config", str(tmp_path / "c.json"), "--write"])
    with pytest.raises(ConnectError):
        run_connect(args, stdout=io.StringIO(), stderr=io.StringIO())
    inline = parser().parse_args(["connect", "claude-desktop", "--url", URL, "--config", str(tmp_path / "c.json"),
                                  "--write", "--inline-token"])
    with pytest.raises(ConnectError):  # token variable not set
        run_connect(inline, stdout=io.StringIO(), stderr=io.StringIO())
    assert not (tmp_path / "c.json").exists()
