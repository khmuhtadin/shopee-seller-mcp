# Connecting MCP clients

Endpoint: `https://mcp.example.com/mcp` (replace with your public URL).

Two authentication methods work at the same time:

- **OAuth 2.1** for ChatGPT and Claude.ai custom connectors. The client registers itself and opens the consent page; approve with the operator passphrase.
- **Static bearer tokens** for everything else: `shopee-mcp-http token create --auth-file <auth.db> --label <name>`. The token is printed once; keep it in a secret manager and export it as `SHOPEE_MCP_TOKEN` where needed.

The transport is stateless Streamable HTTP with JSON responses (no `Mcp-Session-Id`, no long-lived SSE stream), so proxy idle timeouts and server restarts do not break clients.

## ChatGPT

Add a custom MCP connector (developer mode), enter the endpoint URL and choose **OAuth**. ChatGPT discovers the authorization server, registers, and opens the consent page. Check that the client ID and redirect URI look right, enter the operator passphrase and approve. Only approve requests you started yourself.

## Claude.ai and Claude Desktop

Add a custom connector with the endpoint URL. OAuth is discovered automatically; approve on the consent page. Connectors added on claude.ai are also available in Claude Desktop.

To use a bearer token in Claude Desktop instead, bridge through `mcp-remote` (requires Node.js). Claude Desktop does not read your shell environment, so the token has to be written into its config:

```bash
SHOPEE_MCP_TOKEN=smcp_... shopee-mcp-http connect claude-desktop --url https://mcp.example.com/mcp --write --inline-token
```

## `shopee-mcp-http connect`

```text
shopee-mcp-http connect <client> --url https://mcp.example.com/mcp
    [--token-env SHOPEE_MCP_TOKEN] [--name shopee] [--config PATH]
    [--print | --write] [--inline-token]
```

- Default (`--print`): prints the target path and the exact snippet. Nothing is written.
- `--write`: merges the entry into the config file. A timestamped backup (`<file>.bak-YYYYmmdd-HHMMSS`) is created first, other servers and settings are preserved, and the file is replaced atomically. Files with comments (JSONC) or unexpected structure are refused; add the snippet by hand.
- The token is referenced through the environment variable (`--token-env`, default `SHOPEE_MCP_TOKEN`). `--inline-token` writes its value instead, read from that variable (never from the command line).

| Client | Target file | Token reference |
| --- | --- | --- |
| `claude-code` | `./.mcp.json` (project); the printed `claude mcp add` command registers it for your user | `${SHOPEE_MCP_TOKEN}` |
| `codex` | `~/.codex/config.toml` (or `$CODEX_HOME`) | `bearer_token_env_var = "SHOPEE_MCP_TOKEN"` |
| `cursor` | `~/.cursor/mcp.json` | `${env:SHOPEE_MCP_TOKEN}` |
| `vscode` | `./.vscode/mcp.json` | `${input:shopee-mcp-token}` (VS Code prompts once, stores it securely) |
| `gemini-cli` | `~/.gemini/settings.json` | `${SHOPEE_MCP_TOKEN}` (expanded by Gemini CLI) |
| `windsurf` | `~/.codeium/windsurf/mcp_config.json` | `${env:SHOPEE_MCP_TOKEN}` |
| `claude-desktop` | platform `claude_desktop_config.json` | value required (`--inline-token`) |

Snippets produced:

```bash
# Claude Code (user scope; your shell expands the variable, Claude Code stores the value)
claude mcp add --transport http shopee https://mcp.example.com/mcp --header "Authorization: Bearer ${SHOPEE_MCP_TOKEN}"
```

```toml
# ~/.codex/config.toml
[mcp_servers.shopee]
url = "https://mcp.example.com/mcp"
bearer_token_env_var = "SHOPEE_MCP_TOKEN"
```

```json
// ~/.cursor/mcp.json
{"mcpServers": {"shopee": {"url": "https://mcp.example.com/mcp",
  "headers": {"Authorization": "Bearer ${env:SHOPEE_MCP_TOKEN}"}}}}
```

```json
// .vscode/mcp.json
{"servers": {"shopee": {"type": "http", "url": "https://mcp.example.com/mcp",
  "headers": {"Authorization": "Bearer ${input:shopee-mcp-token}"}}},
 "inputs": [{"type": "promptString", "id": "shopee-mcp-token", "description": "Shopee MCP bearer token", "password": true}]}
```

```json
// ~/.gemini/settings.json
{"mcpServers": {"shopee": {"httpUrl": "https://mcp.example.com/mcp",
  "headers": {"Authorization": "Bearer ${SHOPEE_MCP_TOKEN}"}}}}
```

```json
// ~/.codeium/windsurf/mcp_config.json
{"mcpServers": {"shopee": {"serverUrl": "https://mcp.example.com/mcp",
  "headers": {"Authorization": "Bearer ${env:SHOPEE_MCP_TOKEN}"}}}}
```

## `scripts/install-agent.sh` (no Python)

POSIX shell script for Claude Code, Codex and Cursor. It reads the token from `SHOPEE_MCP_TOKEN`, backs up files before changing them and refuses to overwrite an existing entry with the same name.

```bash
export SHOPEE_MCP_TOKEN=smcp_...
curl -fsSL https://raw.githubusercontent.com/OWNER/shopee-seller-mcp/main/scripts/install-agent.sh \
  | sh -s -- codex https://mcp.example.com/mcp
```

Clients: `claude-code` (runs `claude mcp add --scope user`), `codex` (appends a table using `bearer_token_env_var`), `cursor` (merges with `jq` or `node`, or prints the entry). `DRY_RUN=1` shows what would change. Read scripts before piping them to a shell.

## n8n

Use the **MCP Client Tool** node (attached to an AI Agent node):

- Endpoint: `https://mcp.example.com/mcp`
- Server transport: **HTTP Streamable**
- Authentication: **Header Auth**, with name `Authorization` and value `Bearer <token>`
- Tools to include: all, or select `list_connected_shops`, `get_ads_summary` and others.

For plain HTTP Request nodes or scripts, send JSON-RPC to `POST /mcp` with `Authorization: Bearer <token>`, `Content-Type: application/json` and `Accept: application/json, text/event-stream`.

## OpenAI Agents SDK (Python)

```python
import asyncio
import os

from agents import Agent, Runner
from agents.mcp import MCPServerStreamableHttp


async def main() -> None:
    async with MCPServerStreamableHttp(
        name="shopee",
        params={
            "url": "https://mcp.example.com/mcp",
            "headers": {"Authorization": f"Bearer {os.environ['SHOPEE_MCP_TOKEN']}"},
            "timeout": 120,
        },
        cache_tools_list=True,
    ) as shopee:
        agent = Agent(
            name="Ads analyst",
            instructions="Use the Shopee tools. Always pass explicit shop aliases. Never sum shops together.",
            mcp_servers=[shopee],
        )
        result = await Runner.run(agent, "Compare Ads expense and direct GMV for store-a and store-b in October 2026.")
        print(result.final_output)


asyncio.run(main())
```

## LangChain / LangGraph (Python)

```python
import asyncio
import os

from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent


async def main() -> None:
    client = MultiServerMCPClient({
        "shopee": {
            "transport": "streamable_http",
            "url": "https://mcp.example.com/mcp",
            "headers": {"Authorization": f"Bearer {os.environ['SHOPEE_MCP_TOKEN']}"},
        }
    })
    tools = await client.get_tools()
    agent = create_react_agent("openai:gpt-4.1", tools)
    result = await agent.ainvoke({"messages": [{"role": "user", "content": "List my connected shops and their Ads balances."}]})
    print(result["messages"][-1].content)


asyncio.run(main())
```

## Raw MCP over HTTP

```bash
curl -s https://mcp.example.com/mcp \
  -H "Authorization: Bearer $SHOPEE_MCP_TOKEN" \
  -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_connected_shops","arguments":{}}}'
```
