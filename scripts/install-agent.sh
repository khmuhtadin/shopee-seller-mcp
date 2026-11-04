#!/bin/sh
# Connect an MCP client to a remote shopee-seller-mcp server.
#
# POSIX sh; needs no Python. The bearer token is read from an environment
# variable (default SHOPEE_MCP_TOKEN) and is never passed on the command line
# of this script.
#
# Usage:
#   export SHOPEE_MCP_TOKEN=...            # from `shopee-mcp-http token create`
#   sh install-agent.sh <claude-code|codex|cursor> https://mcp.example.com/mcp
#   curl -fsSL <raw-url>/scripts/install-agent.sh | sh -s -- codex https://mcp.example.com/mcp
#
# Options (environment):
#   SHOPEE_MCP_NAME=shopee        server name in the client config
#   SHOPEE_MCP_TOKEN_ENV=SHOPEE_MCP_TOKEN  name of the variable holding the token
#   DRY_RUN=1                     only print what would be done
#
# What it does:
#   claude-code  runs `claude mcp add --transport http --scope user ...` (Claude Code
#                stores the header, including the token, in its user config)
#   codex        appends [mcp_servers.<name>] to ~/.codex/config.toml with
#                bearer_token_env_var (the token itself is not written)
#   cursor       adds the server to ~/.cursor/mcp.json using ${env:VAR}
#                (needs jq or node to merge into an existing file)
# Existing files are backed up first; existing entries with the same name are
# never overwritten (remove them yourself, or use `shopee-mcp-http connect --write`).
set -eu

NAME="${SHOPEE_MCP_NAME:-shopee}"
TOKEN_ENV="${SHOPEE_MCP_TOKEN_ENV:-SHOPEE_MCP_TOKEN}"
DRY_RUN="${DRY_RUN:-0}"

die() { printf 'install-agent: %s\n' "$*" >&2; exit 1; }
info() { printf '%s\n' "$*"; }

usage() {
    printf '%s\n' "usage: SHOPEE_MCP_TOKEN=... sh install-agent.sh <claude-code|codex|cursor> https://mcp.example.com/mcp" >&2
    exit 2
}

[ $# -eq 2 ] || usage
CLIENT="$1"
URL="$2"

case "$NAME" in
    ''|*[!A-Za-z0-9_-]*) die "SHOPEE_MCP_NAME may only contain letters, digits, '-' and '_'" ;;
esac
case "$TOKEN_ENV" in
    ''|[0-9]*|*[!A-Za-z0-9_]*) die "SHOPEE_MCP_TOKEN_ENV must be an environment variable name" ;;
esac
case "$URL" in
    https://*/*|http://127.0.0.1:*/*|http://localhost:*/*) ;;
    *) die "URL must be https and include the MCP path, e.g. https://mcp.example.com/mcp" ;;
esac
if printf '%s' "$URL" | grep -q "[[:space:]\"'\\\\\$\`]"; then
    die "URL contains characters that are not allowed"
fi

TOKEN=$(eval "printf '%s' \"\${$TOKEN_ENV:-}\"")

backup() {
    if [ -f "$1" ]; then
        stamp=$(date +%Y%m%d-%H%M%S)
        dest="$1.bak-$stamp"
        n=1
        while [ -e "$dest" ]; do dest="$1.bak-$stamp-$n"; n=$((n + 1)); done
        cp -p "$1" "$dest"
        chmod 600 "$dest"
        info "backup: $dest"
    fi
}

install_claude_code() {
    [ -n "$TOKEN" ] || die "set \$$TOKEN_ENV to your bearer token first"
    command -v claude >/dev/null 2>&1 || die "the 'claude' CLI was not found; install Claude Code first"
    if claude mcp get "$NAME" >/dev/null 2>&1; then
        die "Claude Code already has a server named '$NAME'; run: claude mcp remove $NAME"
    fi
    if [ "$DRY_RUN" = "1" ]; then
        info "[dry-run] claude mcp add --transport http --scope user $NAME $URL --header \"Authorization: Bearer \$$TOKEN_ENV\""
        return
    fi
    claude mcp add --transport http --scope user "$NAME" "$URL" --header "Authorization: Bearer $TOKEN"
    info "added '$NAME' to Claude Code (user scope)"
}

install_codex() {
    dir="${CODEX_HOME:-$HOME/.codex}"
    file="$dir/config.toml"
    if [ -f "$file" ] && grep -Eq "^[[:space:]]*\[mcp_servers\.\"?$NAME\"?\]" "$file"; then
        die "$file already defines [mcp_servers.$NAME]; edit or remove it first"
    fi
    if [ -f "$file" ] && grep -Eq "^[[:space:]]*$NAME[[:space:]]*=" "$file"; then
        die "$file may define '$NAME' inline; edit it manually"
    fi
    block=$(printf '\n[mcp_servers.%s]\nurl = "%s"\nbearer_token_env_var = "%s"\n' "$NAME" "$URL" "$TOKEN_ENV")
    if [ "$DRY_RUN" = "1" ]; then
        info "[dry-run] append to $file:"; info "$block"; return
    fi
    mkdir -p "$dir"
    backup "$file"
    printf '%s\n' "$block" >> "$file"
    info "added [mcp_servers.$NAME] to $file"
    [ -n "$TOKEN" ] || info "note: export $TOKEN_ENV before starting Codex"
}

install_cursor() {
    dir="$HOME/.cursor"
    file="$dir/mcp.json"
    header="Bearer \${env:$TOKEN_ENV}"
    if [ ! -s "$file" ]; then
        if [ "$DRY_RUN" = "1" ]; then info "[dry-run] create $file"; return; fi
        mkdir -p "$dir"
        umask 077
        printf '{\n  "mcpServers": {\n    "%s": {\n      "url": "%s",\n      "headers": {\n        "Authorization": "%s"\n      }\n    }\n  }\n}\n' \
            "$NAME" "$URL" "$header" > "$file"
        info "created $file"
        return
    fi
    tmp="$file.tmp.$$"
    if command -v jq >/dev/null 2>&1; then
        if jq -e --arg n "$NAME" '(.mcpServers // {}) | has($n)' "$file" >/dev/null; then
            die "$file already has a server named '$NAME'; remove it first"
        fi
        [ "$DRY_RUN" = "1" ] && { info "[dry-run] merge '$NAME' into $file with jq"; return; }
        backup "$file"
        jq --arg n "$NAME" --arg u "$URL" --arg h "$header" \
            '.mcpServers = ((.mcpServers // {}) + {($n): {url: $u, headers: {Authorization: $h}}})' "$file" > "$tmp"
    elif command -v node >/dev/null 2>&1; then
        [ "$DRY_RUN" = "1" ] && { info "[dry-run] merge '$NAME' into $file with node"; return; }
        backup "$file"
        N="$NAME" U="$URL" H="$header" F="$file" node -e '
const fs = require("fs");
const data = JSON.parse(fs.readFileSync(process.env.F, "utf8"));
if (typeof data !== "object" || data === null || Array.isArray(data)) process.exit(3);
data.mcpServers = data.mcpServers || {};
if (Object.prototype.hasOwnProperty.call(data.mcpServers, process.env.N)) process.exit(4);
data.mcpServers[process.env.N] = { url: process.env.U, headers: { Authorization: process.env.H } };
process.stdout.write(JSON.stringify(data, null, 2) + "\n");
' > "$tmp" || { rm -f "$tmp"; die "could not merge $file (invalid JSON or '$NAME' already present)"; }
    else
        info "Neither jq nor node is available. Add this to the \"mcpServers\" object in $file:"
        printf '"%s": {"url": "%s", "headers": {"Authorization": "%s"}}\n' "$NAME" "$URL" "$header"
        return
    fi
    chmod 600 "$tmp"
    mv "$tmp" "$file"
    info "added '$NAME' to $file"
    [ -n "$TOKEN" ] || info "note: export $TOKEN_ENV in the environment Cursor starts from"
}

case "$CLIENT" in
    claude-code) install_claude_code ;;
    codex) install_codex ;;
    cursor) install_cursor ;;
    *) die "client must be claude-code, codex or cursor (use 'shopee-mcp-http connect' for others)" ;;
esac
