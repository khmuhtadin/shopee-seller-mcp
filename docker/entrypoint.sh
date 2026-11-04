#!/bin/sh
# Container entrypoint for the remote HTTP mode.
#
# First boot: creates the data directory (0700), an empty shops file and the
# auth database, and sets the operator passphrase from
# SHOPEE_MCP_ADMIN_PASSPHRASE if none is stored yet. Then it execs
# `shopee-mcp-http serve` bound to 0.0.0.0:$PORT.
#
# Environment:
#   SHOPEE_MCP_PUBLIC_URL        public https base URL (falls back to RENDER_EXTERNAL_URL
#                                or https://$RAILWAY_PUBLIC_DOMAIN when unset)
#   SHOPEE_MCP_ADMIN_PASSPHRASE  operator passphrase (12+ chars), applied only if none is set
#   SHOPEE_MCP_ADMIN_PASSPHRASE_RESET=true  replace the stored passphrase on this boot
#   SHOPEE_PARTNER_ID / SHOPEE_PARTNER_KEY  partner app credentials (read by the server)
#   SHOPEE_SANDBOX_PARTNER_ID / SHOPEE_SANDBOX_PARTNER_KEY  optional sandbox app
#   SHOPEE_MCP_CLIENT_IP_HEADER + SHOPEE_MCP_TRUSTED_PROXIES  optional, see docs/SECURITY.md
#   PORT (default 8080), SHOPEE_MCP_DATA_DIR (default /data), SHOPEE_MCP_LOG_LEVEL
set -eu

DATA_DIR="${SHOPEE_MCP_DATA_DIR:-/data}"
APP_USER="app"

if [ "$(id -u)" = "0" ]; then
    # Volumes are often mounted root-owned: fix ownership, then drop privileges.
    mkdir -p "$DATA_DIR"
    chown -R "$APP_USER:$APP_USER" "$DATA_DIR"
    chmod 0700 "$DATA_DIR"
    exec gosu "$APP_USER" "$0" "$@"
fi

umask 077
PORT="${PORT:-8080}"
SHOPS_FILE="$DATA_DIR/shops.json"
AUTH_FILE="$DATA_DIR/auth.db"

if ! mkdir -p "$DATA_DIR/shops" 2>/dev/null || ! [ -w "$DATA_DIR" ]; then
    echo "entrypoint: $DATA_DIR is not writable by uid $(id -u); mount a writable volume at $DATA_DIR" >&2
    exit 1
fi
chmod 0700 "$DATA_DIR" "$DATA_DIR/shops"

if [ ! -e "$SHOPS_FILE" ]; then
    printf '{"shops": {}}\n' > "$SHOPS_FILE"
fi
chmod 0600 "$SHOPS_FILE"

PUBLIC_URL="${SHOPEE_MCP_PUBLIC_URL:-}"
if [ -z "$PUBLIC_URL" ] && [ -n "${RENDER_EXTERNAL_URL:-}" ]; then
    PUBLIC_URL="$RENDER_EXTERNAL_URL"
fi
if [ -z "$PUBLIC_URL" ] && [ -n "${RAILWAY_PUBLIC_DOMAIN:-}" ]; then
    PUBLIC_URL="https://$RAILWAY_PUBLIC_DOMAIN"
fi
PUBLIC_URL="${PUBLIC_URL%/}"
if [ -z "$PUBLIC_URL" ]; then
    echo "entrypoint: set SHOPEE_MCP_PUBLIC_URL to the public https URL, e.g. https://mcp.example.com" >&2
    exit 1
fi

if [ -n "${SHOPEE_MCP_ADMIN_PASSPHRASE:-}" ]; then
    if [ "${SHOPEE_MCP_ADMIN_PASSPHRASE_RESET:-false}" = "true" ]; then
        printf '%s\n' "$SHOPEE_MCP_ADMIN_PASSPHRASE" | shopee-mcp-http admin set-passphrase --auth-file "$AUTH_FILE"
    else
        printf '%s\n' "$SHOPEE_MCP_ADMIN_PASSPHRASE" | shopee-mcp-http admin set-passphrase --if-unset --auth-file "$AUTH_FILE"
    fi
fi

set -- serve \
    --host 0.0.0.0 \
    --port "$PORT" \
    --public-url "$PUBLIC_URL" \
    --shops-file "$SHOPS_FILE" \
    --auth-file "$AUTH_FILE" \
    --data-dir "$DATA_DIR" \
    --log-level "${SHOPEE_MCP_LOG_LEVEL:-info}" \
    "$@"

if [ -n "${SHOPEE_MCP_CLIENT_IP_HEADER:-}" ]; then
    set -- "$@" --client-ip-header "$SHOPEE_MCP_CLIENT_IP_HEADER"
    # Comma or space separated CIDRs of the proxy that sets the header.
    for cidr in $(printf '%s' "${SHOPEE_MCP_TRUSTED_PROXIES:-}" | tr ',' ' '); do
        set -- "$@" --trusted-proxy "$cidr"
    done
fi

exec shopee-mcp-http "$@"
