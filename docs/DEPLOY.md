# Deployment

Every remote deployment needs:

- a public **https** URL (`SHOPEE_MCP_PUBLIC_URL` / `--public-url`), without a path, for example `https://mcp.example.com`;
- persistent storage for `/data` (auth database, shops file, shop credential files);
- an operator passphrase (12+ characters) for `/admin/shops` and OAuth consent;
- Shopee partner credentials in the environment if you want to add shops from the browser.

Run **one instance** per data directory. Admin sessions and pending shop authorizations are kept in memory; credential refreshes are coordinated with file locks on the shared disk.

## Container layout

The image (`Dockerfile`) installs the package, creates an unprivileged user `app` (uid 10001) and uses `docker/entrypoint.sh`:

1. Started as root, it creates `/data`, gives it to `app` with mode `0700` and re-executes itself as `app` (volumes are often mounted root-owned). Started with `--user 10001`, it skips this step; `/data` must then already be writable by that user.
2. Creates `/data/shops` (`0700`) and an empty `/data/shops.json` (`0600`) if missing.
3. Sets the operator passphrase from `SHOPEE_MCP_ADMIN_PASSPHRASE` if none is stored yet. To replace a stored passphrase, set `SHOPEE_MCP_ADMIN_PASSPHRASE_RESET=true` for one boot.
4. Runs `shopee-mcp-http serve --host 0.0.0.0 --port $PORT ...`. The public URL falls back to a platform-provided URL (`RENDER_EXTERNAL_URL` or `https://$RAILWAY_PUBLIC_DOMAIN`) when `SHOPEE_MCP_PUBLIC_URL` is empty.

| Variable | Required | Purpose |
| --- | --- | --- |
| `SHOPEE_MCP_PUBLIC_URL` | yes (or platform fallback) | Public https base URL |
| `SHOPEE_MCP_ADMIN_PASSPHRASE` | recommended | Operator passphrase, applied on first boot |
| `SHOPEE_MCP_ADMIN_PASSPHRASE_RESET` | no | `true` replaces the stored passphrase |
| `SHOPEE_PARTNER_ID`, `SHOPEE_PARTNER_KEY` | for onboarding | Live partner app |
| `SHOPEE_SANDBOX_PARTNER_ID`, `SHOPEE_SANDBOX_PARTNER_KEY` | no | Sandbox partner app (defaults to the live pair) |
| `SHOPEE_MCP_CLIENT_IP_HEADER`, `SHOPEE_MCP_TRUSTED_PROXIES` | no | Per-client throttling behind a known proxy, see [SECURITY.md](SECURITY.md#client-ip-and-throttling) |
| `PORT` | no | Listen port inside the container (default 8080) |
| `SHOPEE_MCP_DATA_DIR` | no | Data directory (default `/data`) |
| `SHOPEE_MCP_LOG_LEVEL` | no | `debug`, `info`, `warning`, `error` |

The container's health check calls `GET /healthz`.

## Hosted container platforms

Any platform that runs the Dockerfile and mounts a **persistent volume at `/data`** works. Set the variables above and expose `PORT`. Platforms whose free tier has no persistent disk (the filesystem is wiped on restart or sleep) are not supported: shop tokens, OAuth clients and sessions would be lost. A database storage backend for such platforms may be added later.

## Docker

```bash
git clone https://github.com/OWNER/shopee-seller-mcp && cd shopee-seller-mcp
docker build -t shopee-seller-mcp .
cp .env.example .env    # edit values; never commit .env
docker run -d --name shopee-mcp --restart unless-stopped \
  -p 127.0.0.1:8080:8080 -v shopee-mcp-data:/data --env-file .env shopee-seller-mcp
docker exec -it shopee-mcp shopee-mcp-http token create --auth-file /data/auth.db --label laptop
```

Terminate TLS in front of the container (nginx, Caddy, Traefik or a managed load balancer) for the public URL. Binding the published port to `127.0.0.1` keeps plain HTTP off the network.

## VPS with systemd and nginx

Install as a dedicated user, with state in an owner-only directory:

```bash
sudo useradd --system --home /var/lib/shopee-mcp --create-home --shell /usr/sbin/nologin shopee-mcp
sudo -u shopee-mcp python3.12 -m venv /var/lib/shopee-mcp/venv
sudo -u shopee-mcp /var/lib/shopee-mcp/venv/bin/pip install /path/to/shopee-seller-mcp
sudo -u shopee-mcp install -d -m 700 /var/lib/shopee-mcp/data /var/lib/shopee-mcp/data/shops
sudo -u shopee-mcp sh -c 'umask 077; [ -e /var/lib/shopee-mcp/data/shops.json ] || echo "{\"shops\": {}}" > /var/lib/shopee-mcp/data/shops.json'
sudo -u shopee-mcp /var/lib/shopee-mcp/venv/bin/shopee-mcp-http admin set-passphrase --auth-file /var/lib/shopee-mcp/data/auth.db
```

`/etc/systemd/system/shopee-mcp.service`:

```ini
[Unit]
Description=Shopee seller MCP (remote HTTP)
After=network-online.target
Wants=network-online.target

[Service]
User=shopee-mcp
Group=shopee-mcp
UMask=0077
# SHOPEE_PARTNER_ID=... and SHOPEE_PARTNER_KEY=... (root-owned, mode 0600)
EnvironmentFile=/etc/shopee-mcp/partner.env
ExecStart=/var/lib/shopee-mcp/venv/bin/shopee-mcp-http serve \
  --shops-file /var/lib/shopee-mcp/data/shops.json \
  --auth-file /var/lib/shopee-mcp/data/auth.db \
  --data-dir /var/lib/shopee-mcp/data \
  --public-url https://mcp.example.com \
  --port 8091 --client-ip-header X-Real-IP
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/shopee-mcp

[Install]
WantedBy=multi-user.target
```

The server listens on `127.0.0.1:8091` (the default `--host`). nginx terminates TLS:

```nginx
# http {} context, only if Cloudflare proxies the site: restore the real client
# address from CF-Connecting-IP, trusting it ONLY from Cloudflare's published ranges.
# One line per range from https://www.cloudflare.com/ips/ (placeholder below).
set_real_ip_from 203.0.113.0/24;
real_ip_header CF-Connecting-IP;
real_ip_recursive off;

server {
    listen 443 ssl;
    server_name mcp.example.com;
    # ssl_certificate ...; ssl_certificate_key ...;  (Cloudflare origin certificate or Let's Encrypt)

    location / {
        proxy_pass http://127.0.0.1:8091;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 120s;   # get_ads_summary stops itself after about 80 s
        proxy_buffering off;
        access_log off;            # or a log format without $request_uri / $args
    }
    location = /callback {
        proxy_pass http://127.0.0.1:8091;
        proxy_set_header X-Real-IP $remote_addr;
        access_log off;            # the query string carries the Shopee authorization code
    }
    location ^~ /invite/ {
        proxy_pass http://127.0.0.1:8091;
        proxy_set_header X-Real-IP $remote_addr;
        access_log off;            # the path carries the invite token
    }
}
```

- With Cloudflare in front, use **Full (strict)** TLS with a Cloudflare origin certificate, and restrict the origin firewall to Cloudflare's ranges.
- Without Cloudflare, drop the `set_real_ip_from` and `real_ip_header` lines.
- Never derive the throttle key from `X-Forwarded-For` set by untrusted hops; nginx's `$remote_addr` (after `real_ip`) is what the server receives in `X-Real-IP`.

## Local stdio

For a single machine, the stdio server needs no network exposure:

```bash
pip install .
shopee-mcp --shops-file /secure/shops.json --check   # validate offline
```

Client config (Claude Desktop, Cursor and others):

```json
{"mcpServers": {"shopee": {"command": "shopee-mcp", "args": ["--shops-file", "/secure/shops.json"]}}}
```

The legacy single-shop mode (`shopee-mcp --env-file /secure/store-a.env`) remains available; it is the only mode where write tools can be enabled, with an explicit `--allow-write` allowlist.

## Shops file and CLI authorization

The shops file maps aliases to owner-only credential files:

```json
{"shops": {"store-a": "/secure/shops/store-a.env", "store-b": "/secure/shops/store-b.env"}}
```

The shops file and every env file must be regular files owned by the server user with mode `0600`, not symlinks, in directories that other users cannot write. Paths must be absolute and normalized. Duplicate paths or two aliases for the same shop are rejected. `/admin/shops` edits this file atomically and only deletes env files that it created in `<data-dir>/shops/`.

To authorize a shop from a terminal instead of the browser:

```bash
shopee-auth --env-file /secure/shops/store-a.env init-production --partner-id 123456 \
  --redirect-url https://mcp.example.com/callback          # prompts for the partner key
shopee-auth --env-file /secure/shops/store-a.env authorization-url
# open the URL, approve, then paste the full callback URL:
shopee-auth --env-file /secure/shops/store-a.env exchange-code --callback-url-stdin
```

Add the alias to the shops file and restart `serve` (or use `/admin/shops`, which reloads automatically). `/callback` shows a static page for this flow and does not process the code.

### Main account authorization

A seller's *main account* can authorize several shops in one approval. Shopee then redirects with `code` and `main_account_id` (no `shop_id`), and `token/get` with `main_account_id` returns `shop_id_list` plus one access/refresh token pair that is identical for every shop in that authorization. Shopee refreshes tokens per `shop_id`, so the server immediately calls `access_token/get` once for each selected shop, one shop at a time, and stores the resulting independent token pair in that shop's own env file. Later refreshes of one shop never touch another shop's file. A shop whose first refresh fails is skipped and reported, and the other shops are still added.

- Browser: start *Add shop* as usual. After the main-account approval, `/admin/shops` shows a picker (shop ID, name when available, alias). Nothing is written until you submit it. The picker is bound to your admin session, works once and expires after 15 minutes.
- Terminal: after `authorization-url`, paste the callback into

  ```bash
  shopee-auth --env-file /secure/partner.env exchange-main-account --callback-url-stdin \
    --output-dir /secure/shops
  ```

  This writes `shop-<shop_id>.env` for each authorized shop and prints the shop IDs (never tokens). Add the aliases you want to the shops file.

Merchant-only authorizations (`merchant_id_list` without shops) are not supported.

### Invite links

Use an invite when the person who can approve access (a main account or shop account holder) is not the operator. In `/admin/shops` > *Invite links*, choose the environment (live by default), the lifetime (`1h`, `24h`, `72h` or `7d`) and an optional label, then send the URL that is shown once.

- The invitee opens `/invite/<token>`, clicks *Continue to Shopee*, signs in (main account via *Switch to Sub Account*, or a shop account) and approves. Each click creates a fresh, signed Shopee link, so the 5-minute signature limit does not matter.
- The approval must be completed in the same browser within 15 minutes. Shops are added with automatic aliases (shop-name slug, else `shop-<shop_id>`); already connected shops are skipped. Rename aliases afterwards in the shop list.
- The invite becomes used once at least one shop is saved. If every shop fails, the link stays usable until it expires. Active links can be revoked; at most 20 can be active.
- Invites are stored in `<data-dir>/invites.json` (`0600`) as SHA-256 hashes plus label, environment and timestamps, so they survive restarts.

## Operator commands

```bash
shopee-mcp-http admin set-passphrase --auth-file /data/auth.db [--if-unset]
shopee-mcp-http token create --auth-file /data/auth.db --label laptop   # printed once
shopee-mcp-http token list   --auth-file /data/auth.db
shopee-mcp-http token revoke --auth-file /data/auth.db <id>
shopee-mcp-http oauth list   --auth-file /data/auth.db
shopee-mcp-http oauth revoke --auth-file /data/auth.db <client_id>
```

In a container, prefix with `docker exec -it shopee-mcp` (or use the platform shell). Run them as the server user so file ownership stays correct; the container entrypoint already does this for the server itself.

## Endpoints

| Path | Purpose |
| --- | --- |
| `POST /mcp` | MCP Streamable HTTP (stateless JSON; `GET` returns 405) |
| `GET /.well-known/oauth-protected-resource[/mcp]` | RFC 9728 resource metadata |
| `GET /.well-known/oauth-authorization-server` | RFC 8414 metadata |
| `POST /register` | RFC 7591 dynamic registration (public clients, global rate cap) |
| `GET/POST /authorize` | Consent page; PKCE S256 required |
| `POST /token` | `authorization_code` and `refresh_token` grants |
| `POST /revoke` | RFC 7009 revocation |
| `GET/POST /admin/shops` | Operator shop onboarding (passphrase, CSRF, throttling) |
| `GET/POST /invite/<token>` | Invite landing page for a remote seller (throttled; single use) |
| `GET /callback` | Completes an invite or "Add shop" flow; otherwise a static page for the CLI flow |
| `GET /healthz` | Liveness check |
