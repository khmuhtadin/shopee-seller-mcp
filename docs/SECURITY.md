# Security model

## Scope

- Multi-shop (`--shops-file`) and remote HTTP modes are **read-only**: only catalog endpoints whose effect is `read` are exposed, and `--allow-write` is rejected. Writes exist only in the legacy single-shop stdio mode behind an explicit allowlist.
- Each shop is an explicit alias. Unknown or missing aliases fail closed; there is no default shop, prefix matching or fallback. Tool results never contain credential paths, partner keys or tokens; Shopee URLs and secrets are redacted from responses.

## Authentication on `/mcp`

Every request needs `Authorization: Bearer ...` and is rejected with `401` (and an RFC 9728 `WWW-Authenticate` challenge) before reaching MCP otherwise.

1. **Static bearer tokens** (`smcp_...`), created with `shopee-mcp-http token create`. Revocable; `last_used_at` is tracked.
2. **OAuth 2.1** access tokens issued by this server, bound to this server's resource URL (audience check).

All auth state is one owner-only SQLite file (WAL; database and `-wal`/`-shm` files mode `0600`, directory not writable by others). Only SHA-256 hashes of tokens and codes are stored; the passphrase is a salted scrypt hash.

### OAuth details

- RFC 8414 / RFC 9728 metadata; `--public-url` is the only source of the issuer and resource URL. Forwarded host/proto headers are never trusted.
- Dynamic client registration (RFC 7591) creates public clients only (PKCE S256 required). Redirect URIs must exactly match one registered at `https://chatgpt.com` / `https://chat.openai.com` (paths under `/connector_platform_oauth_redirect`, `/aip/`, `/connector/`), `https://claude.ai` / `https://claude.com` (paths under `/api/mcp/auth_callback`), or loopback `http://localhost` / `http://127.0.0.1`. Registration has a global rate cap.
- Consent requires the operator passphrase. Each consent form token is single use and bound to a `__Host-` cookie.
- Lifetimes: access tokens 24 h, refresh tokens 90 days (renewed on refresh), codes 5 min. Refresh tokens rotate; the previous one is accepted once more within 2 minutes (lost responses). Any other reuse, or replay of a used code, revokes the whole grant.
- Restarts keep all clients and tokens.

## Operator passphrase, `/admin/shops` and throttling

- `/authorize` (consent) and `/admin/shops` (shop onboarding) share the same passphrase, the same failure throttle and the same concurrency cap: failures are counted before verification; 5 failures from one client or 20 in total lock the forms for 15 minutes; at most two scrypt verifications run at once.
- Signing in to `/admin/shops` creates an in-memory admin session (1 hour) in an `HttpOnly`, `Secure`, `SameSite=Lax` `__Host-` cookie. `Lax` is required because Shopee's redirect to `/callback` is a cross-site top-level navigation. Every state-changing admin action also needs a single-use form token bound to the session.
- Admin pages never show or accept partner keys or Shopee tokens. Partner credentials come only from the server environment.

### Shop authorization flow

1. *Add shop* validates the alias and environment, then creates a random 256-bit `state`, valid for 15 minutes, single use and bound to the admin session. The browser is redirected to Shopee's authorization page with `redirect_uri=<public-url>/callback`.
2. `/callback` consumes the `state` on first presentation, whether or not the rest succeeds. Without a pending `state`, or from a different or expired admin session, **nothing is exchanged** and nothing is written.
3. The code is exchanged with the CLI's exchange logic against a new `0600` env file in `<data-dir>/shops/` (`0700`). The new service is built and validated first (duplicate shop identities are rejected), then the shops JSON is replaced atomically (temp file, `fsync`, rename), then the running MCP service is swapped. In-flight requests finish on the previous registry, which is closed later.
4. Any failure removes the new env file and leaves the configuration unchanged.

Authorization codes, `state` values, tokens and query strings are never logged. Keep reverse-proxy access logs for `/callback` disabled or free of query strings.

## Network exposure

- `serve` binds `127.0.0.1` by default; put a TLS reverse proxy in front.
- `--host` with a non-loopback address (containers) requires an https `--public-url`.
- uvicorn proxy-header handling and access logs are disabled. Responses carry `nosniff`, `no-referrer`, `X-Frame-Options: DENY`; HTML pages add a strict CSP and `no-store`.

### Client IP and throttling

The per-client part of the passphrase throttle needs the real client address.

- `--client-ip-header <name>` is honoured only when the direct peer is loopback or inside a `--trusted-proxy` CIDR. On a non-loopback `--host`, `--client-ip-header` requires `--trusted-proxy`.
- For list headers such as `X-Forwarded-For`, the right-most address that is not a trusted proxy is used, so values a client prepends cannot choose the throttle key.
- Behind nginx and Cloudflare, restore the client address with `real_ip_header CF-Connecting-IP` trusted only from Cloudflare's ranges, and pass `$remote_addr` as `X-Real-IP` (see [DEPLOY.md](DEPLOY.md#vps-with-systemd-and-nginx)).
- On platforms where the proxy addresses are unknown (Render, Railway), leave the header unset. All clients then share the proxy's throttle key: an attacker can temporarily lock the forms (15 minutes) but gains no extra guesses, and the global limit still applies. Use a long random passphrase.

## Files and secrets

| Data | Location | Protection |
| --- | --- | --- |
| Shop tokens and partner key copy | `<data-dir>/shops/<alias>.env` | `0600`, directory `0700`, owner checks, no symlinks |
| Shops map | `shops.json` | `0600`, aliases and paths only |
| Auth database | `auth.db` | `0600`, hashes only |
| Partner credentials | server environment | never sent to browsers or clients |

Files are access-controlled but **not encrypted**. Protect the host, volume snapshots and backups. Rotate the partner key in the Shopee console if a disk or backup is exposed, then re-add shops.

## Client-side tokens

`shopee-mcp-http connect` and `scripts/install-agent.sh` reference the bearer token through an environment variable, except where a client cannot (Claude Desktop) or when `--inline-token` is given. Existing config files are backed up before changes, and unrelated servers are preserved. Revoke a leaked token with `shopee-mcp-http token revoke`.

## Reporting issues

Please report vulnerabilities privately through the repository's security advisory feature rather than a public issue.
