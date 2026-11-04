# Shopee seller MCP server - remote HTTP mode (read-only, multi-shop).
# State (auth database, shops file, shop credential files) lives in /data:
# mount a persistent volume there.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    SHOPEE_MCP_DATA_DIR=/data

# gosu drops root privileges after the entrypoint fixes ownership of a
# root-owned volume mount (common on Render/Railway/Docker volumes).
RUN apt-get update \
    && apt-get install -y --no-install-recommends gosu \
    && rm -rf /var/lib/apt/lists/* \
    && gosu nobody true \
    && groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY public_catalog ./public_catalog
RUN pip install . && rm -rf /app/src /app/public_catalog

COPY docker/entrypoint.sh /usr/local/bin/shopee-mcp-entrypoint
RUN chmod 0755 /usr/local/bin/shopee-mcp-entrypoint \
    && install -d -o app -g app -m 0700 /data

VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ.get('PORT', '8080'), timeout=4)" || exit 1

# Starts as root only to prepare /data, then re-executes itself as the
# unprivileged "app" user. Run with --user 10001 to skip the root step.
ENTRYPOINT ["/usr/local/bin/shopee-mcp-entrypoint"]
