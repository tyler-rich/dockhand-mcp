# syntax=docker/dockerfile:1
# dockhand-mcp — hardened image (plan S-08). Both stages use the latest official python:<minor>-slim,
# pinned by digest; distroless is not used because its Python lags the latest CPython series (D-013).
# Built for linux/amd64 and linux/arm64 by .github/workflows/release.yml.

# ---- uv: the resolver binary, as a named stage so Dependabot's docker ecosystem updates it --------
# (Dependabot reads FROM lines, including `FROM … AS name`; it does not read `COPY --from=<image>`.)
FROM ghcr.io/astral-sh/uv:0.13.6@sha256:af22a52f5eafef3d78e551599d405c02df61919d18028f0cea8eda93bc9986d0 AS uv

# ---- build: resolve the locked dependencies into a virtualenv ------------------------------------
FROM python:3.15-slim@sha256:94d3426f1def7db4a106a232ac121bfd975393e5dfd40a619b955fae45fe7913 AS build

COPY --from=uv /uv /usr/local/bin/uv

# PYYAML_FORCE_LIBYAML=0: PyYAML is built from its sdist on 3.15 (no cp315 wheel); skip its libyaml
# extension, since the app uses only the pure-Python safe_load/safe_dump. Remove it together with the
# build-constraint pins in pyproject.toml once PyYAML ships cp315 wheels.
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PYYAML_FORCE_LIBYAML=0 \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/app/.venv

WORKDIR /src

# Dependencies first, so source changes reuse this layer.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY README.md LICENSE NOTICE ./
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable

# ---- runtime: only the virtualenv (which holds the app) and the licence files ---------------------
FROM python:3.15-slim@sha256:94d3426f1def7db4a106a232ac121bfd975393e5dfd40a619b955fae45fe7913

# Set by the release workflow; the defaults mark a local build.
ARG VERSION=0.0.0-dev
ARG REVISION=unknown
ARG SOURCE=https://github.com/tyler-rich/dockhand-mcp

LABEL org.opencontainers.image.title="dockhand-mcp" \
      org.opencontainers.image.description="Security-first MCP server for the DockHand REST API" \
      org.opencontainers.image.source="${SOURCE}" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.licenses="Apache-2.0"

RUN groupadd --system --gid 10001 dockhand-mcp \
 && useradd --system --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent \
      --shell /usr/sbin/nologin dockhand-mcp  && install -d -m 0755 /licenses

COPY --from=build /app/.venv /app/.venv
COPY --chmod=0444 LICENSE NOTICE /licenses/

ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
USER 10001:10001
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys;sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz',timeout=3).status==200 else 1)"]

ENTRYPOINT ["dockhand-mcp"]
CMD ["serve"]
