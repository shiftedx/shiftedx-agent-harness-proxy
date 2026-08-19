# syntax=docker/dockerfile:1.7
ARG PYTHON_IMAGE=python:3.11.16-slim-bookworm@sha256:2e32f7d302adc1c37428355c1e646897c0c53f4fd60b6a551245fb90ee129f91
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.10.2@sha256:94a23af2d50e97b87b522d3cea24aaf8a1faedec1344c952767434f69585cbf9

FROM ${UV_IMAGE} AS uv
FROM ${PYTHON_IMAGE} AS builder
WORKDIR /build
COPY --from=uv /uv /uvx /bin/
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
# `uv lock --check` fails before installation if pyproject.toml and uv.lock drift.
# The frozen export proves the locked runtime set has package hashes; uv consumes
# that same checked lock when it installs the non-editable application wheel.
RUN uv lock --check && \
    uv export --frozen --no-dev --no-emit-project --format requirements-txt --output-file /tmp/runtime-requirements.txt && \
    grep --quiet -- '--hash=sha256:' /tmp/runtime-requirements.txt && \
    UV_LINK_MODE=copy uv sync --locked --no-dev --no-editable

FROM ${PYTHON_IMAGE} AS runtime
ARG VERSION=0.1.0
LABEL org.opencontainers.image.title="Shiftedx Agent Harness Proxy" \
      org.opencontainers.image.description="Bounded execution-policy middleware for OpenAI-compatible agents" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}"

RUN groupadd --gid 10001 sxproxy && \
    useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin sxproxy && \
    rm -rf \
      /usr/local/lib/python3.11/site-packages/pip* \
      /usr/local/lib/python3.11/site-packages/setuptools* \
      /usr/local/lib/python3.11/site-packages/wheel* \
      /usr/local/lib/python3.11/site-packages/pkg_resources* \
      /usr/local/bin/pip* \
      /usr/local/bin/wheel
COPY --from=builder --chown=10001:10001 /build/.venv /opt/venv

ENV VIRTUAL_ENV="/opt/venv" \
    PATH="/opt/venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME="/nonexistent"
EXPOSE 8090
USER 10001:10001
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8090/healthz', timeout=2).read()"]
ENTRYPOINT ["python", "-m", "shiftedx_harness_proxy.main"]
