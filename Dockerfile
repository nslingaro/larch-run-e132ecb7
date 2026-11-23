# syntax=docker/dockerfile:1
#
# Tenant Applications API container image (Azure App Service, Linux).
#
# - Base image pinned by digest. OPEN DECISION: the approved base-image source and
#   update policy; this is Docker Official Images python:3.12.16-slim-trixie.
# - Dependencies installed only from requirements.lock with hash checking.
# - Final stage: no compilers, no pip, no package caches; runs as an unprivileged user.
# - No secrets are baked in: the platform injects them as LARCH_* settings at runtime.

ARG PYTHON_IMAGE=docker.io/library/python:3.12.16-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

FROM ${PYTHON_IMAGE} AS build
ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1
RUN python -m venv /opt/venv
COPY requirements.lock /tmp/requirements.lock
RUN /opt/venv/bin/pip install --require-hashes --only-binary=:all: --no-deps -r /tmp/requirements.lock \
 && /opt/venv/bin/pip uninstall --yes pip \
 && find /opt/venv -name '__pycache__' -type d -prune -exec rm -rf {} +

FROM ${PYTHON_IMAGE} AS runtime
RUN python -m pip uninstall --yes pip \
 && rm -rf /root/.cache \
 && groupadd --system --gid 10001 larch \
 && useradd --system --uid 10001 --gid larch --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin larch \
 && mkdir -p /data/documents \
 && chown -R larch:larch /data \
 && chmod -R 0700 /data

COPY --from=build /opt/venv /opt/venv
# Application code stays root-owned and read-only to the service user.
COPY larch /app/larch

ENV PATH=/opt/venv/bin:$PATH \
    PYTHONPATH=/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    LARCH_ENVIRONMENT=production \
    LARCH_DOCUMENTS_DIR=/data/documents \
    FORWARDED_ALLOW_IPS=127.0.0.1

WORKDIR /app
USER 10001:10001
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health', timeout=4).status == 200 else 1)"]

# One worker per container: rate-limit counters live in the process (see larch/ratelimit.py).
CMD ["uvicorn", "larch.main:app", \
     "--host", "0.0.0.0", "--port", "8000", "--workers", "1", \
     "--proxy-headers", "--no-server-header", "--no-access-log", \
     "--limit-concurrency", "100", "--timeout-keep-alive", "5", "--timeout-graceful-shutdown", "20"]
