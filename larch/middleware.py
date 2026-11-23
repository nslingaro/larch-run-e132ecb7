"""Pure ASGI middleware.

RequestContextMiddleware
    Correlation ID (X-Request-ID), client address, per-address rate limit, response
    security headers, access log by route template, and a last-resort handler that turns
    any unhandled exception into a generic 500.
BodyLimitMiddleware
    Request size and content-type limits, enforced before the body is parsed.
"""

from __future__ import annotations

import json
import logging
import re
import time
import uuid
from typing import Any

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from larch.config import Settings
from larch.logs import client_ip_var, log, request_id_var, security_event
from larch.ratelimit import RateLimiter, RateLimitExceeded
from larch.uploads import MAX_DOCUMENT_BYTES

API_PREFIX = "/api/v1"
_REQUEST_ID = re.compile(r"^[A-Za-z0-9._\-]{1,64}$")
_UPLOAD_PATH = re.compile(rf"^{API_PREFIX}/applications/[^/]+/documents/?$")
MULTIPART_OVERHEAD_BYTES = 64 * 1024

API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
# Swagger UI and ReDoc load from a CDN and use inline script. Applies only to the docs
# pages, which are off outside development unless explicitly enabled.
DOCS_CSP = (
    "default-src 'none'; script-src 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
    "font-src https://fonts.gstatic.com; img-src data: https://fastapi.tiangolo.com https://cdn.redoc.ly; "
    "worker-src blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)
DOCS_PATHS = {"/docs", "/redoc", "/docs/oauth2-redirect"}

access_logger = logging.getLogger("larch.access")
error_logger = logging.getLogger("larch.error")


def _header(scope: Scope, name: bytes) -> str | None:
    for key, value in scope.get("headers", []):
        if key == name:
            return value.decode("latin-1")
    return None


async def send_json(send: Send, status: int, body: dict[str, Any], headers: list[tuple[bytes, bytes]] | None = None) -> None:
    payload = json.dumps(body).encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(payload)).encode()),
                *(headers or []),
            ],
        }
    )
    await send({"type": "http.response.body", "body": payload})


class RequestContextMiddleware:
    def __init__(self, app: ASGIApp, settings: Settings, limiter: RateLimiter) -> None:
        self.app = app
        self.limiter = limiter
        self.docs_enabled = settings.api_docs_enabled
        hsts = None
        if settings.hsts_max_age_seconds > 0:
            hsts = f"max-age={settings.hsts_max_age_seconds}"
            if settings.hsts_include_subdomains:
                hsts += "; includeSubDomains"
        self.static_headers: list[tuple[bytes, bytes]] = [
            (b"x-content-type-options", b"nosniff"),
            (b"referrer-policy", b"no-referrer"),
            (b"x-frame-options", b"DENY"),
            (b"cross-origin-opener-policy", b"same-origin"),
            (
                b"permissions-policy",
                b"accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), "
                b"microphone=(), payment=(), usb=(), interest-cohort=()",
            ),
        ]
        if hsts:
            self.static_headers.append((b"strict-transport-security", hsts.encode()))

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        supplied = _header(scope, b"x-request-id")
        request_id = supplied if supplied and _REQUEST_ID.fullmatch(supplied) else str(uuid.uuid4())
        client = scope.get("client")
        client_ip = client[0] if client else "unknown"
        rid_token = request_id_var.set(request_id)
        ip_token = client_ip_var.set(client_ip)
        path = scope.get("path", "")
        csp = DOCS_CSP if self.docs_enabled and path in DOCS_PATHS else API_CSP
        started = time.perf_counter()
        state = {"status": 500, "started": False}

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                state["started"] = True
                state["status"] = message["status"]
                headers = list(message.get("headers", []))
                present = {k.lower() for k, _ in headers}
                extra = [(k, v) for k, v in self.static_headers if k not in present]
                if b"content-security-policy" not in present:
                    extra.append((b"content-security-policy", csp.encode()))
                if b"cache-control" not in present:
                    extra.append((b"cache-control", b"no-store"))
                extra.append((b"x-request-id", request_id.encode()))
                message = {**message, "headers": headers + extra}
            await send(message)

        try:
            if path != f"{API_PREFIX}/health":
                self.limiter.hit("ip", client_ip)
            await self.app(scope, receive, send_wrapper)
        except RateLimitExceeded as exc:
            security_event("rate_limited", "denied", bucket=exc.bucket)
            await send_json(
                send_wrapper, 429, {"detail": "Too many requests"}, [(b"retry-after", str(exc.retry_after).encode())]
            )
        except Exception:
            error_logger.error(
                "unhandled exception",
                exc_info=True,
                extra={"fields": {"error_code": "internal_error", "route": self._route(scope)}},
            )
            if not state["started"]:
                await send_json(send_wrapper, 500, {"detail": "Internal server error", "request_id": request_id})
        finally:
            log(
                access_logger,
                logging.INFO,
                "request",
                method=scope.get("method"),
                route=self._route(scope),
                status=state["status"],
                duration_ms=round((time.perf_counter() - started) * 1000, 1),
                source_ip=client_ip,
            )
            request_id_var.reset(rid_token)
            client_ip_var.reset(ip_token)

    @staticmethod
    def _route(scope: Scope) -> str:
        route = scope.get("route")
        return getattr(route, "path", None) or "unmatched"


class BodyLimitMiddleware:
    """Rejects oversized or wrongly typed bodies before any parser sees them.

    The body is read here, up to the limit, and replayed to the application. Uploads are
    at most 10 MB, so buffering is bounded.
    """

    def __init__(self, app: ASGIApp, settings: Settings) -> None:
        self.app = app
        self.json_limit = settings.max_json_body_bytes
        self.upload_limit = MAX_DOCUMENT_BYTES + MULTIPART_OVERHEAD_BYTES

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] in ("GET", "HEAD", "OPTIONS"):
            await self.app(scope, receive, send)
            return

        is_upload = scope["method"] == "POST" and bool(_UPLOAD_PATH.match(scope.get("path", "")))
        limit = self.upload_limit if is_upload else self.json_limit
        content_type = (_header(scope, b"content-type") or "").split(";")[0].strip().lower()
        declared_length = _header(scope, b"content-length")

        if declared_length is not None:
            if not declared_length.isdigit():
                await send_json(send, 400, {"detail": "Invalid Content-Length"})
                return
            if int(declared_length) > limit:
                await send_json(send, 413, {"detail": "Request body too large"})
                return

        chunks: list[bytes] = []
        size = 0
        more = True
        while more:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            size += len(chunk)
            if size > limit:
                await send_json(send, 413, {"detail": "Request body too large"})
                return
            chunks.append(chunk)
            more = message.get("more_body", False)
        body = b"".join(chunks)

        if body:
            expected = "multipart/form-data" if is_upload else "application/json"
            if content_type != expected:
                await send_json(send, 415, {"detail": "Unsupported media type"})
                return

        replayed = False

        async def replay() -> Message:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        await self.app(scope, replay, send)
