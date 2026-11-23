"""Exception handlers.

Errors keep the contract's ``{"detail": ...}`` body. Responses never carry stack traces,
SQL, file paths, tokens or the submitted values themselves: FastAPI's 422 body is kept,
minus the ``input`` and ``url`` members, which echo what was sent (a password, say).
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import OperationalError, SQLAlchemyError

from larch.logs import log, request_id_var, security_event
from larch.ratelimit import RateLimitExceeded
from larch.security.document_crypto import DecryptionError
from larch.storage import StorageError

logger = logging.getLogger("larch.error")
_PRIMITIVES = (str, int, float, bool, type(None))


def _route(request: Request) -> str | None:
    return getattr(request.scope.get("route"), "path", None)


def safe_validation_errors(errors: Any) -> list[dict[str, Any]]:
    cleaned = []
    for error in errors:
        item: dict[str, Any] = {
            "type": error.get("type"),
            "loc": list(error.get("loc", ())),
            "msg": error.get("msg"),
        }
        ctx = error.get("ctx")
        if isinstance(ctx, dict):
            item["ctx"] = {k: (v if isinstance(v, _PRIMITIVES) else str(v)) for k, v in ctx.items()}
        cleaned.append(item)
    return cleaned


def _server_error(request: Request, code: str, status: int = 500, detail: str = "Internal server error") -> JSONResponse:
    logger.error(
        "request failed",
        exc_info=True,
        extra={"fields": {"error_code": code, "route": _route(request)}},
    )
    return JSONResponse(status_code=status, content={"detail": detail, "request_id": request_id_var.get()})


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        log(logger, logging.INFO, "request validation failed", error_code="validation_error", route=_route(request))
        return JSONResponse(status_code=422, content={"detail": safe_validation_errors(exc.errors())})

    @app.exception_handler(RateLimitExceeded)
    async def _rate_limited(request: Request, exc: RateLimitExceeded) -> JSONResponse:
        security_event("rate_limited", "denied", bucket=exc.bucket, route=_route(request))
        return JSONResponse(
            status_code=429,
            content={"detail": "Too many requests"},
            headers={"Retry-After": str(exc.retry_after)},
        )

    @app.exception_handler(StorageError)
    async def _storage(request: Request, exc: StorageError) -> JSONResponse:
        return _server_error(request, "storage_error")

    @app.exception_handler(DecryptionError)
    async def _decryption(request: Request, exc: DecryptionError) -> JSONResponse:
        return _server_error(request, "document_integrity_error")

    @app.exception_handler(OperationalError)
    async def _db_unavailable(request: Request, exc: OperationalError) -> JSONResponse:
        return _server_error(request, "database_unavailable", 503, "Service temporarily unavailable")

    @app.exception_handler(SQLAlchemyError)
    async def _db_error(request: Request, exc: SQLAlchemyError) -> JSONResponse:
        return _server_error(request, "database_error")
