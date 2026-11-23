"""Application factory."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import APIRouter, FastAPI
from fastapi.responses import JSONResponse
from sqlalchemy import text
from starlette.formparsers import MultiPartParser
from starlette.middleware.cors import CORSMiddleware

from larch.config import Settings
from larch.db import create_schema
from larch.deps import ServicesDep
from larch.errors import install_error_handlers
from larch.logs import configure_logging, security_event
from larch.middleware import API_PREFIX, MULTIPART_OVERHEAD_BYTES, BodyLimitMiddleware, RequestContextMiddleware
from larch.routers import admin, applications, auth, listings
from larch.schemas import Health
from larch.services import Services, build_services
from larch.uploads import MAX_DOCUMENT_BYTES

logger = logging.getLogger("larch.startup")

# Keep uploads in memory while they are parsed, so plaintext documents are never spooled
# to a temporary file on disk. The body is capped at this size by BodyLimitMiddleware.
MultiPartParser.spool_max_size = MAX_DOCUMENT_BYTES + MULTIPART_OVERHEAD_BYTES

health_router = APIRouter(tags=["health"])


@health_router.get("/health", response_model=Health, responses={503: {"model": Health}})
def health(services: ServicesDep) -> Health | JSONResponse:
    # Minimal on purpose: no versions, hosts or error details.
    try:
        with services.engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except Exception:
        logger.warning("health check: database unreachable", extra={"fields": {"error_code": "database_unavailable"}})
        return JSONResponse(status_code=503, content={"status": "unavailable"})
    return Health(status="ok")


def create_app(settings: Settings | None = None, services: Services | None = None) -> FastAPI:
    settings = settings or Settings()
    configure_logging(settings.environment.value)
    services = services or build_services(settings)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        create_schema(services.engine)
        services.store.ensure_root()
        security_event("service_started", "success", reason=f"api_docs={'on' if settings.api_docs_enabled else 'off'}")
        yield
        services.engine.dispose()

    docs = settings.api_docs_enabled
    app = FastAPI(
        title="Larch Lettings Tenant Applications API",
        version="1.0.0",
        lifespan=lifespan,
        docs_url="/docs" if docs else None,
        redoc_url="/redoc" if docs else None,
        openapi_url="/openapi.json" if docs else None,
        debug=False,
    )
    app.state.services = services
    install_error_handlers(app)

    api = APIRouter(prefix=API_PREFIX)
    api.include_router(health_router)
    api.include_router(auth.router)
    api.include_router(admin.router)
    api.include_router(listings.router)
    api.include_router(applications.router)
    app.include_router(api)

    # Last added runs first: CORS, then request context, then body limits.
    app.add_middleware(BodyLimitMiddleware, settings=settings)
    app.add_middleware(RequestContextMiddleware, settings=settings, limiter=services.limiter)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=False,  # bearer tokens travel in the Authorization header, not cookies
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
        expose_headers=["Content-Disposition", "Retry-After", "X-Request-ID"],
        max_age=600,
    )
    return app
