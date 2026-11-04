"""Application factory.

Run with ``uvicorn --factory apiguard.app:create_app``. Settings are read from APIGUARD_*
environment variables; construction fails if the signing key is weak (see config.py).
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, IntegrityError, InterfaceError, OperationalError

from apiguard.config import Settings
from apiguard.db import build_engine, build_session_factory
from apiguard.deps import SessionDep
from apiguard.middleware import RequestIdMiddleware, SecurityHeadersMiddleware
from apiguard.ratelimit import RateLimiter
from apiguard.routers import auth, orgs, projects

logger = logging.getLogger("apiguard")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    app = FastAPI(
        title="apiguard",
        version="0.1.0",
        docs_url="/docs" if settings.enable_docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.enable_docs else None,
    )
    engine = build_engine(settings)
    session_factory = build_session_factory(engine)
    app.state.settings = settings
    app.state.engine = engine
    app.state.session_factory = session_factory
    app.state.rate_limiter = RateLimiter(session_factory, settings.rate_limit_window_seconds)

    # Starlette picks the handler for the most specific class in the exception's MRO.
    @app.exception_handler(IntegrityError)
    async def integrity_conflict(request: Request, exc: Exception) -> JSONResponse:
        # A uniqueness or foreign key race lost against a concurrent request.
        logger.warning("integrity error on %s %s: %s", request.method, request.url.path, exc)
        return JSONResponse(status_code=status.HTTP_409_CONFLICT, content={"detail": "conflict"})

    @app.exception_handler(OperationalError)
    @app.exception_handler(InterfaceError)
    async def database_unavailable(request: Request, exc: Exception) -> JSONResponse:
        # Connection failures, timeouts, deadlocks. Do not leak driver messages to clients.
        logger.error("database unavailable on %s %s: %s", request.method, request.url.path, exc)
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"detail": "service unavailable"},
        )

    @app.exception_handler(DBAPIError)
    async def database_error(request: Request, exc: Exception) -> JSONResponse:
        logger.error("database error on %s %s: %s", request.method, request.url.path, exc)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "internal error"},
        )

    @app.get("/healthz", tags=["health"])
    def healthz() -> dict[str, str]:
        """Liveness: the process is up. Does not touch the database."""
        return {"status": "ok"}

    @app.get("/readyz", tags=["health"])
    def readyz(session: SessionDep) -> dict[str, str]:
        """Readiness: the database answers a trivial query."""
        session.execute(text("SELECT 1"))
        return {"status": "ready"}

    app.include_router(auth.router)
    app.include_router(orgs.router)
    app.include_router(projects.router)

    # Middleware added last runs first: request id wraps everything, including CORS.
    if settings.cors_origin_list:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origin_list,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
            allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
            allow_credentials=False,
        )
    app.add_middleware(
        SecurityHeadersMiddleware,
        relax_csp_paths=("/docs",) if settings.enable_docs else (),
    )
    app.add_middleware(RequestIdMiddleware)
    return app
