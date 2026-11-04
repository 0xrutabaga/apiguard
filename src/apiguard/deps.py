"""FastAPI dependencies: settings, database session, request context, current user."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session, sessionmaker

from apiguard.audit import RequestContext
from apiguard.config import Settings
from apiguard.models import User
from apiguard.ratelimit import RateLimiter
from apiguard.tokens import InvalidAccessToken, decode_access_token

_bearer = HTTPBearer(auto_error=False)

UNAUTHENTICATED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="not authenticated",
    headers={"WWW-Authenticate": "Bearer"},
)


def get_settings(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


def get_session_factory(request: Request) -> sessionmaker[Session]:
    factory: sessionmaker[Session] = request.app.state.session_factory
    return factory


def get_rate_limiter(request: Request) -> RateLimiter:
    limiter: RateLimiter = request.app.state.rate_limiter
    return limiter


def get_session(
    factory: Annotated[sessionmaker[Session], Depends(get_session_factory)],
) -> Iterator[Session]:
    """One session per request. Handlers commit explicitly; anything uncommitted rolls back."""
    with factory() as session:
        yield session


def get_request_context(request: Request) -> RequestContext:
    request_id = getattr(request.state, "request_id", "") or ""
    # request.client is set by the ASGI server. Behind a reverse proxy, run uvicorn with
    # --proxy-headers and --forwarded-allow-ips so this is the real client address;
    # X-Forwarded-For is never read directly here because clients can forge it.
    client_ip = request.client.host if request.client else "unknown"
    return RequestContext(request_id=request_id, client_ip=client_ip)


def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    settings: Annotated[Settings, Depends(get_settings)],
    session: Annotated[Session, Depends(get_session)],
) -> User:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise UNAUTHENTICATED
    try:
        claims = decode_access_token(settings, credentials.credentials)
    except InvalidAccessToken:
        raise UNAUTHENTICATED from None
    user = session.get(User, claims.user_id)
    if user is None:
        raise UNAUTHENTICATED
    return user


SettingsDep = Annotated[Settings, Depends(get_settings)]
SessionDep = Annotated[Session, Depends(get_session)]
SessionFactoryDep = Annotated[sessionmaker[Session], Depends(get_session_factory)]
ContextDep = Annotated[RequestContext, Depends(get_request_context)]
CurrentUser = Annotated[User, Depends(get_current_user)]
RateLimiterDep = Annotated[RateLimiter, Depends(get_rate_limiter)]
