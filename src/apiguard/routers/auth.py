"""Registration, login, token refresh and logout."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from apiguard import passwords, refresh
from apiguard.audit import EventType, RequestContext, record_event
from apiguard.deps import (
    ContextDep,
    CurrentUser,
    RateLimiterDep,
    SessionDep,
    SessionFactoryDep,
    SettingsDep,
)
from apiguard.models import User
from apiguard.ratelimit import Limit, RateLimiter, RateLimitExceeded, account_key, ip_key
from apiguard.schemas import LoginRequest, RefreshRequest, RegisterRequest, TokenPair, UserOut
from apiguard.tokens import issue_access_token

router = APIRouter(prefix="/auth", tags=["auth"])

INVALID_CREDENTIALS = "invalid email or password"
INVALID_REFRESH = "invalid refresh token"


def _too_many(retry_after: int) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail="too many requests",
        headers={"Retry-After": str(retry_after)},
    )


def apply_limits(
    limiter: RateLimiter,
    limits: list[Limit],
    factory: SessionFactoryDep,
    ctx: RequestContext,
    endpoint: str,
) -> None:
    try:
        limiter.hit_all(limits)
    except RateLimitExceeded as exc:
        if exc.first_in_window:
            kind = "ip" if ":ip:" in exc.key else "account"
            record_event(
                factory,
                EventType.RATE_LIMITED,
                ctx,
                detail={"endpoint": endpoint, "limit": kind, "retry_after": exc.retry_after},
            )
        raise _too_many(exc.retry_after) from None


def normalise_email(email: str) -> str:
    return email.strip().lower()


@router.post("/register", status_code=status.HTTP_201_CREATED, response_model=UserOut)
def register(
    body: RegisterRequest,
    session: SessionDep,
    factory: SessionFactoryDep,
    settings: SettingsDep,
    limiter: RateLimiterDep,
    ctx: ContextDep,
) -> User:
    apply_limits(
        limiter,
        [Limit(ip_key("register", ctx.client_ip), settings.register_limit_per_ip)],
        factory,
        ctx,
        "register",
    )
    user = User(
        email=normalise_email(str(body.email)),
        display_name=body.display_name,
        password_hash=passwords.hash_password(body.password),
    )
    session.add(user)
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        # Known limitation: without an email verification flow, registration has to say
        # that the address is taken. It is rate limited per IP; login does not leak this.
        raise HTTPException(status.HTTP_409_CONFLICT, "email already registered") from None
    return user


@router.post("/login", response_model=TokenPair)
def login(
    body: LoginRequest,
    session: SessionDep,
    factory: SessionFactoryDep,
    settings: SettingsDep,
    limiter: RateLimiterDep,
    ctx: ContextDep,
) -> TokenPair:
    email = normalise_email(body.email)
    apply_limits(
        limiter,
        [
            Limit(ip_key("login", ctx.client_ip), settings.login_limit_per_ip),
            Limit(account_key("login", email), settings.login_limit_per_account),
        ],
        factory,
        ctx,
        "login",
    )

    user = session.execute(select(User).where(User.email == email)).scalar_one_or_none()
    # One Argon2 verification happens whether or not the account exists.
    ok = passwords.verify_login_password(user.password_hash if user else None, body.password)
    if user is None or not ok:
        record_event(
            factory,
            EventType.LOGIN_FAILED,
            ctx,
            actor_user_id=user.id if user else None,
            detail={"reason": "bad_credentials"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=INVALID_CREDENTIALS,
            headers={"WWW-Authenticate": "Bearer"},
        )

    if passwords.needs_rehash(user.password_hash):
        user.password_hash = passwords.hash_password(body.password)
    issued = refresh.start_family(session, settings, user.id)
    session.commit()
    record_event(
        factory,
        EventType.LOGIN_SUCCEEDED,
        ctx,
        actor_user_id=user.id,
        detail={"family_id": str(issued.family_id)},
    )
    return TokenPair(
        access_token=issue_access_token(settings, user.id),
        refresh_token=issued.token,
        expires_in=settings.access_token_ttl_seconds,
    )


@router.post("/refresh", response_model=TokenPair)
def refresh_tokens(
    body: RefreshRequest,
    session: SessionDep,
    factory: SessionFactoryDep,
    settings: SettingsDep,
    limiter: RateLimiterDep,
    ctx: ContextDep,
) -> TokenPair:
    apply_limits(
        limiter,
        [Limit(ip_key("refresh", ctx.client_ip), settings.refresh_limit_per_ip)],
        factory,
        ctx,
        "refresh",
    )
    existing = refresh.family_of(session, body.refresh_token)
    if existing is not None:
        apply_limits(
            limiter,
            [Limit(f"refresh:user:{existing.user_id}", settings.refresh_limit_per_account)],
            factory,
            ctx,
            "refresh",
        )
    session.rollback()  # end the read transaction before taking the row lock in rotate()

    try:
        issued = refresh.rotate(session, settings, body.refresh_token)
    except refresh.RefreshRejected as exc:
        # Commit first: on reuse, rotate() revoked the family in this session.
        session.commit()
        if exc.reason is refresh.RefreshFailure.REUSED:
            record_event(
                factory,
                EventType.REFRESH_TOKEN_REUSED,
                ctx,
                actor_user_id=exc.user_id,
                detail={"family_id": str(exc.family_id), "action": "family_revoked"},
            )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, INVALID_REFRESH) from None
    session.commit()
    record_event(
        factory,
        EventType.REFRESH_ROTATED,
        ctx,
        actor_user_id=issued.user_id,
        detail={"family_id": str(issued.family_id)},
    )
    return TokenPair(
        access_token=issue_access_token(settings, issued.user_id),
        refresh_token=issued.token,
        expires_in=settings.access_token_ttl_seconds,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    body: RefreshRequest,
    user: CurrentUser,
    session: SessionDep,
    factory: SessionFactoryDep,
    ctx: ContextDep,
) -> None:
    """Revoke the refresh token family. Requires the access token of the same user."""
    row = refresh.family_of(session, body.refresh_token)
    if row is None or row.user_id != user.id:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, INVALID_REFRESH)
    revoked = refresh.revoke_family(session, row.family_id)
    session.commit()
    record_event(
        factory,
        EventType.LOGOUT,
        ctx,
        actor_user_id=user.id,
        detail={"family_id": str(row.family_id), "revoked": revoked},
    )
