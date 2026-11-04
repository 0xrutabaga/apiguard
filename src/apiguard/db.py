"""Engine and session factory construction."""

from __future__ import annotations

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from apiguard.config import Settings


def build_engine(settings: Settings) -> Engine:
    return create_engine(
        settings.database_url,
        pool_pre_ping=True,
        connect_args={"connect_timeout": settings.database_connect_timeout_seconds},
    )


def build_session_factory(engine: Engine) -> sessionmaker[Session]:
    # expire_on_commit=False lets handlers serialise objects after committing.
    return sessionmaker(bind=engine, expire_on_commit=False)
