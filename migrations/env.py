"""Alembic environment. The URL comes from the Alembic config (tests) or APIGUARD_DATABASE_URL."""

from __future__ import annotations

import os

from alembic import context
from sqlalchemy import create_engine, pool

from apiguard.models import Base

config = context.config
target_metadata = Base.metadata


def _database_url() -> str:
    url = config.get_main_option("sqlalchemy.url") or os.environ.get("APIGUARD_DATABASE_URL")
    if not url:
        raise RuntimeError("Set APIGUARD_DATABASE_URL to run migrations")
    return url


def run_migrations_offline() -> None:
    context.configure(url=_database_url(), target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = create_engine(_database_url(), poolclass=pool.NullPool)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
