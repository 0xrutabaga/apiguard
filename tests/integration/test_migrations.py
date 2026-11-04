"""Alembic migrations: they match the ORM models and can be rolled back and re-applied."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import make_url

from apiguard.models import Base
from tests.conftest import alembic_config, recreate_database


@pytest.fixture
def scratch_url(database_url: str) -> Iterator[str]:
    url = make_url(database_url).set(database=f"{make_url(database_url).database}_migrations")
    rendered = url.render_as_string(hide_password=False)
    recreate_database(rendered)
    yield rendered
    admin = create_engine(url.set(database="postgres"), isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(text(f'DROP DATABASE IF EXISTS "{url.database}" WITH (FORCE)'))
    admin.dispose()


def test_models_and_migrations_have_no_drift(database_url: str) -> None:
    engine = create_engine(database_url)
    with engine.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    engine.dispose()
    assert diff == []


def test_downgrade_to_base_and_upgrade_again(scratch_url: str) -> None:
    config = alembic_config(scratch_url)
    command.upgrade(config, "head")
    engine = create_engine(scratch_url)
    try:
        assert "audit_events" in inspect(engine).get_table_names()
        command.downgrade(config, "base")
        assert set(inspect(engine).get_table_names()) <= {"alembic_version"}
        command.upgrade(config, "head")
        tables = set(inspect(engine).get_table_names())
        assert {t.name for t in Base.metadata.sorted_tables} <= tables
        with engine.connect() as conn:
            triggers = conn.execute(
                text("SELECT tgname FROM pg_trigger WHERE tgname = 'audit_events_append_only'")
            ).all()
        assert len(triggers) == 1
    finally:
        engine.dispose()
