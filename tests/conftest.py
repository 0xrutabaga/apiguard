"""Shared fixtures.

Integration and security tests run against a real PostgreSQL database. By default that is
``apiguard_test`` on the docker compose server (127.0.0.1:55431); override with
APIGUARD_TEST_DATABASE_URL. The database is dropped and re-created from the Alembic migrations
once per test session, and every table is truncated before each test that uses it.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from argon2 import PasswordHasher
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker

from apiguard import passwords
from apiguard.app import create_app
from apiguard.config import Settings
from apiguard.models import Base
from tests.support import World, build_world, make_settings

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TEST_URL = "postgresql+psycopg://apiguard:apiguard@127.0.0.1:55431/apiguard_test"


def get_test_database_url() -> str:
    return os.environ.get("APIGUARD_TEST_DATABASE_URL", DEFAULT_TEST_URL)


@pytest.fixture(autouse=True, scope="session")
def _cheap_password_hashing() -> Iterator[None]:
    """Use minimal Argon2 parameters in tests; production parameters are the library defaults.

    Hashing cost is not what these tests measure, and default parameters (64 MiB per hash)
    would make the suite slow. Unit tests in tests/unit/test_passwords.py check the real hasher.
    """
    original_hasher, original_dummy = passwords._hasher, passwords._DUMMY_HASH
    cheap = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)
    passwords._hasher = cheap
    passwords._DUMMY_HASH = cheap.hash("dummy")
    yield
    passwords._hasher, passwords._DUMMY_HASH = original_hasher, original_dummy


def recreate_database(url: str) -> None:
    target = make_url(url)
    admin = create_engine(target.set(database="postgres"), isolation_level="AUTOCOMMIT")
    try:
        with admin.connect() as conn:
            name = target.database
            assert name and name.replace("_", "").isalnum(), "unexpected test database name"
            conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
            conn.execute(text(f'CREATE DATABASE "{name}"'))
    finally:
        admin.dispose()


def alembic_config(url: str) -> Config:
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
    return config


@pytest.fixture(scope="session")
def database_url() -> str:
    url = get_test_database_url()
    try:
        recreate_database(url)
    except Exception as exc:  # pragma: no cover - environment problem, not a test failure mode
        pytest.fail(
            f"PostgreSQL is not reachable at {make_url(url).render_as_string(hide_password=True)}"
            f" ({type(exc).__name__}). Start it with `docker compose up -d --wait`.",
            pytrace=False,
        )
    command.upgrade(alembic_config(url), "head")
    return url


@pytest.fixture(scope="session")
def engine(database_url: str) -> Iterator[Engine]:
    eng = create_engine(database_url)
    yield eng
    eng.dispose()


@pytest.fixture
def db(engine: Engine) -> Iterator[sessionmaker[Session]]:
    """Empty every table, then hand out a session factory bound to the test database."""
    tables = ", ".join(t.name for t in Base.metadata.sorted_tables)
    with engine.begin() as conn:
        conn.execute(text(f"TRUNCATE {tables} RESTART IDENTITY CASCADE"))
    yield sessionmaker(bind=engine, expire_on_commit=False)


@pytest.fixture
def settings(database_url: str) -> Settings:
    return make_settings(database_url)


@pytest.fixture
def app(settings: Settings, db: sessionmaker[Session]) -> Iterator[FastAPI]:
    application = create_app(settings)
    yield application
    application.state.engine.dispose()


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def app_factory(
    database_url: str, db: sessionmaker[Session]
) -> Iterator[Callable[..., TestClient]]:
    """Build a client for an app with custom settings (for example low rate limits)."""
    apps: list[FastAPI] = []

    def build(**overrides: object) -> TestClient:
        application = create_app(make_settings(database_url, **overrides))
        apps.append(application)
        return TestClient(application)

    yield build
    for application in apps:
        application.state.engine.dispose()


@pytest.fixture
def world(db: sessionmaker[Session], settings: Settings) -> World:
    return build_world(db, settings)
