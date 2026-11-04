"""Shared fixtures.

Integration and security tests run against a real PostgreSQL database. By default that is
``apiguard_test`` on the docker compose server (127.0.0.1:55431); override with
APIGUARD_TEST_DATABASE_URL. The database is dropped and re-created from the Alembic migrations
once per test session, and every table is truncated before each test that uses it.
"""

from __future__ import annotations

import os
import secrets
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
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
from apiguard.models import Base, Document, Membership, Organization, Project, User
from apiguard.tokens import issue_access_token

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TEST_URL = "postgresql+psycopg://apiguard:apiguard@127.0.0.1:55431/apiguard_test"
TEST_PASSWORD = "correct horse battery staple"


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


def make_settings(database_url: str, **overrides: object) -> Settings:
    values: dict[str, object] = {
        "environment": "test",
        "database_url": database_url,
        "jwt_signing_key": secrets.token_urlsafe(48),
        # Generous limits so only the rate-limit tests hit them.
        "login_limit_per_ip": 1000,
        "login_limit_per_account": 1000,
        "refresh_limit_per_ip": 1000,
        "refresh_limit_per_account": 1000,
        "register_limit_per_ip": 1000,
    }
    values.update(overrides)
    return Settings.model_validate(values)


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


# --- a populated two-tenant world ---------------------------------------------------------


@dataclass
class World:
    """Two organisations with members of every role, one project and document in each.

    org_a: a_owner (owner), a_admin (admin), a_editor and a_editor2 (editor), a_viewer
    org_b: b_owner (owner)
    outsider: a user with no membership
    doc_a is owned by a_editor in proj_a; doc_b is owned by b_owner in proj_b.
    """

    settings: Settings
    users: dict[str, User] = field(default_factory=dict)
    org_a: uuid.UUID = field(default_factory=uuid.uuid4)
    org_b: uuid.UUID = field(default_factory=uuid.uuid4)
    proj_a: uuid.UUID = field(default_factory=uuid.uuid4)
    proj_a2: uuid.UUID = field(default_factory=uuid.uuid4)
    proj_b: uuid.UUID = field(default_factory=uuid.uuid4)
    doc_a: uuid.UUID = field(default_factory=uuid.uuid4)
    doc_b: uuid.UUID = field(default_factory=uuid.uuid4)

    def uid(self, name: str) -> uuid.UUID:
        return self.users[name].id

    def auth(self, name: str) -> dict[str, str]:
        token = issue_access_token(self.settings, self.users[name].id)
        return {"Authorization": f"Bearer {token}"}

    def doc_url(self, org: uuid.UUID, project: uuid.UUID, doc: uuid.UUID) -> str:
        return f"/orgs/{org}/projects/{project}/documents/{doc}"

    @property
    def doc_a_url(self) -> str:
        return self.doc_url(self.org_a, self.proj_a, self.doc_a)

    @property
    def doc_b_url(self) -> str:
        return self.doc_url(self.org_b, self.proj_b, self.doc_b)


def build_world(session_factory: sessionmaker[Session], settings: Settings) -> World:
    world = World(settings=settings)
    password_hash = passwords.hash_password(TEST_PASSWORD)
    members = {
        "a_owner": (world.org_a, "owner"),
        "a_admin": (world.org_a, "admin"),
        "a_editor": (world.org_a, "editor"),
        "a_editor2": (world.org_a, "editor"),
        "a_viewer": (world.org_a, "viewer"),
        "b_owner": (world.org_b, "owner"),
        "outsider": (None, None),
    }
    with session_factory.begin() as session:
        session.add_all(
            [Organization(id=world.org_a, name="Org A"), Organization(id=world.org_b, name="Org B")]
        )
        for name in members:
            user = User(email=f"{name}@example.com", display_name=name, password_hash=password_hash)
            session.add(user)
            world.users[name] = user
        session.flush()
        for name, (org, role) in members.items():
            if org is not None and role is not None:
                session.add(Membership(org_id=org, user_id=world.uid(name), role=role))
        session.add_all(
            [
                Project(id=world.proj_a, org_id=world.org_a, name="A project"),
                Project(id=world.proj_a2, org_id=world.org_a, name="A second project"),
                Project(id=world.proj_b, org_id=world.org_b, name="B project"),
            ]
        )
        session.flush()
        session.add_all(
            [
                Document(
                    id=world.doc_a,
                    org_id=world.org_a,
                    project_id=world.proj_a,
                    owner_id=world.uid("a_editor"),
                    title="A plan",
                    body="tenant A data",
                ),
                Document(
                    id=world.doc_b,
                    org_id=world.org_b,
                    project_id=world.proj_b,
                    owner_id=world.uid("b_owner"),
                    title="B plan",
                    body="tenant B data",
                ),
            ]
        )
    return world


@pytest.fixture
def world(db: sessionmaker[Session], settings: Settings) -> World:
    return build_world(db, settings)
