"""OWASP API8:2023 Security Misconfiguration.

Secure defaults: security headers on every response, CORS off unless configured, no
interactive docs or schema unless enabled, no internal details in errors, and refusal to
start with a weak signing key.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from apiguard.app import create_app
from apiguard.middleware import SECURITY_HEADERS
from apiguard.tokens import issue_access_token
from tests.support import World


@pytest.mark.parametrize("path", ["/healthz", "/me", "/does-not-exist"])
def test_security_headers_on_every_response(client: TestClient, path: str) -> None:
    response = client.get(path)
    for name, value in SECURITY_HEADERS.items():
        assert response.headers.get(name) == value, name


def test_cors_is_off_by_default(client: TestClient) -> None:
    preflight = client.options(
        "/auth/login",
        headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"},
    )
    assert "access-control-allow-origin" not in preflight.headers
    simple = client.get("/healthz", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in simple.headers


def test_cors_allows_only_configured_origins(app_factory: Callable[..., TestClient]) -> None:
    client = app_factory(cors_origins="https://app.example")
    allowed = client.get("/healthz", headers={"Origin": "https://app.example"})
    assert allowed.headers["access-control-allow-origin"] == "https://app.example"
    denied = client.get("/healthz", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in denied.headers


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_docs_and_schema_are_disabled_by_default(client: TestClient, path: str) -> None:
    assert client.get(path).status_code == 404


def test_docs_can_be_enabled_explicitly(app_factory: Callable[..., TestClient]) -> None:
    client = app_factory(enable_docs=True)
    assert client.get("/openapi.json").status_code == 200


def test_validation_errors_do_not_echo_secrets_or_internals(client: TestClient) -> None:
    response = client.post(
        "/auth/login", content=b"{not json", headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 422
    assert "Traceback" not in response.text


def test_database_outage_returns_503_without_details(
    app_factory: Callable[..., TestClient], world: World
) -> None:
    # Port 1 on localhost refuses connections immediately.
    client = app_factory(
        database_url="postgresql+psycopg://apiguard:apiguard@127.0.0.1:1/apiguard",
        database_connect_timeout_seconds=1,
    )
    assert client.get("/healthz").status_code == 200
    token = issue_access_token(client.app.state.settings, world.uid("a_owner"))
    for response in (
        client.get("/readyz"),
        client.post("/auth/login", json={"email": "a@example.com", "password": "x"}),
        client.get("/me", headers={"Authorization": f"Bearer {token}"}),
    ):
        assert response.status_code == 503
        assert response.json() == {"detail": "service unavailable"}
        assert "127.0.0.1" not in response.text
        assert "psycopg" not in response.text


@pytest.mark.parametrize("environment", ["production", "development"])
def test_app_refuses_to_start_with_a_weak_key(
    monkeypatch: pytest.MonkeyPatch, environment: str
) -> None:
    monkeypatch.setenv("APIGUARD_ENVIRONMENT", environment)
    monkeypatch.setenv("APIGUARD_JWT_SIGNING_KEY", "secret")
    with pytest.raises(ValidationError, match="refusing to start"):
        create_app()


@pytest.mark.parametrize(
    ("incoming", "echoed"),
    [
        ("abc-123", True),
        ("x" * 65, False),
        ("evil\r\ninjected: 1", False),
        ("<script>", False),
    ],
)
def test_request_id_is_echoed_only_when_safe(
    client: TestClient, incoming: str, echoed: bool
) -> None:
    try:
        response = client.get("/healthz", headers={"X-Request-ID": incoming})
    except Exception:
        # The HTTP client itself refuses to send header values with CR/LF.
        assert not echoed
        return
    if echoed:
        assert response.headers["x-request-id"] == incoming
    else:
        assert response.headers["x-request-id"] != incoming
        assert len(response.headers["x-request-id"]) == 32
