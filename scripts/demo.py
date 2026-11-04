"""End-to-end demo against a real server and PostgreSQL.

    docker compose up -d --wait
    uv run python scripts/demo.py

The script applies migrations, starts uvicorn on a free local port, then drives the HTTP API:
two organisations, a cross-tenant read (404), a viewer edit (403), a failed login, refresh
token reuse, and finally prints the audit events those actions produced. Every step checks the
status code it expects and the script exits non-zero if any check fails.

Pass --base-url to run the same scenario against a server you started yourself (migrations
are then your responsibility). Users get a random suffix, so the demo can be re-run.
"""

from __future__ import annotations

import argparse
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import IO, Any

import httpx2 as httpx
from alembic import command
from alembic.config import Config
from sqlalchemy.exc import OperationalError

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB = "postgresql+psycopg://apiguard:apiguard@127.0.0.1:55431/apiguard"
PASSWORD = "demo password, not a real one"

failures: list[str] = []


def check(label: str, response: httpx.Response, expected: int) -> httpx.Response:
    ok = response.status_code == expected
    mark = "ok  " if ok else "FAIL"
    print(f"  [{mark}] {label:<58} -> {response.status_code} (expected {expected})")
    if not ok:
        failures.append(f"{label}: {response.status_code} {response.text}")
    return response


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
        return port


def start_server(env: dict[str, str], handle: IO[bytes]) -> tuple[subprocess.Popen[bytes], str]:
    port = free_port()
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "--factory",
            "apiguard.app:create_app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        env=env,
        stdout=handle,
        stderr=subprocess.STDOUT,
    )
    base_url = f"http://127.0.0.1:{port}"
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if process.poll() is not None:
            break
        try:
            if httpx.get(f"{base_url}/readyz", timeout=1).status_code == 200:
                return process, base_url
        except httpx.TransportError:
            pass
        time.sleep(0.2)
    process.terminate()
    process.wait(timeout=10)
    handle.seek(0)
    sys.exit(f"server did not become ready; log:\n{handle.read().decode(errors='replace')}")


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def print_events(title: str, events: list[dict[str, Any]]) -> None:
    print(f"\n{title}")
    for event in reversed(events):
        detail = {k: v for k, v in event["detail"].items() if k != "family_id"}
        print(
            f"  #{event['id']:<4} {event['event_type']:<22} "
            f"actor={str(event['actor_user_id'])[:8] if event['actor_user_id'] else '-':<8} "
            f"request_id={event['request_id'] or '-':<32} {detail}"
        )


def scenario(api: httpx.Client) -> None:
    run = secrets.token_hex(3)
    emails = {name: f"{name}.{run}@example.com" for name in ("alice", "victor", "bob")}
    print(f"\nRun id {run}: alice owns Acme, victor is a viewer in Acme, bob owns Globex.\n")

    print("Setup")
    for name, email in emails.items():
        check(
            f"register {name}",
            api.post(
                "/auth/register",
                json={"email": email, "password": PASSWORD, "display_name": name.title()},
            ),
            201,
        )
    tokens: dict[str, dict[str, str]] = {}
    for name, email in emails.items():
        response = check(
            f"login {name}",
            api.post("/auth/login", json={"email": email, "password": PASSWORD}),
            200,
        )
        tokens[name] = response.json()
    alice, victor, bob = (bearer(tokens[n]["access_token"]) for n in ("alice", "victor", "bob"))

    acme = check(
        "alice creates org Acme", api.post("/orgs", json={"name": "Acme"}, headers=alice), 201
    ).json()
    check("bob creates org Globex", api.post("/orgs", json={"name": "Globex"}, headers=bob), 201)
    project = check(
        "alice creates a project",
        api.post(f"/orgs/{acme['id']}/projects", json={"name": "Finance"}, headers=alice),
        201,
    ).json()
    doc = check(
        "alice creates a document",
        api.post(
            f"/orgs/{acme['id']}/projects/{project['id']}/documents",
            json={"title": "Q3 plan", "body": "confidential"},
            headers=alice,
        ),
        201,
    ).json()
    doc_url = f"/orgs/{acme['id']}/projects/{project['id']}/documents/{doc['id']}"
    victor_member = check(
        "alice adds victor to Acme as viewer",
        api.post(
            f"/orgs/{acme['id']}/members",
            json={"email": emails["victor"], "role": "viewer"},
            headers=alice,
        ),
        201,
    ).json()
    check(
        "alice shares the document with victor (read)",
        api.put(
            f"{doc_url}/shares/{victor_member['user_id']}",
            json={"permission": "read"},
            headers=alice,
        ),
        200,
    )

    print("\nAuthorization")
    check(
        "bob (Globex owner) reads Acme's document by its real id",
        api.get(doc_url, headers={**bob, "X-Request-ID": f"demo-{run}-bola"}),
        404,
    )
    check("victor (viewer, read share) reads the document", api.get(doc_url, headers=victor), 200)
    check(
        "victor tries to edit the document",
        api.patch(
            doc_url, json={"body": "edited"}, headers={**victor, "X-Request-ID": f"demo-{run}-bfla"}
        ),
        403,
    )
    check(
        "victor tries to add org_id to a new document (mass assignment)",
        api.post(
            f"/orgs/{acme['id']}/projects/{project['id']}/documents",
            json={"title": "x", "org_id": acme["id"]},
            headers=victor,
        ),
        422,
    )

    print("\nAuthentication")
    check(
        "bob logs in with a wrong password",
        api.post("/auth/login", json={"email": emails["bob"], "password": "wrong password"}),
        401,
    )
    check(
        "login for an email that does not exist",
        api.post("/auth/login", json={"email": f"nobody.{run}@example.com", "password": "x"}),
        401,
    )
    old = tokens["alice"]["refresh_token"]
    rotated = check(
        "alice refreshes her session", api.post("/auth/refresh", json={"refresh_token": old}), 200
    )
    check(
        "an attacker replays alice's old refresh token",
        api.post("/auth/refresh", json={"refresh_token": old}),
        401,
    )
    check(
        "alice's new refresh token is revoked with the family",
        api.post("/auth/refresh", json={"refresh_token": rotated.json()["refresh_token"]}),
        401,
    )

    print("\nAudit")
    org_events = check(
        "alice reads Acme's audit log",
        api.get(f"/orgs/{acme['id']}/audit-events", headers=alice),
        200,
    ).json()
    check(
        "victor (viewer) cannot read Acme's audit log",
        api.get(f"/orgs/{acme['id']}/audit-events", headers=victor),
        403,
    )
    print_events("Acme audit events (oldest first):", org_events)
    print_events(
        "alice's own security events:",
        api.get("/me/audit-events", headers=bearer(rotated.json()["access_token"])).json(),
    )
    print_events("bob's own security events:", api.get("/me/audit-events", headers=bob).json())


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--base-url", help="use an already running server instead of starting one")
    args = parser.parse_args()

    if args.base_url:
        with httpx.Client(base_url=args.base_url.rstrip("/"), timeout=10) as api:
            scenario(api)
    else:
        env = dict(os.environ)
        env.setdefault("APIGUARD_DATABASE_URL", DEFAULT_DB)
        env.setdefault("APIGUARD_ENVIRONMENT", "development")
        if not env.get("APIGUARD_JWT_SIGNING_KEY"):
            # A fresh random key per run; tokens from this demo die with the process.
            env["APIGUARD_JWT_SIGNING_KEY"] = secrets.token_urlsafe(48)
        config = Config(str(ROOT / "alembic.ini"))
        config.set_main_option("sqlalchemy.url", env["APIGUARD_DATABASE_URL"].replace("%", "%%"))
        print("Applying migrations ...")
        try:
            command.upgrade(config, "head")
        except OperationalError as exc:
            sys.exit(
                f"Cannot reach PostgreSQL ({type(exc.orig).__name__}). "
                "Start it with `docker compose up -d --wait` and retry."
            )
        with tempfile.TemporaryFile() as log:
            process, base_url = start_server(env, log)
            print(f"Server started at {base_url}")
            try:
                with httpx.Client(base_url=base_url, timeout=10) as api:
                    scenario(api)
            finally:
                process.terminate()
                process.wait(timeout=10)

    if failures:
        print(f"\n{len(failures)} check(s) failed:")
        for failure in failures:
            print(f"  - {failure}")
        sys.exit(1)
    print("\nAll demo checks passed.")


if __name__ == "__main__":
    main()
