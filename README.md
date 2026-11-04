# apiguard

A multi-tenant FastAPI + PostgreSQL service in which every read and write of tenant data goes
through one authorization policy module, backed by a regression suite organised by the OWASP API
Security Top 10 (2023). The problem it addresses is broken object-level authorization (API1) and
broken function-level authorization (API5): an API that authenticates users correctly but lets
them reach another tenant's objects, or call functions above their role, by changing an id or a
URL.

## Why it matters

API1 and API5 are first and fifth in the OWASP API Security Top 10 (2023). They are rarely
caused by missing authentication; they come from authorization checks that are scattered across
handlers, forgotten in one of them, or that use a different rule for lists than for single
objects. Most example APIs show login and stop there. This repository shows the parts that come
after login: a single policy, tenant-scoped queries, property allow-lists, session handling that
survives token theft, and tests that try the attacks.

## What it does

Domain: organisations (tenants) contain projects, projects contain documents. Users join
organisations with a role (`owner`, `admin`, `editor`, `viewer`). A document can be shared with
a specific member of the same organisation with `read` or `edit` permission.

| Area | Behaviour | Where |
| --- | --- | --- |
| Policy | `decide(actor, action, resource)` returns allowed/visible; invisible becomes 404, visible but not allowed becomes 403 | `src/apiguard/policy.py` |
| Tenant scoping | loaders always filter by the organisation (and project) in the URL; list endpoints use `visible_documents_clause`, the SQL form of the same read rule | `src/apiguard/authz.py`, `policy.py` |
| Schema invariants | composite foreign keys stop a document sitting in another tenant's project and a share pointing at a non-member | `src/apiguard/models.py`, `migrations/versions/0001_initial_schema.py` |
| Property allow-lists | request models use `extra="forbid"`; `org_id`, `owner_id`, `role`, `password_hash` cannot be set from a body | `src/apiguard/schemas.py` |
| Passwords | Argon2id via argon2-cffi (library defaults, RFC 9106 low-memory profile); unknown emails still cost one verification | `src/apiguard/passwords.py` |
| Access tokens | HS256 JWT via PyJWT, algorithm allow-list `["HS256"]`, required `exp iat nbf iss aud sub jti`, `typ=access`, key from env; identity only, roles are read from the database per request | `src/apiguard/tokens.py` |
| Refresh tokens | opaque 256-bit tokens, stored as SHA-256, rotated on every use; replaying a used token revokes the whole family; a row lock serialises concurrent refreshes, so two simultaneous refreshes with one token also revoke the family (logging the user out) | `src/apiguard/refresh.py` |
| Membership | joining an organisation needs an invitation the invitee accepts with a one-time token and an account with the invited email; creating an invitation looks nothing up and returns the same fields for any email | `src/apiguard/routers/invitations.py` |
| Rate limiting | fixed-window counters in PostgreSQL for login (per IP and per account), refresh (per IP and per account), registration (per IP), invitations and accepts (per user); 429 with `Retry-After`; one `rate_limited` audit row per key per window; every hit deletes finished windows of all keys | `src/apiguard/ratelimit.py`, `routers/auth.py` |
| Audit log | security events with request id and client IP; a trigger rejects UPDATE and DELETE | `src/apiguard/audit.py`, migration |
| Configuration | pydantic-settings; refuses to start with a short, low-variety or placeholder signing key outside test mode; CORS off and API docs off unless configured | `src/apiguard/config.py`, `app.py` |
| Headers | `nosniff`, `X-Frame-Options: DENY`, `Cache-Control: no-store`, a deny-all CSP, HSTS, request id echo | `src/apiguard/middleware.py` |

Lockout policy: there is no permanent account lockout. When an account exceeds
`APIGUARD_LOGIN_LIMIT_PER_ACCOUNT` attempts (default 5) in a window of
`APIGUARD_RATE_LIMIT_WINDOW_SECONDS` (default 60), further logins for that email get 429 until
the window ends, even with the correct password; the per-IP limit (default 20) bounds password
spraying across accounts. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for why.

## Architecture

```mermaid
flowchart LR
    client([HTTP client])
    subgraph app["FastAPI app (create_app)"]
        mw["RequestIdMiddleware<br/>SecurityHeadersMiddleware<br/>CORS only if configured"]
        routes["routers: auth, orgs, projects"]
        user["deps.get_current_user<br/>tokens.decode_access_token"]
        authz["authz: resolve_actor,<br/>load_project, authorize_document,<br/>authorize / enforce"]
        policy["policy.decide<br/>policy.visible_documents_clause"]
        rl["ratelimit.RateLimiter"]
        refresh["refresh.rotate"]
        audit["audit.record_event / add_event"]
    end
    pg[("PostgreSQL 17")]

    client --> mw --> routes
    routes --> user
    routes --> authz --> policy
    routes -- "/auth/*" --> rl
    routes -- "/auth/refresh" --> refresh
    authz -- "denied: 404 or 403" --> audit
    routes --> audit
    user --> pg
    authz --> pg
    rl --> pg
    refresh --> pg
    audit --> pg
```

A request for `/orgs/{org_id}/projects/{project_id}/documents/{document_id}`:

1. `get_current_user` validates the bearer token and loads the user.
2. `authorize_org` looks up the caller's membership in `org_id`; a non-member is denied as
   invisible (404) and the denial is written to the audit log in its own transaction.
3. `authorize_document` selects the document by id *and* organisation *and* project, so an id from
   another tenant or another project is 404 even before the policy runs.
4. `authorize` asks `policy.decide` about this action on this document (ownership, share,
   role ceiling) and turns the decision into 404, 403 or continue.

## Technology choices

- **FastAPI with sync handlers** – handlers run in the threadpool with one SQLAlchemy session
  each and commit explicitly; there is no hidden commit in a dependency.
- **SQLAlchemy 2 + psycopg 3 + Alembic** – typed ORM models; migrations are reviewed by hand and
  a test fails if the models and the migration drift.
- **PostgreSQL for rate limits and refresh tokens** – one stateful dependency instead of two;
  `INSERT ... ON CONFLICT ... RETURNING` and `SELECT ... FOR UPDATE` give the atomicity these
  features need across several API processes.
- **argon2-cffi, PyJWT** – maintained, widely used libraries; no custom cryptography.
- **pydantic-settings** – typed configuration with validation at startup.

Longer reasoning and alternatives are in [docs/ENGINEERING_DECISIONS.md](docs/ENGINEERING_DECISIONS.md).

## Installation

Requirements: [uv](https://docs.astral.sh/uv/), Docker with Compose. uv installs Python 3.12
from `.python-version` if needed.

```bash
git clone <this repository> apiguard
cd apiguard
uv sync --locked
docker compose up -d --wait      # PostgreSQL 17 on 127.0.0.1:55431
```

## Quick start

```bash
uv run python scripts/demo.py
```

The demo applies the migrations, starts the API on a free local port with a random signing key,
and runs a scripted scenario over HTTP. Each line states the status it expects and the script
exits 1 if any differs. Part of the output of one local run (ids differ per run; event
numbers depend on what is already in the database):

```text
Authorization
  [ok  ] bob (Globex owner) reads Acme's document by its real id    -> 404 (expected 404)
  [ok  ] victor (viewer, read share) reads the document             -> 200 (expected 200)
  [ok  ] victor tries to edit the document                          -> 403 (expected 403)
  [ok  ] victor tries to add org_id to a new document (mass assignment) -> 422 (expected 422)

Authentication
  [ok  ] bob logs in with a wrong password                          -> 401 (expected 401)
  [ok  ] login for an email that does not exist                     -> 401 (expected 401)
  [ok  ] alice refreshes her session                                -> 200 (expected 200)
  [ok  ] an attacker replays alice's old refresh token              -> 401 (expected 401)
  [ok  ] alice's new refresh token is revoked with the family       -> 401 (expected 401)

Acme audit events (oldest first):
  #112  member_added           actor=e23979df request_id=845dda97863c4ca088c15cc26a1a919b {'via': 'org_created', 'role': 'owner', 'user_id': 'e23979df-9396-475e-8b09-a024935f7537'}
  #114  invitation_created     actor=e23979df request_id=a8da8a53a2be474e9d7e2ff3c0027ca2 {'role': 'viewer', 'invitation_id': '3bfe0212-0214-4fb3-9de7-059517297d40'}
  #115  permission_denied      actor=91e6ea9a request_id=c86803ffb0974963abbeb1d7e996d923 {'action': 'org.read', 'reason': 'not found or not visible', 'status': 404}
  #116  member_added           actor=91e6ea9a request_id=8d49c485f2134b08a2be2722f757d4e6 {'via': 'invitation', 'role': 'viewer', 'user_id': '91e6ea9a-a8d5-461b-9147-80aeacbd0d86', 'invited_by': 'e23979df-9396-475e-8b09-a024935f7537'}
  #117  permission_denied      actor=40f3c1cc request_id=demo-81aafd-bola                 {'action': 'project.read', 'reason': 'not found or not visible', 'status': 404}
  #118  permission_denied      actor=91e6ea9a request_id=demo-81aafd-bfla                 {'action': 'document.update', 'reason': 'access read does not permit document.update', 'status': 403, 'document_id': '1553a913-4653-44f4-92ac-a85c89f4608d'}
```

## Examples

Run the server yourself (the key must be at least 32 characters with 10 distinct characters,
and not a placeholder, or startup fails):

```bash
export APIGUARD_ENVIRONMENT=development
export APIGUARD_DATABASE_URL=postgresql+psycopg://apiguard:apiguard@127.0.0.1:55431/apiguard
export APIGUARD_JWT_SIGNING_KEY="$(uv run python -c 'import secrets; print(secrets.token_urlsafe(48))')"
uv run alembic upgrade head
uv run uvicorn --factory apiguard.app:create_app --port 8000
```

```bash
curl -s -X POST localhost:8000/auth/register -H 'Content-Type: application/json' \
  -d '{"email":"carol@example.com","password":"a long demo password","display_name":"Carol"}'
# {"id":"…","email":"carol@example.com","display_name":"Carol"}

curl -s -X POST localhost:8000/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"carol@example.com","password":"wrong"}'
# {"detail":"invalid email or password"}   (same body for an unknown email)

TOKEN=$(curl -s -X POST localhost:8000/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"carol@example.com","password":"a long demo password"}' | uv run python -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')
curl -s -X POST localhost:8000/orgs -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"name":"Carol Co"}'
```

Endpoints:

| Method and path | Who |
| --- | --- |
| `POST /auth/register`, `/auth/login`, `/auth/refresh`; `POST /auth/logout` | anyone; logout needs the access token |
| `GET /me`, `GET /me/audit-events`, `GET /orgs`, `POST /orgs` | any authenticated user |
| `GET /orgs/{org}`, `GET /orgs/{org}/members`, `GET /orgs/{org}/projects[/{project}]` | members |
| `PATCH/DELETE /orgs/{org}/members/{user}`; `POST/GET /orgs/{org}/invitations`, `DELETE /orgs/{org}/invitations/{id}` | owner, admin (admins manage and invite editors and viewers only) |
| `POST /invitations/accept` | the invited user, with the token |
| `POST/PATCH/DELETE /orgs/{org}/projects[/{project}]`, `GET /orgs/{org}/audit-events` | owner, admin |
| `POST /orgs/{org}/projects/{project}/documents` | owner, admin, editor |
| `GET/PATCH/DELETE …/documents/{doc}`, `PUT/DELETE …/documents/{doc}/shares/{user}` | per document, see `policy.py` |
| `GET /healthz` (no database), `GET /readyz` (database) | anyone |

## Testing

```bash
docker compose up -d --wait
uv run ruff format --check .
uv run ruff check .
uv run mypy src
uv run pytest -q
```

`uv run pytest --collect-only -q` reports 487 tests at the time of writing. The suite
drops and re-creates a database named `apiguard_test` on the compose server from the Alembic
migrations (set `APIGUARD_TEST_DATABASE_URL` to use another server).

- `tests/unit/` – the policy matrix for every role and action (written out by hand, not derived
  from the code), JWT validation cases, settings validation, password hashing.
- `tests/integration/` – real PostgreSQL: auth flows, documents and shares, members and the
  last-owner rule, audit log contents and the append-only trigger, the rate limiter with a fake
  clock and under 20 concurrent threads, migration drift and downgrade/upgrade, and a check
  that the SQL listing filter agrees with the per-object policy for every member and document.
- `tests/security/` – one file per OWASP API Top 10 (2023) item covered:
  `test_api1_bola.py`, `test_api2_broken_authentication.py`,
  `test_api3_broken_object_property_level_authorization.py`,
  `test_api4_unrestricted_resource_consumption.py`,
  `test_api5_broken_function_level_authorization.py`, `test_api8_security_misconfiguration.py`.

Dependency audit of the locked versions:

```bash
uv export --locked --format requirements-txt --no-emit-project -o requirements.audit.txt
uvx pip-audit@2.10.1 --require-hashes --disable-pip -r requirements.audit.txt
```

CI (`.github/workflows/ci.yml`) runs all of the above plus the demo on ubuntu-latest against a
PostgreSQL 17 service container.

## Limitations

- Registration answers 409 for an email that is already registered, which reveals whether an
  address has an account. It is rate limited per IP; removing it needs email verification,
  which is not built.
- Emails are not verified, so whoever registers an address first owns it. An invitation can
  only be accepted with its one-time token *and* that email, so squatting an invited address
  is not enough on its own, but the token travels outside the API (the inviter receives it
  in the response and passes it on; a real deployment would email it).
- Per-account throttling means an attacker who knows an email can keep that account at 429 for
  as long as they keep sending attempts (bounded by their per-IP limit). This is the usual
  trade-off of throttling by account.
- One HS256 signing key; no key id (`kid`) or rotation without invalidating all access tokens.
  Access tokens cannot be revoked before they expire (default 300 s); removal and role changes
  still take effect at once because roles are read per request.
- Fixed windows allow up to twice the limit across a window boundary.
- Client IP comes from the ASGI server; behind a proxy, uvicorn must be run with
  `--proxy-headers --forwarded-allow-ips` or every request shares one IP.
- The login timing equalisation is checked by counting Argon2 verifications in tests, not by
  measuring response times.
- No endpoints for deleting users or organisations, for password change or reset, or for
  listing a document's shares.
- The last-owner rule takes row locks (`routers/orgs.py::_ensure_another_owner`) so two owners
  demoting each other at the same moment cannot both succeed. Only the sequential case is
  tested; an attempt at a threaded test did not reliably overlap the two requests, so it was
  not kept.
- Some database growth is bounded by rate, not by size. Each failed login writes one
  `login_failed` row (at most the per-IP and per-account limits per window), each successful
  registration one user, and each denied authenticated request one `permission_denied` row
  (authenticated endpoints other than invitations are not rate limited). Rejected 429
  requests write one `rate_limited` row per key per window, and `rate_limit_counters` holds
  only the current window. Audit retention and archiving are left to the operator.
- The Examples section registers `carol@example.com`; running it a second time against the same
  database answers 409 for that step.
- The append-only trigger does not stop `TRUNCATE` or a superuser disabling triggers; database
  privileges for the application role have to do that (see the threat model).

## Future work

- Asymmetric signing (EdDSA or ES256) with `kid` and a published key set, so keys can rotate.
- Email verification, and emailing invitation tokens instead of returning them.
- A general per-user request limit for authenticated endpoints.
- A sliding-window or token-bucket limiter, and an optional Redis backend.
- A Dockerfile and a compose service for the API itself, with a least-privilege database role
  that has only INSERT and SELECT on `audit_events`.
- Property-based tests that generate random organisations, roles and shares for the
  policy/SQL agreement check.

## Licence

MIT, see [LICENSE](LICENSE).
