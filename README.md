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
| Refresh tokens | opaque 256-bit tokens, stored as SHA-256, rotated on every use; replaying a used token revokes the whole family; row lock serialises concurrent refreshes | `src/apiguard/refresh.py` |
| Rate limiting | fixed-window counters in PostgreSQL for login (per IP and per account), refresh (per IP and per account) and registration (per IP); 429 with `Retry-After` | `src/apiguard/ratelimit.py`, `routers/auth.py` |
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
        authz["authz: resolve_actor,<br/>load_project / load_document,<br/>authorize / enforce"]
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
3. `load_document` selects the document by id *and* organisation *and* project, so an id from
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
  #44   member_added           actor=22eff9ac request_id=d5dca9230b1348eea2ff17d65f100c1a {'via': 'org_created', 'role': 'owner', 'user_id': '22eff9ac-eefe-4e9f-9c84-37cc4d069b30'}
  #46   member_added           actor=22eff9ac request_id=68c108c258f24e279a1b1a600f6fee0d {'role': 'viewer', 'user_id': 'efede4ff-4b13-48ea-81ef-8c3ae15abf15'}
  #47   permission_denied      actor=5c0ed4ef request_id=demo-8d6d76-bola                 {'action': 'project.read', 'reason': 'not a member of the organisation', 'status': 404}
  #48   permission_denied      actor=efede4ff request_id=demo-8d6d76-bfla                 {'action': 'document.update', 'reason': 'access read does not permit document.update', 'status': 403, 'document_id': '2fab8cf3-cb58-4696-ad0f-210d08ca8de0'}
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
| `POST/PATCH/DELETE /orgs/{org}/members[/{user}]` | owner, admin (admins manage editors and viewers only) |
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

`uv run pytest --collect-only -q` reports 469 tests at the time of writing. The suite
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

- Registration answers 409 for an email that is already registered, and adding a member by
  email answers 404 for an unknown email (to owners and admins only). Both reveal whether an
  address has an account; fixing that needs an email verification and invitation flow, which is
  not built. Registration is rate limited per IP.
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
- Every denied request writes one audit row, and only login, refresh and registration are rate
  limited. An authenticated user can therefore grow the audit table by probing; a general
  per-user request limit is not built.
- The Examples section registers `carol@example.com`; running it a second time against the same
  database answers 409 for that step.
- The append-only trigger does not stop `TRUNCATE` or a superuser disabling triggers; database
  privileges for the application role have to do that (see the threat model).

## Future work

- Asymmetric signing (EdDSA or ES256) with `kid` and a published key set, so keys can rotate.
- Email verification and invitations to remove the two enumeration points above.
- A sliding-window or token-bucket limiter, and an optional Redis backend.
- A Dockerfile and a compose service for the API itself, with a least-privilege database role
  that has only INSERT and SELECT on `audit_events`.
- Property-based tests that generate random organisations, roles and shares for the
  policy/SQL agreement check.

## Licence

MIT, see [LICENSE](LICENSE).
