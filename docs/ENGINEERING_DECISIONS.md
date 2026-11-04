# Engineering decisions

Each entry: the decision, why, what it costs, and what was rejected.

## 1. One policy module, called with (actor, action, resource)

`src/apiguard/policy.py` holds every authorization rule. Handlers do not compare roles
themselves; they call `authz.authorize_org` or `authz.authorize`, which call `policy.decide`.

- Why: authorization bugs are usually a check missing from one handler or a rule that differs
  between two places. With one module the rules can be read in one screen and tested as a
  matrix (`tests/unit/test_policy_matrix.py` covers every role x action and every role x
  relationship x document action, with the expected table written by hand).
- Cost: handlers must load the resource before deciding, and the policy needs a small resource
  description (`OrgResource`, `DocumentResource`) rather than ORM objects.
- Rejected: decorators like `@require_role("admin")` on routes. They work for function-level
  checks but not for object-level ones (ownership, shares), so a second mechanism would be
  needed anyway.

## 2. `Decision` separates "visible" from "allowed"

`decide` returns `visible` and `allowed`. `authz.enforce` turns invisible into 404 and visible
but not allowed into 403.

- Why: a 403 for another tenant's id confirms that the id exists. A 404 that is byte-identical
  to the one for a random id (`test_404_for_foreign_document_is_identical_to_404_for_missing_document`)
  gives nothing away. Inside a tenant, a member who can see a document but not edit it gets 403,
  which is more useful to clients and leaks nothing they did not know.
- Cost: the rule "can read implies visible" has to be kept consistent; the matrix test asserts
  `visible is (READ in expected)` for every case.

## 3. Tenant scoping in the query, not only in the policy

`authz.load_project` and `authz.authorize_document` always filter by the org (and project) in the URL.

- Why: defence in depth. If a future handler forgot to call `authorize`, a foreign id would
  still not load. The policy then decides about a row that is already known to be in the right
  tenant.
- Also in the schema: `documents (project_id, org_id)` references `projects (id, org_id)` and
  `document_shares (org_id, user_id)` references `memberships`, so a cross-tenant document or
  share cannot be inserted even by code that bypasses the API
  (`test_database_rejects_document_in_foreign_project`, `test_database_rejects_cross_tenant_share_even_without_the_api`).
- Cost: `org_id` is duplicated onto documents and shares, and composite unique constraints
  `(id, org_id)` exist only to be foreign key targets.
- Rejected: PostgreSQL row-level security. It is a strong option, but it needs a per-request
  `SET` of the tenant and careful role setup; it would hide the policy inside the database
  where the matrix tests cannot reach it. Listed as future work, not a replacement.

## 4. Listings use the same rule as SQL, and a test keeps them equal

`policy.visible_documents_clause(actor)` is the SQL predicate for "this actor can read this
document". `tests/integration/test_policy_sql_agreement.py` evaluates both forms for every
member of both tenants against every document (with read, edit and no shares) and asserts they
agree.

- Why: filtering lists in Python after fetching would break pagination and load other tenants'
  rows into memory; writing the rule twice without a check is how list endpoints leak.

## 5. Roles are not in the access token

The JWT carries `sub` only. `authz.resolve_actor` reads the membership on every request.

- Why: removing a member or demoting them takes effect on the next request
  (`test_removed_member_loses_access_immediately`, `test_demotion_narrows_existing_share_immediately`),
  not when a token expires. One indexed primary-key lookup per request is cheap.
- Cost: one query per request; tokens alone cannot be used to authorize at an edge proxy.

## 6. Access tokens: HS256, short lifetime, strict validation

`tokens.decode_access_token` passes `algorithms=["HS256"]`, the audience, the issuer and
`options={"require": [...]}` to PyJWT, then checks `typ == "access"`.

- Why HS256: one service both issues and verifies; a symmetric key is the simplest correct
  choice. Asymmetric keys matter when other services verify tokens, which is future work.
- The allow-list blocks `alg=none` and algorithm confusion; required claims make a token
  missing `exp` invalid instead of eternal.
- Default lifetime is 300 s (`access_token_ttl_seconds`, bounded 30..3600 in `config.py`).

## 7. Refresh tokens: opaque, hashed with SHA-256, rotated, family revocation

See the module docstring in `src/apiguard/refresh.py`.

- Opaque instead of JWT: refresh tokens have to be checked against the database anyway
  (rotation and revocation), so a signed format adds nothing.
- SHA-256 instead of Argon2: the token is 256 random bits. Slow hashing protects low-entropy
  secrets like passwords; here a single SHA-256 already makes a database leak useless, and
  the lookup can use a unique index on the hash.
- Reuse detection: a used token presented again means two parties hold it. Revoking the family
  logs out the thief and the user; the user has to log in again, the thief cannot.
- Concurrency: `rotate` locks the row with `SELECT ... FOR UPDATE`. Of two simultaneous
  refreshes with the same token, the second is treated as reuse and revokes the whole family,
  including the token the first one just got
  (`test_concurrent_refresh_with_the_same_token_revokes_the_family`). A client that retries a
  refresh after a network error will therefore be logged out. Some systems allow a short grace
  period for this; apiguard chooses the strict behaviour and documents it.
- Each family also has an absolute expiry (`refresh_family_max_age_seconds`, default 30 days)
  so rotation cannot extend a session forever.

## 8. Rate limiting in PostgreSQL with fixed windows

`ratelimit.RateLimiter.hit` runs `INSERT ... ON CONFLICT DO UPDATE SET count = count + 1
RETURNING count` in its own transaction.

- Why PostgreSQL: it is already required, the upsert is atomic (20 parallel threads produce
  exactly 5 successes in `test_concurrent_hits_are_counted_exactly`), and limits hold across
  several API processes. An in-memory limiter would reset on restart and differ per worker.
- Why its own transaction: the increment must survive the request failing, which is the whole
  point for failed logins.
- Fixed windows are simple and their counters are easy to inspect; they allow up to twice the
  limit across a boundary. A sliding window or token bucket is future work.
- Emails are stored as SHA-256 in counter keys (`ratelimit.account_key`).
- Cost: two small writes per login attempt. At very high login rates Redis would be the next step.

## 9. Two ways to write audit events

`audit.add_event` adds the row to the request's session; `audit.record_event` commits in its
own transaction.

- Role and membership changes use `add_event`, so the event exists if and only if the change
  was committed (`test_role_change_is_recorded_in_the_same_transaction`,
  `test_rejected_role_change_leaves_no_role_changed_event`).
- Denials, failed logins and token reuse use `record_event`, because the request is about to
  fail and its transaction will not commit.
- Append-only is enforced by a trigger created in the migration, so it also applies to manual
  SQL (`test_audit_events_are_append_only`). The table has no foreign keys on purpose: records
  must outlive the users and organisations they mention.

## 10. Explicit commits in handlers

`deps.get_session` yields a session and closes it; it never commits. Each handler calls
`session.commit()` where its change is complete.

- Why: whether a yield-dependency's cleanup runs before or after the response has changed
  between FastAPI versions, and an implicit commit makes it unclear what happens when a handler
  raises after writing. Explicit commits keep the transaction boundary visible in the handler.
- Where a failure must still persist something (refresh reuse revokes the family, then the
  handler returns 401), the handler commits before raising; see `routers/auth.py::refresh_tokens`.

## 11. Startup refuses weak configuration

`config.Settings` validates the signing key unless `environment="test"`: at least 32
characters, at least 10 distinct characters, and none of a list of placeholder words.
`hide_input_in_errors=True` keeps the rejected key out of the error text.

- Why: a deployment that forgets the key, or copies `.env.example`, must fail loudly at
  startup, not issue tokens anyone can forge.
- The default environment is `production`, so the strict path is the one taken when nothing is
  configured.

## 12. Sync handlers and psycopg 3

- Why: the work per request is a few short queries plus Argon2 (CPU-bound, releases the GIL in
  the C library). Sync SQLAlchemy in FastAPI's threadpool is simple to reason about,
  especially for row locks and explicit transactions. Async would add complexity without a
  measured need.
- Cost: concurrency is bounded by the threadpool size and the connection pool.

## 13. Testing against a real database

Integration and security tests run against PostgreSQL 17, never SQLite. The things being tested
(`FOR UPDATE`, `ON CONFLICT`, composite foreign keys, triggers, JSONB) behave differently or do
not exist elsewhere. The test database is created from the Alembic migrations, not from
`metadata.create_all`, so the migration itself is under test, and
`test_models_and_migrations_have_no_drift` fails if the models change without a migration.
The suite lowers Argon2 cost for speed (`tests/conftest.py::_cheap_password_hashing`); the
production parameters are checked separately in `tests/unit/test_passwords.py`.

## 14. Membership by invitation, with a token

`src/apiguard/routers/invitations.py`. Owners and admins invite an *email*; the invitee joins
by calling `POST /invitations/accept` with a one-time token while logged in with that email.

- Why not "add member by email": any user can create an organisation and become its owner, so
  an add-by-email endpoint that answers differently for unknown emails is an account oracle,
  and adding people without consent puts them into organisations they never chose.
- The create endpoint never looks up the user, so its response and its queries are the same
  for registered and unregistered emails, and it returns no display name.
- Why a token and not only the email: registration does not verify email ownership, so
  "accept if your account has the invited email" would let whoever registers the address
  first take the invitation. The token (256 random bits, stored as SHA-256, replaced on
  re-invite, expiring after `invitation_ttl_seconds`) proves receipt; the email check stops a
  forwarded or leaked token being used by anyone else. Unknown, expired and wrong-email tokens
  get one identical 404.
- Cost: the token is returned to the inviter, who has to pass it on. A real deployment would
  email it instead; that is future work.

## 15. One audit row for "missing" and "not visible"

Callers can read their own audit events (`GET /me/audit-events`). If a denied read of an
existing-but-invisible document wrote a row and a missing id did not, or the two rows gave
different reasons, the audit trail would tell the caller which ids exist. Both now go through
`authz.authorize_document` / `authz.deny_not_found` and write the same row: action, status 404,
reason "not found or not visible", and the id the caller supplied. The policy's own reason is
stored only for 403s, where the caller already knows the resource exists.

## 16. Database errors map by kind

`app.py`: `IntegrityError` (a uniqueness or foreign key race lost to a concurrent request)
becomes 409; `OperationalError` and `InterfaceError` (connection, timeout, deadlock) become
503; any other driver error becomes a generic 500. None of them returns driver text. The race
test in `tests/integration/test_database_errors.py` is deterministic: it holds a competing
insert open in another transaction, so the request blocks on the primary key and then loses.
