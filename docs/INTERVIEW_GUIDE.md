# Interview guide

Five hard questions an interviewer is likely to ask about this repository, with answers that
point at the code, the trade-offs taken, and how to show each one live.

Live setup for all demos (one terminal):

```bash
docker compose up -d --wait
uv sync --locked
uv run python scripts/demo.py
```

---

## 1. "Show me how you guarantee a user can never read another tenant's document. What if a developer forgets the check?"

Answer:

- Three layers, each enough on its own for the cross-tenant case:
  1. `authz.authorize_org` (`src/apiguard/authz.py`) resolves the caller's membership in the
     URL's `org_id`. No membership means `Decision(visible=False)` from `policy.decide`, which
     `authz.enforce` turns into 404 and an audit event.
  2. `authz.authorize_document` selects by `id`, `org_id` and `project_id` together. A handler that
     skipped step 1 would still get 404 for a foreign id, because the row does not match the
     org in the URL.
  3. The schema: `documents (project_id, org_id)` references `projects (id, org_id)`, and
     shares reference `memberships (org_id, user_id)` (`src/apiguard/models.py`). A cross-tenant
     row cannot be inserted at all.
- Lists are the usual leak, so `projects.list_documents` filters with
  `policy.visible_documents_clause`, and `tests/integration/test_policy_sql_agreement.py`
  checks it against `decide` for every member and every document.
- 404, not 403, and identical to a random id, so ids reveal nothing
  (`tests/security/test_api1_bola.py::test_404_for_foreign_document_is_identical_to_404_for_missing_document`).

Trade-off: `org_id` is denormalised onto documents and shares. Row-level security in PostgreSQL
would be a fourth layer; it was not added because it moves rules out of the tested policy
module and needs per-request session state.

Live: the demo line "bob (Globex owner) reads Acme's document by its real id -> 404". Then:

```bash
uv run pytest tests/security/test_api1_bola.py -v
```

Break it on purpose (keep a copy of `src/apiguard/authz.py` and restore it afterwards):

- Delete the `Document.org_id == org_id,` line in `authz.authorize_document`. Every test in
  `tests/security/test_api1_bola.py` still passes: the project filter and the policy each
  still stop the cross-tenant read.
- Also delete the `authorize(...)` call at the end of `authz.authorize_document`. Now four
  tests fail, including `test_foreign_project_id_under_own_org_url_is_404` and
  `test_intra_tenant_private_document_is_invisible_to_other_editor`. The suite only goes red
  when two independent layers are gone, and it says which attack got through.

---

## 2. "Walk me through refresh token rotation. What happens when an attacker steals one? What about two tabs refreshing at once?"

Answer (`src/apiguard/refresh.py::rotate`):

- Login starts a family (`start_family`). Each refresh locks the presented row with
  `SELECT ... FOR UPDATE`, marks it `used_at`, and inserts a new token in the same family.
- If the presented token already has `used_at`, two parties hold it. `revoke_family` sets
  `revoked_at` on every token in the family; the handler (`routers/auth.py::refresh_tokens`)
  commits that before returning 401 and writes a `refresh_token_reused` audit event in a
  separate transaction.
- Whichever of attacker and user refreshes second triggers the revocation; both are logged out
  and only the one with the password can log in again.
- Only SHA-256 of the token is stored. The token has 256 bits of entropy, so a slow hash adds
  nothing; a fast hash lets the lookup use a unique index.
- Two tabs at once: the row lock serialises them. The first rotates; the second sees a used
  token and is treated as reuse, which revokes the family, including the token the first tab
  just received. Net effect: the user is logged out. That is the strict choice. A grace window for the previous token
  would avoid it at the cost of giving a thief the same window. I chose strict and documented
  it (docs/ENGINEERING_DECISIONS.md, section 7).

Live:

```bash
uv run pytest "tests/security/test_api2_broken_authentication.py::test_refresh_token_reuse_revokes_the_whole_family" \
  "tests/security/test_api2_broken_authentication.py::test_concurrent_refresh_with_the_same_token_revokes_the_family" -v
```

The demo's "Authentication" block shows the same sequence over HTTP, and the
`refresh_token_reused` event appears in "alice's own security events".

---

## 3. "Your login returns the same message for unknown users. Is it really timing-safe? How do you know?"

Answer:

- Body, status and headers are identical (`routers/auth.py::login` raises one
  `HTTPException` for both cases).
- Timing: the expensive part is Argon2. `passwords.verify_login_password` verifies against
  `_DUMMY_HASH` when the account does not exist, so both paths do exactly one Argon2
  verification with the same parameters.
- How I know: `tests/security/test_api2_broken_authentication.py::test_login_failure_is_identical_for_unknown_email_and_wrong_password`
  counts verifications on both paths and compares responses.
- What I do not claim: that response times are statistically indistinguishable. The user lookup
  by email and the audit write still differ slightly. I did not measure timing, because a
  timing test on shared CI runners would be flaky; the README lists this as a limitation.
- Membership goes through invitations, which look nothing up and return the same fields for
  any email (`routers/invitations.py::create_invitation`), so "create an org, then probe
  emails" does not work; the invitee has to accept with the one-time token.
- One enumeration point remains and is documented: registration returns 409 for a taken
  email. Closing it needs email verification.

Live:

```bash
uv run pytest tests/unit/test_passwords.py tests/security/test_api2_broken_authentication.py -k "verification or identical" -v
```

---

## 4. "Why is the rate limiter in PostgreSQL? What are its failure modes? Isn't per-account lockout a denial-of-service vector?"

Answer (`src/apiguard/ratelimit.py`):

- One atomic statement per hit: `INSERT ... ON CONFLICT (key, window_start) DO UPDATE SET
  count = count + 1 RETURNING count`, in its own transaction, so a failed login still counts and
  every API process shares the count. `tests/integration/test_rate_limiter.py::test_concurrent_hits_are_counted_exactly`
  fires 20 threads at a limit of 5 and gets exactly 5 successes.
- `hit_all` increments every relevant counter before raising, so being over the IP limit does
  not stop the per-account counter from advancing.
- Failure modes: if PostgreSQL is down, the limiter raises and the request gets 503 (fail
  closed). Fixed windows allow up to 2x the limit across a boundary. Every attempt is two small
  writes, which is fine at login rates but would move to Redis at much higher volume.
- DoS: yes, per-account throttling lets someone who knows an email keep it at 429. That is why
  it is a short window that expires on its own, not a lockout that needs an administrator. The
  per-IP limit bounds how much of this one client can do. Written down in docs/THREAT_MODEL.md
  ("Lockout policy").
- Client IP is `request.client.host`; behind a proxy uvicorn's `--proxy-headers` with a trusted
  proxy list has to set it. Reading `X-Forwarded-For` directly would let clients choose their
  own rate-limit key.

Live:

```bash
uv run pytest tests/security/test_api4_unrestricted_resource_consumption.py tests/integration/test_rate_limiter.py -v
```

---

## 5. "An admin wants to become owner. A viewer has an 'edit' share. A member is demoted while holding a valid token. What happens in each case?"

Answer (`src/apiguard/policy.py`):

- Admin to owner: `decide_membership_change` lets admins act only on editors and viewers and
  grant only editor or viewer. Changing their own role to admin or owner, or touching an owner,
  is 403 (`test_admin_cannot_escalate_self`, `test_admin_cannot_demote_or_remove_owner`).
  Separately, `routers/orgs.py::_ensure_another_owner` locks the owner rows and refuses to
  remove or demote the last owner, even when an owner asks.
- Viewer with an edit share: `document_access` takes `min(granted, _ROLE_CEILING[role])`, and a
  viewer's ceiling is read. The share cannot lift them above their role
  (`test_edit_share_cannot_lift_viewer_above_role_ceiling`).
- Demotion with a valid token: tokens carry no roles. The next request resolves the membership
  again, so a demoted editor's edit share stops working immediately
  (`test_demotion_narrows_existing_share_immediately`), and a removed member gets 404
  (`test_removed_member_loses_access_immediately`). Removing a member also deletes their shares
  through the composite foreign key's `ON DELETE CASCADE`.
- Every one of these denials is audited with the request id
  (`test_denials_are_audited_with_the_request_id`); the role change itself is audited in the same
  transaction as the change.

Trade-off: an extra membership query per request in exchange for immediate revocation.

Live: the demo's "victor tries to edit the document -> 403" line, then:

```bash
uv run pytest tests/security/test_api5_broken_function_level_authorization.py tests/unit/test_policy_matrix.py -q
```

---

## Things to be ready to admit

- Single HS256 key, no `kid`, no rotation story beyond "change it and every access token dies
  within five minutes".
- No password reset or change, no email verification.
- The append-only trigger does not stop TRUNCATE or a superuser; database privileges must.
- No load testing was done; there are no performance numbers in this repository.
