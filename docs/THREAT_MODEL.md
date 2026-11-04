# Threat model

Scope: the apiguard HTTP API, its PostgreSQL database and its configuration. Out of scope: the
host, TLS termination, the reverse proxy and the network, which a deployment has to provide.

## Assets

| Asset | Why it matters |
| --- | --- |
| Document contents | tenant data; the main thing an attacker wants |
| Memberships and roles | control who can read and change everything else |
| Password hashes | offline cracking would expose reused passwords |
| Refresh tokens | long-lived session credentials |
| JWT signing key | anyone holding it can mint access tokens for any user |
| Audit log | the record needed to detect and investigate abuse |

## Actors

| Actor | Capabilities assumed |
| --- | --- |
| Anonymous internet client | can send any request, knows or guesses emails |
| Authenticated user of another tenant | has valid tokens; knows real ids of our objects (ids leak through URLs, logs, screenshots) |
| Low-privilege member of the same tenant (viewer, editor) | valid tokens and membership; wants more than their role grants |
| Admin of a tenant | wants owner rights, or rights over other admins |
| Holder of a stolen refresh or access token | has the token, not the password |
| Operator with database access | trusted for availability, not trusted to rewrite the audit trail silently |

## Trust boundaries

1. Client to API: every byte of the request is untrusted, including path ids, JSON bodies,
   `Authorization` and `X-Request-ID`.
2. API to database: the API is the only writer; the database enforces tenant consistency with
   composite foreign keys and audit immutability with a trigger, so a bug above it is not
   enough on its own to break those invariants.
3. Configuration to API: environment variables are trusted input but validated at startup.

## Threats, mitigations and tests

Test paths are relative to `tests/`.

| # | Threat (OWASP API 2023) | Mitigation | Tests |
| --- | --- | --- | --- |
| T1 | Read/modify another tenant's document by id (API1) | membership resolved per request (`authz.resolve_actor`); loaders filter by org and project (`authz.authorize_document`); invisible resources answer 404 identical to a missing id | `security/test_api1_bola.py::test_cross_tenant_document_read_is_404`, `::test_cross_tenant_document_update_and_delete_change_nothing`, `::test_404_for_foreign_document_is_identical_to_404_for_missing_document` |
| T2 | Put a foreign id under an org the attacker does belong to (API1) | loaders filter by the URL's org *and* project together | `security/test_api1_bola.py::test_foreign_document_id_under_own_org_url_is_404`, `::test_foreign_project_id_under_own_org_url_is_404`, `::test_document_under_wrong_project_of_same_org_is_404` |
| T3 | Read a colleague's private document in the same tenant (API1) | document access requires ownership, a share or a manager role (`policy.document_access`) | `security/test_api1_bola.py::test_intra_tenant_private_document_is_invisible_to_other_editor` |
| T4 | List endpoint leaks what GET hides (API1) | listings filter with `policy.visible_documents_clause`; the two rules are compared exhaustively | `integration/test_policy_sql_agreement.py::test_listing_filter_matches_per_object_decision` |
| T5 | Share a document into another tenant (API1) | API checks membership; composite FK `document_shares(org_id, user_id) -> memberships` | `security/test_api1_bola.py::test_cannot_share_with_a_user_from_another_tenant`, `::test_database_rejects_cross_tenant_share_even_without_the_api` |
| T6 | Forged access token: `alg=none`, another algorithm, another key (API2) | PyJWT with `algorithms=["HS256"]` and the configured key only | `security/test_api2_broken_authentication.py::test_alg_none_token_is_rejected`, `::test_token_signed_with_another_key_is_rejected`, `unit/test_tokens.py::test_algorithm_outside_allow_list_is_rejected` |
| T7 | Stale or misdirected token: expired, wrong audience/issuer/type, missing claims (API2) | required claims `exp iat nbf iss aud sub jti`, `typ=access` | `security/test_api2_broken_authentication.py::test_expired_token_is_rejected`, `::test_token_for_another_audience_or_issuer_is_rejected`, `unit/test_tokens.py::test_missing_required_claim_is_rejected` |
| T8 | Stolen refresh token replayed (API2) | rotation on every use; reuse of a used token revokes the whole family. `FOR UPDATE` serialises concurrent refreshes with one token: the second is treated as reuse and revokes the family, including the token the first just received, so two tabs refreshing at once log the user out (accepted trade-off: there is no grace window for a thief either) | `security/test_api2_broken_authentication.py::test_refresh_token_reuse_revokes_the_whole_family`, `::test_concurrent_refresh_with_the_same_token_revokes_the_family` |
| T9 | Refresh tokens read from a database dump | only SHA-256 of 256-bit random tokens is stored | `integration/test_auth_flow.py::test_refresh_rotates_and_old_token_stops_working` |
| T10 | User enumeration through login (API2) | identical status, body and headers; one Argon2 verification against a dummy hash for unknown emails | `security/test_api2_broken_authentication.py::test_login_failure_is_identical_for_unknown_email_and_wrong_password`, `unit/test_passwords.py::test_unknown_account_still_costs_one_verification` |
| T11 | Offline cracking of leaked hashes | Argon2id, RFC 9106 low-memory parameters (argon2-cffi defaults), rehash on login if parameters change | `unit/test_passwords.py::test_production_hashes_are_argon2id_with_rfc9106_low_memory_parameters`, `::test_needs_rehash_detects_weaker_parameters` |
| T12 | Mass assignment of `org_id`, `owner_id`, `role`, `password_hash` (API3) | request models with `extra="forbid"`; handlers set server-owned fields from the URL and token | `security/test_api3_broken_object_property_level_authorization.py::test_document_create_rejects_server_controlled_fields`, `::test_document_update_rejects_server_controlled_fields`, `::test_registration_cannot_set_role_or_hash` |
| T13 | Responses expose hashes or internal fields (API3) | explicit response models | `security/test_api3_broken_object_property_level_authorization.py::test_responses_never_contain_secrets` |
| T14 | Online password guessing and spraying (API4) | per-account and per-IP fixed windows in PostgreSQL; 429 with `Retry-After` | `security/test_api4_unrestricted_resource_consumption.py::test_login_is_limited_per_account`, `::test_login_is_limited_per_ip`, `integration/test_rate_limiter.py::test_concurrent_hits_are_counted_exactly` |
| T15 | Refresh token guessing, registration floods (API4) | per-IP limits on refresh and register, per-account limit on refresh | `security/test_api4_unrestricted_resource_consumption.py::test_refresh_is_limited_per_ip`, `::test_refresh_is_limited_per_account`, `::test_registration_is_limited_per_ip` |
| T16 | Large inputs and pages (API4) | field length limits, password max 128, `limit <= 100` | `security/test_api4_unrestricted_resource_consumption.py::test_page_size_is_bounded`, `::test_oversized_fields_are_rejected`, `::test_oversized_password_is_rejected_before_hashing` |
| T17 | Calling manager functions as editor/viewer (API5) | `policy.ORG_ACTION_ROLES`, enforced by `authz.authorize_org` | `security/test_api5_broken_function_level_authorization.py::test_non_managers_cannot_manage_projects`, `::test_non_managers_cannot_manage_members`, `::test_non_managers_cannot_read_the_audit_log` |
| T18 | Admin escalates to owner/admin or acts on owners (API5) | `policy.decide_membership_change` | `security/test_api5_broken_function_level_authorization.py::test_admin_cannot_escalate_self`, `::test_admin_cannot_grant_admin_or_owner`, `::test_admin_cannot_demote_or_remove_owner` |
| T19 | Share lifts a viewer above their role; stale rights after demotion or removal (API5) | role ceiling in `policy.document_access`; roles read per request, not from the token | `security/test_api5_broken_function_level_authorization.py::test_edit_share_cannot_lift_viewer_above_role_ceiling`, `::test_demotion_narrows_existing_share_immediately`, `security/test_api1_bola.py::test_removed_member_loses_access_immediately` |
| T20 | Organisation left without an owner | handler locks owner rows and refuses the last demotion/removal | `integration/test_documents_and_projects.py::test_last_owner_cannot_leave_or_be_demoted` |
| T21 | Deployment with a weak or placeholder signing key (API8) | settings validation refuses to start outside test mode; the key is not echoed in the error | `security/test_api8_security_misconfiguration.py::test_app_refuses_to_start_with_a_weak_key`, `unit/test_config.py::test_weak_keys_are_refused_outside_test_mode`, `::test_rejected_key_is_not_echoed_in_the_error` |
| T22 | Permissive CORS, exposed docs, missing headers (API8) | CORS only for listed origins; docs off by default; header middleware | `security/test_api8_security_misconfiguration.py::test_cors_is_off_by_default`, `::test_docs_and_schema_are_disabled_by_default`, `::test_security_headers_on_every_response` |
| T23 | Error responses leak internals; database outage | connection errors map to a generic 503, integrity conflicts (a lost uniqueness race) to 409, any other driver error to a generic 500; no driver text reaches clients | `security/test_api8_security_misconfiguration.py::test_database_outage_returns_503_without_details`, `integration/test_database_errors.py::test_losing_a_duplicate_share_race_returns_409` |
| T24 | Log injection through request ids | only `[A-Za-z0-9._-]{1,64}` is accepted, otherwise a new id is generated | `security/test_api8_security_misconfiguration.py::test_request_id_is_echoed_only_when_safe` |
| T25 | Abuse goes unnoticed or the trail is edited afterwards | failure events written in their own transaction; UPDATE/DELETE rejected by trigger | `integration/test_audit_log.py::test_audit_events_are_append_only`, `security/test_api5_broken_function_level_authorization.py::test_denials_are_audited_with_the_request_id` |
| T26 | Account enumeration and unwanted membership through invitations (API3, API6) | invitations are keyed by email and look nothing up, so the response is the same for any email and contains no profile data; membership needs the invitee to accept with a one-time token (stored as SHA-256) and an account with that email; invitations and accepts are rate limited per user | `security/test_api3_broken_object_property_level_authorization.py::test_invitation_response_does_not_reveal_whether_an_account_exists`, `integration/test_invitations.py::test_invitation_does_not_grant_membership_until_accepted`, `::test_token_only_works_for_the_invited_email`, `security/test_api4_unrestricted_resource_consumption.py::test_invitations_are_limited_per_actor` |
| T27 | Existence oracle through the caller's own audit events (API1) | missing and invisible documents produce the same 404 and the same audit row with a generic reason (`authz.authorize_document`, `authz.deny_not_found`) | `security/test_api1_bola.py::test_audit_trail_does_not_reveal_whether_an_invisible_document_exists` |
| T28 | Anonymous requests grow the database (API4) | one `rate_limited` row per key per window; every hit deletes finished windows of all keys | `security/test_api4_unrestricted_resource_consumption.py::test_a_flood_of_rejected_requests_writes_one_audit_row_per_window`, `integration/test_rate_limiter.py::test_finished_windows_of_other_keys_are_pruned_too` |
| T29 | Whitespace silently changes a password | passwords are used byte for byte at registration and login; only names, titles and the login email are trimmed | `integration/test_auth_flow.py::test_password_whitespace_is_significant` |

## Lockout policy

apiguard throttles; it does not lock accounts.

- Per account (`APIGUARD_LOGIN_LIMIT_PER_ACCOUNT`, default 5 per
  `APIGUARD_RATE_LIMIT_WINDOW_SECONDS`, default 60): every attempt for an email, successful or
  not, counts. Over the limit, the API answers 429 with `Retry-After` until the window ends,
  even for the right password, so guessing cannot continue in the background.
- Per IP (`APIGUARD_LOGIN_LIMIT_PER_IP`, default 20): bounds spraying one password over many
  accounts.
- Every counter is incremented before the request is rejected (`RateLimiter.hit_all`), so an IP
  that is already over its limit still uses up per-account budget.
- Counters live in PostgreSQL and are incremented in their own transaction, so they persist
  when the login itself fails and are shared by all API processes. If the database is down,
  login fails with 503 rather than skipping the limit.

Why not permanent lockout: it hands any attacker who knows an email a way to disable that
account until an administrator intervenes. Throttling limits guessing to a known rate while
the account recovers by itself. The residual risk (an attacker can keep one account throttled
while they keep sending requests) is listed in the README limitations.

## Residual risks and deployment requirements

- TLS and HSTS preload are the deployment's responsibility; the API sends HSTS but cannot
  enforce HTTPS itself.
- Behind a reverse proxy, run uvicorn with `--proxy-headers --forwarded-allow-ips=<proxy>` so the
  per-IP limits see client addresses; apiguard never reads `X-Forwarded-For` itself.
- Grant the application's database role only INSERT and SELECT on `audit_events`. The trigger
  stops UPDATE and DELETE for every role, but not TRUNCATE or a superuser disabling triggers.
- The signing key must come from a secret store; anyone with it can impersonate any user until
  it is changed, and changing it ends every access token (at most `access_token_ttl_seconds`).
- Registration (409) reveals whether an email has an account. Emails are not verified;
  invitation tokens are handed to the inviter to pass on, which a real deployment would
  replace with email delivery.
- Growth bounded by rate: failed logins, registrations and denied authenticated requests
  each add rows; the README limitations give the exact bounds.
- Security-relevant time checks (token expiry, refresh expiry, rate-limit windows) use the API
  host's clock. `created_at`/`updated_at` columns use the database clock. During development the
  Docker VM clock was about 70 s ahead of the host, which is why the two are never compared.
