# 0036 — Resetting a user's second factor from the management plane

- **Status:** Accepted.
- **Date:** 2026-09-18
- **Relates to:** [0035](0035-mfa-for-every-user.md) — the change that made this
  a routine task rather than a rare one, and named the reset path as work it did
  not do. [0032](0032-admin-mfa.md) — its answer, the Keycloak admin console
  under `KC_ADMIN_PASSWORD`, is what this replaces for ordinary users and keeps
  for privileged ones. [0024](0024-no-admin-ui-in-v1.md) — a destructive
  management action stays a terminal call for a privileged target. [0019](0019-kill-switch.md)
  — the service account and the header identity this reuses. [0034](0034-read-only-management-group.md)
  — why `AUDITOR_GROUP` cannot reach this. [0028](0028-live-sessions-endpoint.md)
  — the one place a person appears, and why it does not help here.

## Context

[ADR-0035](0035-mfa-for-every-user.md) made a second factor a property of every
login, and in the same breath made a lost or replaced phone a routine helpdesk
task rather than a rare one. It named the reset path as work it did not do, and
left the mechanism measured but unbuilt.

[ADR-0032](0032-admin-mfa.md)'s answer — the Keycloak admin console under
`KC_ADMIN_PASSWORD`, delete the credential, next login re-enrols — was sized for
two to five administrators. For a whole directory it makes a routine task reach
for the realm-master credential, and a credential reached for often is a
credential that gets shared. The reset has to move to the management plane, on
the identity the management plane already trusts.

The mechanism was already measured, and re-measured on the lab before this was
written, with the backend's own service account (the one the kill switch uses,
`openberat-backend`, `manage-users`):

| Call | Result |
|---|---|
| `GET /admin/realms/openberat/users?username=<u>&exact=true` | **200**, the user, whose `id` is the `sub` |
| `GET /admin/realms/openberat/users/{id}/groups` | **200**, `[{"name":"OpenBerat-Finance", …}]` |
| `GET /admin/realms/openberat/users/{id}/credentials` | **200**, `type: "otp"` beside `password` when one is enrolled |
| `DELETE …/credentials/<nonexistent>` | **404**, not 403 — the permission is held |

The second row is the one that was in doubt. Group membership reaches the token
through the `memberOf` attribute strategy ([ADR-0006](0006-group-membership-source.md)),
not through Keycloak groups, so it was not obvious the admin API would report a
federated user's AD groups at all. It does: the LDAP group mapper still writes
the membership into Keycloak, and `/users/{id}/groups` returns the `OpenBerat-`
names. The privileged-target guard below can therefore read a target's groups
the same way the token carries them.

**No new secret, role, or compose change.** Only the HTTP surface is added.

## Decision

Two endpoints, both `ADMIN_GROUP` only and `Origin`-checked by the guard
`admin.rs` already runs on every route — which refuses `AUDITOR_GROUP` on
anything that is not a `GET`/`HEAD` ([ADR-0034](0034-read-only-management-group.md)),
so the read-only group reaches the list and not the reset without a new check:

- **`GET /api/admin/users?search=&page=`** — the directory, read **live from
  Keycloak**, not stored. Each row is a username, an email and a **privileged**
  flag; paged with Keycloak's `first`/`max` and filtered with its `search`.
- **`POST /api/admin/reset-second-factor`, body `{"username": "<sAMAccountName>"}`**
  — resolves the username, deletes every `otp` credential the user holds, and
  the next login sends them back to enrolment.

**The list is a view of Keycloak's directory, not a directory of our own.** The
subject of a reset is, by definition, someone who cannot log in — so the one
place a person otherwise appears, the Live tab over the kill-switch index
([ADR-0028](0028-live-sessions-endpoint.md)), is exactly where they are not. A
list is therefore needed, and the honest way to build one is to read the
directory that already exists rather than to keep a second copy: `GET
/api/admin/users` projects Keycloak's own user list and stores nothing. This is
**not** `known_user`, which stays on `Later` — that is a product-managed table of
users the system has decided things about; this is a read-through to the
identity provider, the same service account and the same live-truth stance the
kill switch takes.

**The privileged flag is computed once per page, not per user.** Reading every
listed user's groups would be a call each; instead the members of `ADMIN_GROUP`
and `AUDITOR_GROUP` are fetched once (two calls) and a row is privileged if its
username is among them. The flag disables the row's reset button — a convenience,
not the control: the backend re-reads the target's own groups on the reset
itself and never trusts the list.

Three refusals, all fail-closed and all terminal — no override flag, the way
revocation had none ([ADR-0024](0024-no-admin-ui-in-v1.md)):

- **Self.** An admin resetting their own second factor is already past it, so
  they gain nothing a re-enrolment from their account settings would not — and a
  stolen admin session gains durability, swapping the thief's authenticator in
  for the victim's. Refused: the caller's `sub` is on the request
  (`X-Auth-Subject`), and the resolved target's `id` is the same value.
- **A privileged target** — anyone in `ADMIN_GROUP` or `AUDITOR_GROUP`. Reset is
  a way to take over an account: delete the factor, and whoever logs in next
  enrols theirs. For an ordinary user that is the point; for a management-plane
  account it is privilege escalation with a helpdesk ticket, so it stays a
  terminal call made at the Keycloak console under `KC_ADMIN_PASSWORD` — which
  is exactly the set ADR-0032's answer was sized for. The target's groups are
  read from `/users/{id}/groups` and matched against `ADMIN_GROUP` and
  `AUDITOR_GROUP` by exact name, the same comparison the guard uses.
- **A read the backend cannot make.** If resolving the username, reading the
  groups, or listing the credentials does not answer, the call refuses rather
  than proceeds — a reset that cannot first prove the target is not privileged
  is a reset that must not run.

**Idempotent.** A user with no `otp` credential is not an error: the reset's
whole effect is "the next login enrols", and that is already true. It answers
`200` and says nothing was enrolled, so a second click, or a race with the user
enrolling, is safe.

**Audited like every management-plane write** — the structured `admin` log line
ADR-0019's kill switch and every `create_*`/`delete_*` already emit: `actor`,
`action = "reset_second_factor"`, `target` (the username), `outcome`, and the
count of credentials removed. Not `audit_event`: that table is decision
summaries with an immutable format (`docs/02`).

## Consequences

- **A phone reset no longer touches the realm-master credential.** It is an
  `ADMIN_GROUP` member acting through the same session and Origin the rest of the
  management plane uses, recorded the same way.
- **A privileged account's reset still does.** That is deliberate, and the
  Keycloak console under `KC_ADMIN_PASSWORD` — ADR-0032's mechanism — is kept for
  exactly the accounts this refuses. The break-glass shape does not change.
- **The admin UI gains a Users tab.** A searchable, paged list of Keycloak's
  own users, each row a reset — disabled for a privileged user and for the
  caller. It reads through to Keycloak and stores nothing, so `known_user`, a
  product-managed user table, stays on `Later`: this is a view of the identity
  provider's directory, not a directory of our own.
- **The list adds a Keycloak read on the management path, and it is unbounded
  by design.** `GET /api/admin/users` is paged, but a directory can be large and
  the two group-member reads grow with the privileged groups. It is on the
  management plane, not the decision path, so it spends no N-01/N-02 budget — but
  it is the first admin endpoint whose cost scales with the directory rather than
  with what the operator typed.
- **A username that does not resolve answers `404`.** An admin who typos a name,
  or names a user Keycloak has never seen, is told so rather than left wondering
  — the same distinction the kill switch draws between `NoSuchUser` and an
  outage ([ADR-0019](0019-kill-switch.md)).
- **The service account's blast radius grows by one verb.** It could already
  read users and groups and log sessions out; it now deletes a credential. It
  still cannot set a password, read one, or touch anything but the `otp`
  credential type, and the endpoint deletes nothing else.

## Measured

`verify-resetmfa.sh` on the lab (`docs/07`): `GET /api/admin/users` lists the
directory for `ADMIN_GROUP`, marks the privileged rows, and answers `AUDITOR_GROUP`
(a read) but not an anonymous caller; the reset then has an `ADMIN_GROUP` member
clear an ordinary user's second factor and the user meets enrolment on the next
login, while the same call refuses `AUDITOR_GROUP` (403), refuses the caller's
own username (403), refuses a target in `ADMIN_GROUP`/`AUDITOR_GROUP` (403),
answers 404 for a name that does not resolve, and is idempotent for a user with
no credential. The decision path is untouched — a reset changes who can enrol,
not who is entitled.
