# 0034 — A read-only group for the management plane

- **Status:** Accepted
- **Date:** 2026-09-17
- **Relates to:** [0008](0008-group-identity-name.md) — the new group is matched
  the way `ADMIN_GROUP` is, and inherits both of its mitigations.
  [0026](0026-audit-explain-screen-in-v1.md) and
  [0033](0033-admin-write-screens.md) — the reading half and the writing half
  this decision separates.
- **Supersedes in part:** [0032](0032-admin-mfa.md) — its "and for nobody else".
  The second factor now covers this group too; the flow is unchanged.

## Context

F-12 binds the whole of `/api/admin/*` to one group. Somebody whose job is to
read — an internal auditor, a KVKK reviewer, the person answering "why was this
user denied" on a helpdesk — has to be put in `ADMIN_GROUP` to do it, and then
holds a wildcard entitlement one POST away. The SSO roadmap `TODO.md` was read
against splits the management role six ways (§14.1) and asks for least
privilege (§14.2). Five of those six roles — realm, client, user, security and
integration administration — are Keycloak's own admin console and not this
product's. The sixth, the auditor, is ours and is missing.

The seam is already cut. The guard in `admin.rs` already treats `GET`/`HEAD`
differently from everything else: only state-changing calls are
`Origin`-checked, which is only safe because nothing under `/api/admin/*` writes
on a `GET`. The reading endpoints are `applications`, `entitlements`, `audit`,
`sessions` and `explain`; the writing ones are the application and entitlement
CRUD and the kill switch.

## Options

| Option | Pro | Con |
|---|---|---|
| A — one group, as today | Nothing to write | Reading the audit record requires the power to rewrite who reaches what. The least-privilege request has no answer |
| **B — a second group that reaches every `GET`/`HEAD` under `/api/admin/*`** | One condition, in the one guard every management route already passes, on the split the `Origin` check already relies on | A `GET` added later is readable by the auditor the day it lands, whatever it returns |
| C — a second group with a per-route allowlist | Explicit about each route | A second list beside the router. The router is the list the existing enumeration test already reads; a copy of it is the one that drifts |
| D — roles in the database | Any number of roles | The first admin cannot come from a table nobody can write to yet (ADR-0008), and a role engine is the RBAC §14.1 describes — Keycloak's, not ours |

## Decision

**B.** `AUDITOR_GROUP`, from the environment and never from the database,
defaulting to `OpenBerat-Auditors`. A member reaches every `GET` and `HEAD`
under `/api/admin/*` and is refused everything else, the kill switch included.
`ADMIN_GROUP` stays a superset: a member of both is an admin.

B's one cost is the right one to carry. A `GET` that exposes something an
auditor should not see would be a new endpoint, and the integration suite
already enumerates every management route precisely so that a new one cannot
arrive unnoticed — it now asserts the auditor's answer for each of them, so
adding a route means stating that answer. A `GET` that *wrote* would already be
a hole today, because the `Origin` check does not run on it.

**The group carries the second factor.** The export maps `openberat-mfa` onto
`OpenBerat-Auditors` as well as onto `OpenBerat-Admins`, so ADR-0032's flow asks
both for TOTP. ADR-0032 argued from "the account that can change who reaches
what", and this account cannot. It reads the three things an attacker needs
first, though: every user's access history with source addresses, the complete
map of who may reach what (`explain`), and who is signed in right now. That is
personal data as well as reconnaissance. And a read-only group is the one most
likely to be handed to a script; a second factor keeps it interactive, and the
script's route to the same records is the F-14 log stream.

## Consequences

- **F-15 in `docs/06`**, and `GET /api/me` gains an `auditor` flag beside
  `admin`. The header link to the management screen is drawn for either — a
  convenience, like the flag it reads.
- **The screen hides nothing from an auditor.** All five tabs draw; a save or a
  delete answers 403 with a sentence that names the read-only group as one of
  its causes. ADR-0033's rule that the page hides nothing is unchanged: the
  guard is the refusal, and a page that hid the forms would be a second copy of
  the guard's rule.
- **Three names have to agree now, and no code can check it:** `ADMIN_GROUP`,
  `AUDITOR_GROUP`, and the groups `openberat-mfa` is mapped onto. An
  installation that renames the auditor group and does not map the role reads
  the audit record with one factor. `INSTALL.md` §4 carries the line.
- **The group has to pass the group filter**, the same trap ADR-0008 describes
  for `ADMIN_GROUP` — but it fails in the safer direction: the auditor loses
  reading and nobody loses writing. The comma attack is the same one, one step
  less valuable: `OpenBerat-X,OpenBerat-Auditors` would read rather than write,
  and `(!(cn=*,*))` closes it for both.
- **Under ADR-0023 this is MINOR** — a new variable with a default, and the
  existing configuration keeps working. Changing what either group means is
  MAJOR, and that row now names both.
- **Two groups with fixed meanings, not a role system.** A third kind of admin —
  an application owner who manages one application's entitlements, say —
  reopens this ADR rather than extending it, because it needs per-row scope and
  a method split cannot express that.
- **Revocation stays with `ADMIN_GROUP`.** Seeing a session on the Live tab and
  being able to end it are deliberately different grants.
