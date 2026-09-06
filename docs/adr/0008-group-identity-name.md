# 0008 — Group identity: match by name in v1

- **Status:** Accepted
- **Date:** 2026-09-05

## Context

`entitlement.subject_id` has to hold something that identifies an AD group. What
it holds is `0001_init.sql`'s business, and changing it later means a migration
plus an audit problem — so it has to be settled before Phase 2.

The danger with names is not renaming, it is **recreation**: delete
`OpenBerat-Finance`, let another team create an unrelated group with the same
name months later, and every member of that group silently inherits the old
group's entitlements. In AD, `objectSid` is immutable; names change and can be
reused.

## Options

| Option | Pro | Con |
|---|---|---|
| **A — name** | The only thing we actually have: both Keycloak's group mapper and oauth2-proxy carry names | A recreated group inherits entitlements |
| B — SID | Immutable, no recreation risk | Requires reading LDAP, which ADR-0006 path A deliberately does not do |
| C — name + SID recorded, decide by name, audit the pairing | Detects drift | Still needs an LDAP connection to read the SID in the first place |

## Decision

**A — match by name.** Not because it is the best option, but because ADR-0006
already decided the backend does not talk to LDAP. Without an LDAP connection
there is no SID to store, so B and C are not available without reopening
ADR-0006. Adding an AD dependency and a service account secret to the backend to
close a recreation hole is a worse trade than the hole.

`entitlement.subject_id` holds the group name as a plain string, and the schema
carries no SID column. A nullable column that nothing ever writes is exactly the
"we might need it later" field the project forbids (`CONTRIBUTING.md`).

## Mitigations, which are the only thing making this acceptable

1. **A group name prefix.** Groups that grant access through this product are
   named `OpenBerat-<scope>` (e.g. `OpenBerat-Finance`, `OpenBerat-Admins`). The
   prefix does three jobs: it keeps the `groups` claim small (`docs/03`, token
   bloat), it narrows the authorisation surface, and it makes the blast radius
   of a recreated group visible to whoever administers AD. The prefix lives in
   the Keycloak group mapper filter — customer configuration, not our code.

   **It does a fourth job that was not known when this ADR was written, and it
   is the reason the filter is now mandatory rather than advisable.** The group
   list travels comma-joined in one header and is split back apart in the
   backend, so one group *named* `Payroll,OpenBerat-Admins` arrives as two and
   the second is `ADMIN_GROUP`. Measured on the lab: an ordinary portal user in
   that single group reached `/api/admin/*` and created a wildcard entitlement
   (`docs/07`, "A comma in a group name is the management plane"). The backend
   cannot detect it — oauth2-proxy flattens the claim array before the request
   arrives — so the filter, which matches the whole `cn` against `OpenBerat-*`
   and rejects that name, is the control. An installation that skips it has an
   escalation path, not merely a large token.
2. **Change control on deletion and recreation** of prefixed groups, on the AD
   side. This is an operational control, written into the installation
   documentation, not something the software can enforce.
3. **`ADMIN_GROUP` defaults to `OpenBerat-Admins`** and is supplied through the
   environment (`docs/02`, "Management plane"). It follows the same convention
   but is deliberately a separate variable, so a customer with a fixed AD naming
   policy can point it anywhere.

## Consequences

- The recreation hole is **accepted, documented debt**, not a solved problem. It
  belongs in the risk section of any security review of this product. So does
  the comma above: both are consequences of identifying a group by a string
  somebody else controls.
- The decision is unchanged — matching by name still costs less than an LDAP
  dependency — but mitigation 1 is no longer optional, and `INSTALL.md` has to
  say so where it configures the mapper.
- If ADR-0006's path B is ever triggered, SID matching comes for free and this
  ADR is superseded rather than patched.
- The `ZTNA-` prefix used in earlier drafts is replaced by `OpenBerat-`: the
  prefix names the product that reads the group, and `ZTNA` names a category
  that a customer may already be using for something else.
- Renaming a group in AD **does** break its entitlements — that is the cost of
  the same choice, and it is the safe direction to fail in.
