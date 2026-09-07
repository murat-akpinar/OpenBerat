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
   arrives — so the filter is the control. An installation that skips it has an
   escalation path, not merely a large token. Verified against a real LDAP
   filter and its control case (`docs/07`): with the filter in place the name is
   in AD, in the user's `memberOf` and absent from the claim; with it emptied
   the same account reaches `/api/admin/*`.

   **The prefix half of that filter is not the whole control, and this ADR said
   it was.** `(cn=OpenBerat-*)` rejects `Payroll,OpenBerat-Admins` because that
   name does not carry the prefix — which is the name the measurement used. Put
   the prefix in front of it and the same attack passes the same filter:
   `OpenBerat-Payroll,OpenBerat-Admins` is selected by `(cn=OpenBerat-*)`, enters
   the claim, and splits into a group nobody granted and `ADMIN_GROUP`. Measured
   against a directory holding all three names, and then end to end on the lab:
   with the old filter a non-admin in that one group reads `admin: true` and
   gets **200** from `/api/admin/applications`; with the two-clause one the claim
   does not carry the name at all (`docs/07`). The filter is
   `(&(cn=OpenBerat-*)(!(cn=*,*)))` now: the prefix bounds what the claim may
   name and the second clause is what actually closes the comma. A prefix is a
   naming convention; the comma is the injection, and only the second clause
   speaks to it.
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
  ADR is superseded rather than patched. **Measured since (2026-09-07,
  `docs/07`): not on the current path.** Keycloak will import a group's
  `objectSid` if asked, but it reads the binary attribute as text — 28 raw bytes
  arrive as a 13-character string with four U+FFFD replacement characters in it,
  which is not an identifier — and no stock protocol mapper emits a group
  attribute into a token in the first place. So the alternative this ADR
  described as "available if we reopen ADR-0006" needs a custom Keycloak mapper
  as well.
- The `ZTNA-` prefix used in earlier drafts is replaced by `OpenBerat-`: the
  prefix names the product that reads the group, and `ZTNA` names a category
  that a customer may already be using for something else.
- Renaming a group in AD **does** break its entitlements — that is the cost of
  the same choice, and it is the safe direction to fail in.
- **The comma now has a second consumer.**
  [ADR-0021](0021-application-identity-trusted-headers.md) hands the same
  comma-joined header to the protected application, which splits it exactly as
  the backend does. Mitigation 1 is the control for both, and an installation
  that widens the filter widens it inside every application behind the proxy,
  not only inside `/api/admin/*`.
