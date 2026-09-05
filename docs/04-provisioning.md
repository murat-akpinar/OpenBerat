# 04 — Provisioning and Deprovisioning

The phrase "automatic provisioning based on my entitlements" actually covers
**two separate** jobs. Conflating them breaks the design.

## Two different kinds of provisioning

| # | What | Where it happens | Do we write it? |
|---|---|---|---|
| **A** | **Identity provisioning** — does the user account exist, what are its groups | Keycloak ↔ AD (LDAP federation) | **No**, Keycloak does it |
| **B** | **Access provisioning (entitlement)** — which applications does this user see | Our PDP + sync | **Yes**, this is the actual work |

A is off the shelf. The project is B and nothing else.

## B: AD group → application access

The core mapping, a single table:

```
AD group                 →  application         →  effect
────────────────────────────────────────────────────────
OpenBerat-Finance             →  sap-portal          →  allow
OpenBerat-Finance             →  bi-dashboard        →  allow
OpenBerat-IT-Admin            →  * (all)             →  allow
OpenBerat-Intern              →  prod-admin          →  deny
```

When a user logs in:
1. The `groups` claim is read from the token
2. All entitlements matching those groups are collected
3. If there is a deny, deny wins; otherwise the allows are unioned
4. The result is the user's list of reachable sites

There is no separate "create user" step. **The access list is derived on every
request**, never stored.

But **where** the group membership is read from is critical — see "The stale
group problem" below. This is the easiest part of the design to get wrong.

## JIT (Just-In-Time) provisioning

Nothing needs to be prepared the first time a user touches the system, because
in the model above there is no persistent record belonging to the user.

A first-sight record is only worth opening for:
- Last login time (for reporting)
- A user-specific exception entitlement (per person rather than per group)

## The stale group problem

> **Correction.** The first version of this section claimed there were three
> staleness layers and that the delays added up. Research showed that was wrong —
> Keycloak reads group membership **live** from LDAP. Decision:
> [ADR-0006](adr/0006-group-membership-source.md).

Group information goes stale in exactly **one place** in the chain:

| Layer | Goes stale? | Why |
|---|---|---|
| Active Directory | — | Source of truth |
| Keycloak | **No** | Reads group membership live from LDAP on login and token refresh |
| **oauth2-proxy** | **Yes** | Groups come from the ID token at login time and freeze into the session |
| backend decision cache | Yes | Our TTL. The identity resolution lives in the same entry (`docs/05`) — one TTL, not a separate layer. |

### Dangerous defaults

oauth2-proxy's default settings are **silently wrong** for this project:

| Setting | Default | Consequence | Should be |
|---|---|---|---|
| `set_xauthrequest` | `false` | No identity or group header arrives at all | `true` |
| `cookie_refresh` | off | The session lives as long as `cookie_expire` → **168 hours** of stale groups | `5m` |
| `session_store_type` | `cookie` | Kill switch impossible + the 4 KB cookie limit | `redis` |
| `cookie_expire` | `168h0m0s` | 7 days | Shorten per policy |

`cookie_refresh` is not supported for every provider in oauth2-proxy, but
**Keycloak is supported** (along with ADFS, Azure, GitLab, Google and providers
with a full OIDC implementation).

> **`cookie_refresh` is the single most critical configuration line in this
> project.** Delete it and the system does not error; it silently keeps running
> on week-old entitlements. This is why it will be covered by a configuration
> test (Phase 1).

### Consequence

Deprovisioning delay = `cookie_refresh` + decision cache TTL. Two numbers.
To be measured in Phase 1 and compared against the N-03 target.

The backend connecting directly to AD (path B) **was not needed**, but it was
not abandoned either — it reopens if one of the three triggers in ADR-0006 fires.

## Group identity: name or SID?

`entitlement.subject_id` currently holds the AD group **name**, because both
Keycloak's group mapper and oauth2-proxy carry the group **name**.

The danger is not renaming — it is **recreation**:

> The group `OpenBerat-Finance` is deleted. Months later another team creates an
> unrelated group with the same name. Every member of that group silently
> inherits all of the old group's entitlements.

In AD, `objectSid` is immutable; names change and can be reused. Matching by
name is therefore a structural security weakness.

**Mitigation options:**
- Record the group's SID as well when the entitlement is created (read from
  LDAP); keep deciding by name, but have a periodic job audit the name↔SID
  pairing, disabling the entitlement and raising an alert if it breaks.
- If ADR-0006's path B is triggered we will already be talking to LDAP; matching
  directly by SID then removes the problem entirely.

**Current state:** name matching is **accepted debt**
([ADR-0008](adr/0008-group-identity-name.md)), mitigated by the `OpenBerat-`
prefix convention and change control over group deletion and creation.

## Deprovisioning

Cutting access matters more than granting it. Three scenarios:

| Scenario | How it is cut | Delay |
|---|---|---|
| Account disabled in AD | The `userAccountControl` filter; Keycloak rejects the session on refresh | `cookie_refresh` + cache TTL |
| Removed from a group in AD | The refreshed session carries the new `memberOf` | `cookie_refresh` + cache TTL |
| Emergency revocation (incident response) | Kill switch from the admin UI | **Immediate** (ADR-0016: ≤ 5 s) |
| Active WebSocket/SSE connection | Not cut — authorised once at the upgrade | **Outside the guarantee** (`docs/02`) |

An earlier version of this table gave the account-disabled row a delay of only
`cookie_refresh`. That was wrong: on a decision-cache hit the backend never
calls oauth2-proxy, so a disabled account keeps its access for the cache TTL on
top of `cookie_refresh`, exactly like a group removal. Both rows are the same
two numbers.

### Design decisions

1. **Keycloak access token TTL is short** (5 min).
2. **`cookie_refresh` must be set** (ADR-0006). If it is not, the session lives
   for 7 days with its original groups.
3. **The oauth2-proxy session must be in Redis** (`--session-store-type=redis`).
   A session held inside a cookie **cannot** be revoked server-side — the kill
   switch would not work.
4. **The kill switch acts in two places:** the Keycloak Admin API `logout-all`
   **and** deleting the oauth2-proxy session from Redis. Skipping either
   silently neuters it. Redis is keyed by ticket rather than by user, so
   finding that session requires the backend's `sub → session` index
   ([ADR-0019](adr/0019-kill-switch-session-index.md)).
5. **The kill switch drops only that user's decision-cache entries**, through
   the `sub → keys` reverse index. Clearing the whole cache is self-DoS
   (`docs/05`). The full order is four steps and fixed — Keycloak → session
   keys → cache entries → index entry (ADR-0019) — and dropped entries flush
   their audit counters first (`docs/02`).

### The test that measures the delay (acceptance criterion)

> Disable a user in AD / remove them from a group.
> How many seconds later do they lose access to the protected application?

The two numbers are measured separately (disabled ≠ removed from group) and
compared against the N-03 target. This is a Phase 6 exit criterion.

## Is SCIM needed?

**No** in v1. SCIM is for an IdP pushing users into target applications
(e.g. Keycloak → create an account in Jira). Our system is not a target
application; it is the door in front of them. A door does not create accounts in
the rooms behind it.

It becomes necessary the moment accounts should also be created automatically in
the applications reached through the portal. That is a different project
(Identity Governance & Administration — IGA).

## Per-person exception

A time-limited entitlement for one person outside any group ("two hours of prod
access for Ahmet"):
- `subject_type='user'` + `expires_at` in the `entitlement` table
- Expired records are automatically invalid (`expires_at > now()` in the query)
- This is the simple form of **JIT access** from the PAM world

**Not in v1** — F-20, v2. The `known_user` table and person selection in the
admin UI arrive with it. Approval workflow comes later still.
