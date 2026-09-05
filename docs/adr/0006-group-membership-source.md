# 0006 — Group membership source: the oauth2-proxy header + mandatory `cookie_refresh`

- **Status:** Accepted
- **Date:** 2026-09-05

## Context

The authorisation decision rests on AD group membership. Where should that
information reach the backend from?

The first analysis (`docs/04`) claimed there were three staleness layers and
that the delays added up. **Research partly disproved that:**

| Layer | My first assumption | Verified reality |
|---|---|---|
| Keycloak | "Group membership comes from a cache, stale by the sync period" | **Wrong.** Keycloak reads group membership **live** from LDAP; it queries AD on login and on token refresh. |
| oauth2-proxy | "Stale for 7 days unless `cookie_refresh` is set" | **Right, and worse.** `cookie_expire` defaults to `168h0m0s` and `cookie_refresh` defaults to **off**. |
| Decision cache | Our TTL | Right |

So all of the staleness is in **one place**: the oauth2-proxy session. And
oauth2-proxy **does support** `cookie_refresh` for Keycloak (along with ADFS,
Azure, GitLab, Google and providers with a full OIDC implementation).

Also, `set_xauthrequest` defaults to `false` — without turning it on, no
identity or group header arrives at all.

## Options

| | A — trust the oauth2-proxy header | B — the backend queries LDAP itself |
|---|---|---|
| Extra code | None | LDAP client, connection pool, error handling |
| Extra secret | None | The service account bind credentials live in the backend |
| Freshness | As fresh as `cookie_refresh` (configurable, e.g. 5 min) | As fresh as the cache TTL (e.g. 30 s) |
| Matching by group SID | Impossible (the header carries a name) | Possible |
| Who guarantees freshness | The oauth2-proxy configuration | Our code |
| Failure surface | A component already in the chain | One more dependency (AD) |

## Decision

**Path A: `X-Auth-Request-Groups` will be used.** These three settings are
**mandatory** and cannot be removed from the configuration:

```
set_xauthrequest    = true      # default false — without it, no groups arrive
cookie_refresh      = "5m"      # default off — without it, 7 days of staleness
session_store_type  = "redis"   # default cookie — kill switch fails + 4KB limit
```

The first analysis thought this was a three-layer problem and that justified
path B (our own LDAP client). Once the layer count drops to one, B's benefit is
limited to "30 seconds of freshness instead of 5 minutes", while its cost is
adding an AD dependency and a service account secret to the backend. That trade
favours A.

**Path B was not abandoned, only untriggered.** It reopens if any of these
happens:
1. The Phase 1 measurement cannot hit the N-03 target even with `cookie_refresh`
2. A requirement to match on group **SID** becomes firm ([ADR-0008](0008-group-identity-name.md) accepted name matching only because this ADR closed the LDAP path)
3. Nested groups turn out not to resolve correctly through `memberOf`

## Consequences

- Deprovisioning delay = `cookie_refresh` + decision cache TTL. **Two numbers,
  not three.** To be measured and compared against N-03 (Phase 1).
- `cookie_refresh` is **the single most critical line** in the configuration.
  Delete it and the system does not error; it silently runs for a week on stale
  entitlements. It should be covered by a configuration test.
- Group matching will be **by name**; the SID risk (`docs/04`) stands as
  accepted debt.
- The backend has **no** direct connection to AD. The identity chain is
  one-directional: AD → Keycloak → oauth2-proxy → backend.
