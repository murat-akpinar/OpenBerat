# 05 — Authorisation Model

## Choice: start with RBAC, layer ABAC on top

| Model | In v1? | Why |
|---|---|---|
| RBAC (AD group → application) | **Yes** | AD already works in groups. The user already knows this model. |
| ABAC (IP, time, MFA, device) | **No** | F-21, v2. The `conditions` column is not in the v1 schema; it is added when needed. |
| ReBAC (Zanzibar) | No | Overkill for this problem. |

## Policy engine: write one or take one?

| Option | Pro | Con |
|---|---|---|
| **Our own code** (table query + ifs) | Simple, fast, debuggable, nobody has to learn Rego | If complex rules arrive, you rewrite |
| **OPA / Rego** | Industry standard, policy separated from code | Steep Rego learning curve, the team will hate it |
| **Cedar** | More readable than Rego, formally verifiable | Smaller ecosystem |
| **Casbin** | Embedded, light | The model file is still a DSL |

**Decided: our own code in v1** ([ADR-0009](adr/0009-policy-engine-own-code.md)).
The decision order is a six-step function (see `docs/02-architecture.md`); moving
that to OPA means 300 lines of Rego and one more service. The reversal trigger is
written down in the ADR — when the rule count stops being manageable with ifs,
this moves to OPA.

## Decision inputs

```
{
  subject:  { sub, username, groups[] },
  resource: { application_id, hostname, path, method },
  context:  { now }        -- for comparing expires_at; policy.rs does not read
}                          -- the clock, it arrives as a parameter (CONTRIBUTING)
```

`acr` and `src_ip` do **not** feed the decision: the first arrives with ABAC
(v2), the second is only relevant to the audit record.

Output:

```
{ decision: "allow" | "deny", reason: "...", ttl_seconds: 30 }
```

`reason` is **logged**, never shown to the user.

## Rules

1. **Default deny.** No matching allow means deny.
2. **Deny > allow.** A single deny overrides every allow.
3. **Path granularity is optional.** An empty `path_pattern` means the whole
   application. A non-empty one (`/admin/*`) means only that path. **Matching
   happens on the normalised path and at a segment boundary** — see below.
4. **Wildcard (`*`) applications** for groups such as IT-Admin. Dangerous, and
   logged separately.
5. **Expiry.** An entitlement whose `expires_at` has passed is ignored.

## Path normalisation — where deny rules go to die

`X-Original-URI` arrives raw (`$request_uri`). Doing prefix matching on the raw
string skips **every** `path_pattern`-based deny rule:

| Request | Raw match against `/admin/*` | What the upstream sees |
|---|---|---|
| `/%61dmin/users` | no match → deny skipped | `/admin/users` |
| `//admin/users` | no match | `/admin/users` |
| `/x/../admin/users` | no match | `/admin/users` |
| `/admin` | no match (no trailing `/`) | the same page in most frameworks |

A single normalisation function runs before the decision:

1. Drop the query string (cut at `?`)
2. One round of percent-decoding. If a `%` remains afterwards (double
   encoding), or the decoded bytes are not valid UTF-8, or they contain a
   control character (`%00` — NUL truncates the path inside some upstream
   frameworks) → **DENY** `malformed_uri`
3. Resolve `.` and `..` segments, collapse consecutive `/`
4. Lowercase
5. Match **at a segment boundary**: `/admin/*` → the prefix `/admin/`; `/adminx`
   does not match, `/admin` does

This function lives in `policy.rs`, is pure and is tested. Every row of the table
above is a test case.

## Management plane authority

`/api/admin/*` is not protected by this table; it requires `ADMIN_GROUP`
membership and is **not cached** (`docs/02`, "Management plane"). The decision
function is separate and two lines long: is `ADMIN_GROUP` in the group list or
not.

## Decision cache

A DB query on every HTTP request does not scale. But a long cache means late
deprovisioning.

**What is cached is not the verdict, but the inputs to it.** Two constraints
force this:

- Learning `sub` requires a call to oauth2-proxy. If that internal HTTP call
  stays on every request, N-01 (< 5 ms) will not hold — so the identity has to
  live in the entry.
- A verdict **cannot be keyed by the rule it matched.** Finding the matching
  `path_pattern` *is* the DB query we are trying to avoid, so the matched
  pattern is unknown at lookup time and cannot be part of the key. An earlier
  draft of this section keyed on `(cookie_hash, app_slug, matched_pattern)`,
  which is unimplementable for exactly this reason.

So:

- Key: `(cookie_hash, app_slug)` — both computable from the request alone.
  - `cookie_hash`: SHA-256 of the **`_oauth2_proxy` cookie's value only** —
    never the whole `Cookie` header. Applications set cookies of their own on
    the shared domain; hash the whole header and every app-cookie change is a
    new key, and the hit rate N-01 depends on collapses.
  - Neither the path nor the query string is part of the key
- Value:
  ```
  { sub, username, groups[],
    rules[],     -- the entitlements matching these groups for this application,
                 -- ordered: (effect, path_pattern, expires_at)
    counters }   -- see below
  ```
- On a hit, `policy.rs` runs against the normalised path and the cached
  `rules[]`. That is a pure function over data already in memory: one hash
  lookup, one normalisation, a handful of prefix comparisons.
- TTL: **30 seconds** (configurable). Identity and rules go stale together — one
  number.
- **Single-flight:** concurrent requests for the same key wait on one refresh. A
  page with 50 assets does not trigger 50 parallel refreshes when the TTL expires.
- Bounded LRU. One user cannot produce unbounded entries.
- A `sub → keys` reverse index is kept; logout and the kill switch drop **only
  that user's** entries. Clearing the whole cache is self-DoS. A dropped
  entry's counters are flushed to the audit channel first — eviction, logout
  and the kill switch flush for the same reason TTL expiry does (`docs/02`,
  "Audit granularity").
- The kill switch order is fixed: **Keycloak `logout-all` → the oauth2-proxy
  session keys from the `sub → session` index → this user's cache entries →
  the index entry.** In the reverse order a request arriving in the gap refills
  the cache with a fresh ALLOW. Finding the session at all needs that index —
  Redis is keyed by ticket, not by user ([ADR-0019](adr/0019-kill-switch-session-index.md)).
- On a miss the `sub → session key` index entry (ADR-0019) is written **before**
  the ALLOW is returned, and a failed write is a DENY `store_unavailable`: a
  session the kill switch cannot find must not gain access. Redis dying
  outright already fails closed at oauth2-proxy; this covers the narrower
  failure where reads still work but writes do not (a full Redis under
  `noeviction`).

Caching the rule set rather than the verdict is also the safer design: every
request is evaluated against the **full** rule list, so a deny can never be
skipped because two paths collapsed into one cache key. And because the path is
not in the key, a cache-buster such as `?v=hash` cannot drive the hit rate to
zero.

**Counters.** One entry now covers several paths and both outcomes, so it keeps
them separately:

```
allow: { count, first_seen, last_seen, distinct_path }
deny:  { reason → { count, first_seen, last_seen } }
```

When the entry leaves the cache — TTL, eviction, logout, kill switch — one
summary row is written per outcome: an allow row, and one row per distinct deny
reason (`docs/02`, "Audit granularity").

Deprovisioning delay is therefore still **two numbers**: `cookie_refresh` plus
this TTL (ADR-0006, ADR-0016). **Exception:** long-lived connections such as
WebSocket/SSE are authorised once and are not covered by either number
(`docs/02`, "Long-lived connections").

`# ponytail: in-memory cache keyed per sub, assumes a single instance. Move to Redis once there are several.`

## Application access levels (not in v1, reserved in the design)

In some systems "can reach" is not enough; "can read / can write / can
administer" is needed. That is the upstream application's own job — the proxy
only passes the identity in a header and the upstream interprets the level. The
proxy is not made responsible for carrying roles.

### Header contract

There are two distinct header sets in the chain; do not conflate them:

**oauth2-proxy → backend** (identity, ADR-0003):
```
X-Auth-Request-User    : the Keycloak `sub`, a UUID — **not** the username
X-Auth-Request-Preferred-Username : sAMAccountName
X-Auth-Request-Email   : mail
X-Auth-Request-Groups  : comma-separated group list
```

**nginx → upstream application** (after authorisation):
```
X-Auth-Subject     : Keycloak sub (immutable identity)
X-Auth-Username    : sAMAccountName
X-Auth-Email       : mail
X-Auth-Groups      : comma-separated group list
X-Auth-Request-Id  : for correlating with the audit log
```

The upstream set is rewritten by nginx from `/decide`'s **response headers** on
a 200 (`auth_request_set` → `proxy_set_header`; the response contract in
`docs/02` lists them) — `auth_request` passes no body, so headers are the only
channel. `X-Auth-Request-Id` alone comes from nginx's own `$request_id`.

Which claim oauth2-proxy puts in `X-Auth-Request-User` was a Phase 1
verification and is now **measured** (`docs/07`): it is the immutable Keycloak
`sub`, and the username arrives beside it in
`X-Auth-Request-Preferred-Username`. An earlier version of this contract had
sAMAccountName in `X-Auth-Request-User`; reading `X-Auth-Subject` from it would
have keyed the ADR-0019 kill-switch index on a **renameable** value.

### Header spoof protection — the classic hole in this architecture

A user can add their own `X-Auth-Groups: IT-Admin` header to a request. Before
passing anything upstream, nginx must unconditionally strip **every** `X-Auth-*`
header coming from the client, then rewrite them from the verified identity.

In nginx this is done with `proxy_set_header X-Auth-... ""` and it **must be
repeated in every protected location** — forget it in one location and it is not
just that application that falls, but the entire system's security claim. It
belongs in a shared `include` file pulled in everywhere.

The `Cookie` header gets the same treatment in the other direction: the
`_oauth2_proxy` session cookie is **removed** before the request is proxied
upstream (the application's own cookies pass through). The upstream has no use
for it — identity arrives in the `X-Auth-*` headers — and an application that
receives it is holding, and probably access-logging, a credential valid for
every host on `.apps.<domain>` (ADR-0015).

The same applies to `/decide`: the backend listens only on the `core` network,
which no protected application joins (`docs/02`, "Deployment"). The `internal;`
directive stops the *browser* reaching `/decide` through nginx; it does nothing
about a container calling `backend:8081` directly — that is what the network
split is for. Otherwise, even if an attacker cannot produce an "allow" with
their own identity headers, they can enumerate the policy table.

```rust
// --- Feature Start ---
// Incoming X-Auth-* headers may have been forged by the client; they are stripped
// unconditionally before proxying and rewritten from the verified identity.
// --- Feature End ---
```

**Acceptance criterion:** a test will be written showing that a protected
application cannot be reached with a forged `X-Auth-Groups` header (TODO.md
Phase 3).

**The uncovered side:** the upstream application cannot distinguish a request
that **bypassed** nginx from the incoming headers. In v1 the basis is network
isolation (upstream containers only on the `edge` network with nginx — never on
`core` with the backend, Redis and Postgres — and no `ports`; `docs/02`,
"Deployment"). The answer
that stands up to an audit is issuing a short-lived **signed identity JWT**;
tracked under the security open questions in `docs/06`.

## Attacks this design must refuse

Nothing here is new — every row is decided somewhere above or in `docs/02`. It is
collected so that a reviewer can find them in one place, and so that a row
without a test is visible as a gap rather than an omission.

| Attack | Where it is refused | Proof |
|---|---|---|
| Client sends its own `X-Auth-Groups: IT-Admin` | nginx strips every `X-Auth-*` in a shared `include`, in **every** protected location, before proxying | Phase 3 test |
| Client sends `X-Auth-Request-Groups: <ADMIN_GROUP>` straight to `/api/admin/*` | The same strip `include` is pulled into the portal host's `/api/*` location — the admin check trusts only what nginx rewrote | Phase 3 test |
| A protected application harvesting the shared session cookie from incoming requests | nginx removes the `_oauth2_proxy` cookie before proxying upstream; identity travels in `X-Auth-*` only | Phase 3 test |
| Client drives `Host` / `X-Forwarded-Host` to borrow another application's entitlements | `X-App-Slug` is a constant in each `server` block, never taken from the request | Phase 3 test |
| `/%61dmin/users` — single-encoded past a `/admin/*` deny | Normalisation runs before matching: decode once, then match | Phase 2 test |
| `/%2561dmin/` — double-encoded | A `%` surviving one decode round → DENY `malformed_uri` | Phase 2 test |
| `/admin%00.png` — the upstream truncates at NUL and serves `/admin` | Control characters or invalid UTF-8 after the decode round → DENY `malformed_uri` | Phase 2 test |
| `//admin/`, `/x/../admin/` | Consecutive slashes collapsed, `.`/`..` resolved | Phase 2 test |
| `/adminx` slipping into a `/admin/*` rule | Matching at a **segment boundary**, not a raw prefix | Phase 2 test |
| An entitlement whose `expires_at` has passed still granting | `expires_at` is part of the decision, and the cached rule list carries it | Phase 2 test |
| A portal user calling `/api/admin/*` | `ADMIN_GROUP` check on the handler's first line, **never cached** | Phase 2 test |
| A compromised protected application posting to `/api/admin/*` | `Origin` check on state-changing admin endpoints — `SameSite` cannot help, the hosts are same-site (ADR-0015) | Phase 3 test |
| A request in the gap after a kill switch refilling the cache with a fresh ALLOW | The four-step order is fixed: Keycloak → session keys → cache → index (ADR-0019) | Phase 5 test |
| A kill switch erasing the audit trail of the user it kills | Dropped cache entries flush their counters to the audit channel before they go | Phase 3 test |
| Calling `/decide` directly to enumerate the policy table | From the browser: `internal;`. From a container: the backend sits only on `core`, which no protected application joins (`docs/02`) | Phase 3 |
| Reaching an upstream while bypassing nginx entirely | v1: two networks — upstreams on `edge` with nginx only, never on `core` (`docs/02`); no published `ports`. **Not fully closed** — the signed identity JWT is the answer that survives an audit | Open question, `docs/06` |
| A deleted AD group recreated with the same name inheriting its entitlements | **Not closed.** Accepted debt, mitigated by the `OpenBerat-` prefix and change control (ADR-0008) | — |
| Revoking access on an **active** WebSocket/SSE connection | **Not closed.** Explicitly outside the N-03 guarantee (ADR-0016) | Phase 1 measures the gap |

The last three rows are the honest ones: they are open, and a security review
should find them here rather than in the code.
