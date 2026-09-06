# 02 — Target Architecture

Decisions: [0001](adr/0001-scope-v1-web-only.md) web only ·
[0002](adr/0002-pep-nginx-auth-request.md) nginx `auth_request` ·
[0003](adr/0003-oidc-oauth2-proxy.md) OIDC in oauth2-proxy ·
[0004](adr/0004-stack-rust.md) Rust backend ·
[0005](adr/0005-frontend-backend-split.md) separate frontend ·
[0006](adr/0006-group-membership-source.md) group source ·
[0007](adr/0007-frontend-buildless-static.md) buildless frontend ·
[0008](adr/0008-group-identity-name.md) group identity ·
[0009](adr/0009-policy-engine-own-code.md) policy engine ·
[0011](adr/0011-nginx-config-generation.md) nginx config generation ·
[0012](adr/0012-project-name-openberat.md) project name ·
[0015](adr/0015-single-parent-domain.md) one parent domain ·
[0016](adr/0016-n03-revocation-targets.md) revocation targets ·
[0017](adr/0017-fail-closed-availability.md) accepted SPOF ·
[0019](adr/0019-kill-switch-session-index.md) kill switch session index ·
[0020](adr/0020-frontend-in-nginx-image.md) frontend packaging

Sources for the technical claims: [`docs/07-references.md`](07-references.md).

## Components

| Component | Role | Do we write it? |
|---|---|---|
| **Active Directory** | Source of truth for identity and `memberOf` membership — though not the only source of the group claim Keycloak issues (`docs/07`) | Exists |
| **Keycloak** | IdP. LDAP federation to AD, OIDC, MFA | Configured |
| **nginx** | PEP. TLS, carries traffic, `auth_request`, serves static files | Configured |
| **oauth2-proxy** | Authentication: the OIDC dance, session (Redis) | Configured |
| **backend** | **Authorisation decision + `/api` + audit** | **Written** |
| **frontend** | **Portal + admin UI** (buildless static, ADR-0007) | **Written** |
| **Postgres** | application / entitlement / audit_event | Deployed |
| **Redis** | oauth2-proxy session store — mandatory for the kill switch **and** for the 4 KB cookie limit. Also holds the backend's `sub → session` index (ADR-0019) | Deployed |

The two components we write are `backend` and `frontend`. The rest is
off-the-shelf parts and configuration.

## Flow: reaching a protected application

In nginx, `auth_request` is a single-valued directive (`auth_request uri | off;`),
not a list — a second one does not chain, it overrides the first. oauth2-proxy's
official nginx documentation also describes no way to chain a second
authorisation check. The chain is therefore built inside the backend:

```
1.  User → app.apps.example.local ─────────────────────────► nginx

2.  nginx: auth_request /decide ───────────────────────────► backend
                                                               │
3.      backend forwards the request cookie to oauth2-proxy    │
        GET /oauth2/auth ──────────────────────────────────────┤
                                                               │
        ┌── 401 (no session) ───────────────────────────────────┘
        │
4.      backend returns 401
5.      nginx: error_page 401 → @signin ──► oauth2-proxy /oauth2/start
             the return address travels as a header (docs/07)
6.      nginx relays its 302 ─────────────► Keycloak /auth
7.      Keycloak → LDAP bind ─────────────► Active Directory
             user is verified, memberOf is read
8.      Keycloak → 302 + code ────────────► oauth2-proxy /oauth2/callback
             token exchange, session written to Redis, cookie set
9.      User retries → nginx  (back to step 2)

        ┌── 200 (authenticated) ─────────────────────────────────┐
        │   X-Auth-Request-User / -Email / -Groups               │
10.     backend: X-Auth-Request-Groups + target → decision       │
        (group source: ADR-0006)                                 │
                                                                 │
11.     DENY → 403 → nginx error_page → portal "no access"       │
        ALLOW → 200                                              │
                                                                 │
12. nginx → upstream application ────────────────────────────────┘
        with X-Auth-* headers stripped and rewritten

13. The decision is counted; when the cache entry expires a single summary
        row is written to audit_event ("Audit granularity")
```

Steps 2–12 repeat **on every HTTP request** — for the page, and for every CSS
file, script and icon. A page with 50 assets means 50 decisions. This is why the
decision cache is not an optimisation but a **mandatory part of the
architecture**, and why `N-01` is a requirement rather than a wish. Letting
static assets bypass authorisation is not an option; they can be confidential too.

The cache entry has to carry **the identity as well** (`docs/05`, "Decision
cache"). Caching only the decision is not enough: learning `sub` requires the
oauth2-proxy call in step 3, and if that internal HTTP call stays on every
request, N-01 will not hold. What is cached is the identity plus the rule set
that applies to it — not a verdict, which cannot be keyed before it is computed.

### Audit granularity

Both extremes are unacceptable. Writing every request produces 50 rows for a
single page with 50 assets, and the thing filling the disk becomes our own audit
rather than an attack. Never writing cache hits makes a user who downloads
50,000 files **invisible** in the audit record — the log says "accessed
`/files/1.pdf` at 09:14" and nothing more.

The rule: **count decisions, summarise rows.**

- The cache entry keeps counters per outcome: `count`, `first_seen`, `last_seen`
  and `distinct_path` for allows, and the same per reason for denies (`docs/05`).
- When the entry leaves the cache — TTL expiry, LRU eviction, logout or the
  kill switch — **one summary row per outcome** is written: one allow row, and
  one row per distinct deny reason. Every exit road flushes for the reason
  shutdown does: dropping an entry without writing its counters silently
  deletes audit, and the kill-switch road would lose exactly the user under
  incident response.
- Writing happens **off the decision path**: it is handed to a bounded channel.
  If the channel is full the request is not blocked; a loss counter increments
  and the event is logged through `tracing`.
- If the raw request stream is needed, structured logs go to stdout and are
  shipped to the SIEM from there (F-23) — full trace without bloating the DB.
- Counters live in memory until the entry expires, so **up to one TTL of
  summaries is lost if the process dies.** On shutdown the cache is flushed to
  the channel first; on a hard crash the loss is accepted and bounded by the TTL
  (30 s). Anything needing a gapless record uses the stdout stream, not the DB.

This is why the `audit_event` schema **starts** with the `count` / `first_seen` /
`last_seen` / `distinct_path` columns and the table is partitioned by month.
Because the audit record format is treated as immutable (CONTRIBUTING.md),
these cannot be added later.

## Flow: the portal

```
User → portal.apps.example.local
  → same authentication (steps 2–9)
  → nginx: frontend static files
  → frontend: GET /api/apps ──► backend
       "applications reachable with this user's memberOf groups"
  → buttons with icons
```

The portal **grants nothing**, it only displays. The real decision is always
made in step 10; going directly to an address not shown in the portal still
returns 403.

## The `/api` contract

The only coupling between frontend and backend. If it changes, both sides are
updated together.

| Endpoint | Caller | Function |
|---|---|---|
| `GET /decide` | **nginx** (`auth_request`) | 200 / 401 / 403. No body. |
| `GET /api/me` | frontend | The signed-in user: name, email, groups, admin flag |
| `GET /api/apps` | frontend | Applications the user can reach (portal buttons) |
| `POST /api/logout` | frontend | The caller's own kill switch, run **before** the sign-out redirect: session key (derived from the cookie it holds), cache entries, index entry ("Logout" below) |
| `GET /api/admin/applications` | admin | Application list |
| `POST/PATCH/DELETE /api/admin/applications` | admin | Defining applications |
| `GET/POST/DELETE /api/admin/entitlements` | admin | AD group ↔ application mapping |
| `GET /api/admin/audit` | admin | Audit record, filtered |
| `POST /api/admin/kill/{sub}` | admin | Kill switch |
| `GET /healthz` | operator, compose | The process is alive. No dependencies checked, no body |
| `GET /readyz` | operator, nginx | Postgres and Redis are reachable. 200 or 503 |

`/healthz` and `/readyz` exist because **the fail-closed rule hides the outage**:
`/decide` answers 403 `store_unavailable` when the database is gone, which from
outside is indistinguishable from a user who is simply not entitled. Without a
readiness endpoint the operator at 3 a.m. sees "everyone is denied" and cannot
tell whether the policy is working or the system is down — which is exactly when
the break-glass decision has to be made ([ADR-0017](adr/0017-fail-closed-availability.md)).
They are reachable on the internal network only, like `/decide`, and they are
the health check the second instance in Phase 6 needs.

### The `/decide` request contract

In the `auth_request` subrequest the URI is `/decide`; information about the
original request reaches the backend **only** through the headers nginx passes:

| Header | nginx value | Why |
|---|---|---|
| `X-App-Slug` | **fixed in every `server` block** | This is what identifies the application |
| `X-Original-URI` | `$request_uri` | The path input to the decision (raw; the backend normalises it) |
| `X-Original-Method` | `$request_method` | Audit |
| `X-Real-IP` | `$remote_addr` | Audit |
| `X-Request-Id` | `$request_id` | Correlating the nginx access log with `audit_event` |
| `Cookie` | from the client | The session cookie to forward to oauth2-proxy. The cache key hashes **only the `_oauth2_proxy` cookie's value**, never the whole header (`docs/05`, "Decision cache") |
| `X-Auth-Request-*`, `X-Auth-*` | **cleared** (`proxy_set_header … "";`) | Not input. They are the *response* side of this contract; inherited copies from the client are removed so the backend cannot read one by accident |

The application identity comes from the fixed `X-App-Slug` value in nginx's own
configuration, **not from a client-controlled hostname**: the subrequest
inherits the main request's headers verbatim — measured, `docs/07` — so `Host`,
`X-Forwarded-Host` and every `X-…` name the include does not overwrite arrive at
the backend exactly as the client wrote them. That is why the table's values are
written **unconditionally** in every protected location through a shared
`include`, and why the last row clears rather than sets.

`$request_uri` and `$request_method` resolve to the **main** request inside the
subrequest, not to the `GET /decide` on the wire (measured, `docs/07`); the two
rows above are correct as written. `$uri` is the subrequest's own path and is
not what this contract wants.

If any of them is missing the decision cannot be made → **DENY**
(`missing_context`), fail-closed.

**Response contract:**

| What | Rule |
|---|---|
| 200 / 401 / 403 | The only valid codes. **`/decide` never returns 5xx** — if the DB is unreachable, 403 `store_unavailable` |
| `Set-Cookie` | If it came from oauth2-proxy it is **relayed verbatim, whatever the decision turns out to be**; nginx passes it to the browser with `auth_request_set` + `add_header ... always`. Without this, `cookie_refresh` silently stops working (ADR-0006 collapses). Relaying it only on 200 is the same bug wearing a smaller hat: oauth2-proxy refreshes the session on the subrequest before the decision exists, so a denied user whose refreshed cookie is swallowed never refreshes again and their groups freeze until the cookie expires |
| `X-Auth-Subject` / `-Username` / `-Email` / `-Groups` | The verified identity, **whenever there is one** — on a DENY as well as on a 200. Nothing is proxied upstream after a deny, so nothing is rewritten from them there; the nginx **access log** is, and without them a denied line can say why and not who, which is the one question anybody asks about a denial. They never reach the client: `auth_request` response headers stop at nginx. `auth_request` passes no response body, so these headers are the only channel nginx can lift the identity from (`auth_request_set`) to rewrite the upstream `X-Auth-*` headers (`docs/05`, "Header contract") — without them the strip-and-rewrite include would rewrite from nothing |
| `X-Deny-Reason` | The reason on DENY; written to the nginx access log, never shown to the user |

### Anonymous endpoints

There are **no anonymously reachable endpoints** — with three mandatory
exceptions. The first two are the same trap in two places: a login flow cannot
sit behind the login flow.

- **`/oauth2/*` is anonymous.** If oauth2-proxy's `start` / `callback` / `auth`
  endpoints sit behind `auth_request`, you would have to be authenticated in
  order to authenticate; nobody could ever get in.
- **Keycloak's own host is anonymous.** The browser is redirected to Keycloak's
  login page in step 6, so that hostname is served by the same nginx and must be
  exempt for exactly the reason above. Easy to miss, because Keycloak is thought
  of as infrastructure rather than as something the user's browser visits.
  Anonymous covers only the paths the login flow needs (`/realms/*`,
  `/resources/*`): the `/admin` console and `/metrics` are **not proxied at
  all** — an internet-facing Keycloak admin login page is attack surface
  nothing here requires.
- **The portal host (`portal.apps.<domain>`, ADR-0015) is open to every
  authenticated user.** Not through policy, but through a separate `location` in
  `00-auth.conf`. Otherwise an unauthorised user is redirected to `/denied`,
  that page is itself DENYed, and the redirect loops forever. The portal's
  `auth_request` therefore targets `/oauth2/auth` **directly**, not `/decide` —
  authentication without a policy decision — and the identity headers for
  `/api/*` are lifted from that subrequest's response exactly as `/decide`'s
  are on application hosts. Known consequence: a user who only ever visits the
  portal never hits `/decide`, so they never enter the ADR-0019 kill-switch
  index — their revocation path is Keycloak `logout-all` plus `cookie_refresh`
  (TODO Phase 5 measures this).

The portal being open does **not** open the admin endpoints: `/api/admin/*`
separately requires `ADMIN_GROUP` membership and is not cached (see "Management
plane").

## Management plane

`/api/admin/*` is **not protected by the entitlement table.** Because the portal
is open to every user, if the admin endpoints sat under the portal's path anyone
who could reach the portal could grant themselves entitlements.

- Source of authority: a single `ADMIN_GROUP` from the environment (e.g. `OpenBerat-Admins`).
  If it is not in the user's group list, 403.
- The list arrives as **`X-Auth-Groups`**, not `X-Auth-Request-Groups`: the
  backend is an upstream on this path like any other, and the shared strip
  clears the `X-Auth-Request-*` family before proxying anywhere. Reading the
  cleared family here would need one location that must *not* run the shared
  strip — precisely the "forget it in one place" hazard the include exists to
  remove. One set of names arrives at every upstream, the backend included.
- That header is trustworthy only because nginx strips client-supplied
  `X-Auth-*` on the portal host's `/api/*` location too, exactly as on the
  protected applications (`docs/05`, "Header spoof protection").
- The check is on the handler's first line, **independent of the decision cache** —
  losing admin rights does not wait for a TTL.
- On every state-changing admin endpoint the `Origin` header must equal the
  expected portal origin. Because the portal and the protected applications live
  under the same registrable domain, `SameSite` does not block this request.
- This is the source of the `admin` field returned by `GET /api/me`; hiding
  things in the frontend is only a convenience (ADR-0007).

Every state-changing admin call and every kill switch invocation is recorded —
actor, action, target, outcome — in the structured stdout stream, the same
stream that carries the per-request records (F-14). Not in `audit_event`: that
table's rows are decision summaries and its format is immutable, so admin
actions would either distort it or freeze a second schema today. A dedicated
table can arrive later without breaking anything — a new table is not a format
change.

**Bootstrap:** `ADMIN_GROUP` is supplied through the environment at install
time. In a fail-closed system the first admin cannot come from the DB — nobody
can grant entitlements before anybody can log in.

## Long-lived connections

`auth_request` only runs on an HTTP request. After a WebSocket 101, and during
SSE or a long download, there is no new request, so **authorisation is never
asked again**: the kill switch, logout and disabling the account in AD do not
touch that connection.

**`proxy_read_timeout` does not solve this.** It is an idle timeout — nginx
resets it on every successful read from the upstream — so it closes an idle
WebSocket but never a busy one. A connection carrying steady traffic can outlive
any value set here. An earlier version of this document claimed the connection
"drops periodically and is re-authorised"; that only holds for idle connections.

nginx OSS has no directive that bounds the total lifetime of an upgraded
connection. The candidates, none of them free:

| Option | Effect | Cost |
|---|---|---|
| `proxy_read_timeout` | Cuts **idle** long-lived connections only | Does not cover the case that matters |
| `worker_shutdown_timeout` + a periodic reload | Old workers are killed after the timeout, so every connection is bounded | Reload side effects, worker churn; a blunt instrument |
| Re-authorisation inside the upstream application | Correct and precise | Not something a proxy can impose; the upstream has to cooperate |

**Decision: v1 sets `proxy_read_timeout` below the N-03 target (300 s,
ADR-0016) and states the limitation rather than hiding it** — an idle
connection is cut, a busy one is not. Revocation on active WebSocket/SSE connections is **explicitly outside the
N-03 guarantee** (ADR-0016), and the Phase 1 measurement exists to show exactly
how large the gap is. If it turns out to matter, the `worker_shutdown_timeout`
route is the next step.

## Data model

```
application
  id, slug, name, icon, upstream_url, external_hostname, enabled

entitlement                       -- "who reaches what"
  id, application_id,             -- NULL = every application: the wildcard of
                                  -- docs/05 rule 4. Dangerous, logged separately.
  subject_type ('ad_group' | 'user'),
  subject_id,                     -- AD group name (see warning below) or Keycloak sub
  effect ('allow' | 'deny'),
  path_pattern,                   -- empty = whole application; '/admin/*' = prefix
  expires_at                      -- NULL = no expiry

audit_event         -- append-only, partitioned by month on ts; one summary row
                    -- per (cache entry, outcome) — "Audit granularity" above
  id, ts, actor_sub, actor_name,
  application_id, application_slug, decision, reason,
  count, first_seen, last_seen, distinct_path,
  first_path, src_ip, request_id  -- of the FIRST request folded into the row;
                                  -- the per-request stream is stdout (F-23)
  -- PK is (id, ts): Postgres requires the partition key in the primary key
  --                 of a partitioned table. Not a detail to discover in Phase 2.
  -- 0001_init.sql also creates a DEFAULT partition: an INSERT with no matching
  -- partition is an error, and audit writes happen off the request path — they
  -- would fail silently. There is no user_agent column: a summary row has no
  -- single one; the stdout stream carries it per request.
  -- application_id carries NO foreign key and application_slug is denormalised
  -- beside it: deleting an application must not delete the record of who
  -- reached it, and a decision made for an unknown X-App-Slug never had a row
  -- to point at — that denial is exactly the one worth keeping.
```

`application` and `entitlement` each carry a `created_at`; who changed them is
the structured log's job (F-14), not a column.

For AD groups, `entitlement.subject_id` currently holds a **name**. This has a
structural weakness: a group that is deleted and recreated with the same name
silently inherits the old entitlements. See `docs/04-provisioning.md`, "Group
identity: name or SID?".

There is **no `known_user` table in v1.** Its only customer was per-person
time-limited access (F-20, v2); until that arrives there is no need to search
for a person in the admin UI, and when there is, `audit_event.actor_sub` /
`actor_name` are already the source. The table is added in v2.

`entitlement.conditions` (ABAC conditions) is likewise **absent in v1** —
F-21, v2. The column is added then; carrying an unused JSON field through v1
buys nothing.

## Decision order (fail-closed)

```
0. Required header missing or URI unparseable → DENY  missing_context / malformed_uri
1. Not authenticated                          → 401   (nginx redirects to login)
1b. A dependency did not answer               → DENY  auth_unavailable / store_unavailable
2. Application missing or enabled=false       → DENY  application_disabled
3. A matching deny entitlement exists         → DENY  explicit_deny
4. No matching (unexpired) allow              → DENY  no_matching_grant
5. Otherwise                                  → ALLOW
```

Step 1b is an outage wearing a decision's clothes, and it is two reasons rather
than one on purpose: `auth_unavailable` is oauth2-proxy not answering,
`store_unavailable` is Postgres. At three in the morning that is the difference
between which service gets restarted, and `/decide` cannot say it any other way
— it may not answer 5xx.

Every DENY is logged with a `reason`. The message shown to the user is generic —
which rule blocked them is never leaked. `audit_event.reason` is NOT NULL, so an
allow row carries the single reason `allowed`; the vocabulary is closed and
lives in one enum, because a typo in a reason string silently splits one
finding across two rows in every report ever run against the table.

## What does a denied user see?

A bare `403` is unacceptable. With `error_page 403`, nginx redirects to the
portal's "no access" page: which application refused them, what to do about it,
and a link back to the portal's list of what they *can* reach. Which rule
blocked them is not shown — that is the administrator's question, answered from
the audit log.

Because that page lives on the portal host, nginx **cannot serve it internally**
(`error_page` does not cross into another `server` block):
`error_page 403 = @denied` → `return 302 https://portal.apps.<domain>/denied?app=$host`.
The redirect carries nothing beyond the application name.

The page names the application from that query parameter, and treats it as
untrusted: nginx puts the matched `$host` there, but anybody can type the URL
by hand. The name is written as text, never as a link, and only when it still
looks like a hostname — otherwise the page's own sentence becomes a place to
put whatever the sender wanted the user to read, including a contact address of
the sender's choosing. A **per-application** owner or request link would be the
useful thing to show here and is not shown: it needs a column nothing writes
yet, and serving it from an endpoint any authenticated user can call would
answer "does application X exist" for applications they cannot reach. Until an
operator asks for it, the page points at the portal and at whoever administers
access.

## Logout

Three steps; skip one and the user believes they have logged out when they have
not:

1. oauth2-proxy `/oauth2/sign_out` → cookie cleared, Redis session dropped
2. Keycloak RP-initiated logout (`end_session_endpoint`) → the IdP session closes
3. That `sub` is dropped from the backend decision cache **and from the
   `sub → session` index** (ADR-0019)

Skip step 2 and the next login hands the session straight back without a
password prompt — the "I logged out" illusion.

Logout has the browser in hand, so step 1 knows which session to drop. The kill
switch does not — the admin acts on a `sub`, and Redis is keyed by ticket. That
is what the index in step 3 exists for; its order there is fixed (`docs/05`).

Step 3 does not run by itself — an earlier version of this list named no caller,
which made it a step nobody executes. The portal calls **`POST /api/logout`**
(the `/api` contract) *before* starting the redirect chain: holding the very
cookie it was called with, the backend deletes the oauth2-proxy session key,
then this `sub`'s cache entries, then the index entry — the kill-switch order.
Cache before session would let a request in the gap refill the cache from the
still-live session; skipping the call entirely leaves a replayed cookie working
for up to one cache TTL after "logout". The browser then walks steps 1–2, which
clear the cookie and the IdP session.

`POST /api/logout` is state-changing, so it carries the same `Origin` check as
the admin endpoints: the hosts behind the proxy are same-site (ADR-0015), and a
compromised application logging users out at will is a denial of service.

## Availability: the price of fail-closed

The system is deliberately fail-closed: no decision means no access. The
operational consequence:

> If `backend` goes down, `auth_request` fails and **every protected
> application becomes unreachable.** The same is true for nginx, oauth2-proxy,
> Redis, Keycloak and Postgres.

This is why the timeout budget is failure-mode design rather than optimisation:
if the backend slows down, nginx waits the default 60 seconds, worker
connections fill up, and the system stops completely. The break-glass config
lives **inside the image** — because nothing is mounted from outside
(CONTRIBUTING.md), nobody should have to build an image at 3 a.m.

Removing the VPN and putting this in its place means placing a single point of
failure in front of every internal application. This is
**accepted** ([ADR-0017](adr/0017-fail-closed-availability.md)) — a security
product that fails open is not a security product — and what makes it acceptable
is the rehearsed break-glass below, not a promise of uptime.

| Measure | In v1? |
|---|---|
| `backend` stateless, horizontally scalable | **Yes**, a design constraint |
| At least 2 instances + nginx upstream health check | Not in v1, but `/readyz` ships in v1 so the check has something to poll |
| Decision cache is instance-local; moves to Redis with multiple instances | Noted |
| Postgres unreachable → DENY; cached decisions survive for their TTL | **Yes** |
| **Break-glass:** a second nginx config in the same image, via `docker compose --profile breakglass` — written down and **rehearsed** | **Yes**, Phase 3 exit criterion |
| Timeout budget decreasing outward-in (`/decide` 2s → oauth2-proxy 1s → sqlx 500ms) | **Yes**, a design constraint |
| `error_page 500 502 503 504` → local static maintenance page (no bare nginx 500) | **Yes** |
| Monitoring: decision latency, error rate, cache hit rate | Phase 6 |

## Deployment (v1: single machine, docker compose)

```
                         [Client]
                             │ https://*.apps.example.local
                       ┌─────▼──────────┐
                       │  nginx    :443 │ ── frontend (static files)
                       └──┬─────────────┘    :80 redirects to :443
                          │ auth_request /decide
                    ┌─────▼──────────┐
                    │  backend  :8081│──► Postgres :5432
                    └─────┬──────────┘──► Redis :6379 (sub → session index)
                          │                └► shared volume: the generated
                          │                   application blocks, which nginx
                          │                   tests and installs (ADR-0011)
                          │ GET /oauth2/auth
                  ┌───────▼──────────┐
                  │ oauth2-proxy:4180│──► Redis :6379 (session)
                  └───────┬──────────┘
                  ┌───────▼──────────┐
                  │  Keycloak  :8080 │──► Active Directory (LDAPS :636)
                  └──────────────────┘
```

**443 is the only published port.** Every other container publishes nothing.
Isolation is **two docker networks, not one** — a flat "everything on nginx's
network" would put the protected applications next to Postgres, Redis and the
backend, and a compromised application could then skip nginx entirely: post to
`backend:8081/api/admin/*` with forged identity headers, read every
oauth2-proxy session out of Redis, or read the entitlement table. On a flat
network the `internal;` guard on `/decide` is no defence — that directive
constrains nginx's own routing, not who can reach the backend's port.

| Network | Members | Purpose |
|---|---|---|
| `edge` | nginx + the protected applications | The only thing an upstream can reach is nginx |
| `core` | nginx + backend + oauth2-proxy + Keycloak + Postgres + Redis | The decision chain; no protected application is on it |

nginx is the only member of both. This isolation is v1's answer to the
upstream-bypass question (`docs/06`). Keycloak's `:8080` is reached by the
browser *through* nginx, not directly; it needs TLS and a stable public hostname
for the OIDC redirect to work at all.

## Directory layout

```
backend/       Rust: /decide, /api, authorisation decision, audit  → Dockerfile
frontend/      portal + admin UI — copied into the nginx image at
               build (ADR-0020), no container of its own
nginx/         PEP configuration + static serving + frontend files → Dockerfile
keycloak/      realm export (LDAP federation)                      stock image
oauth2-proxy/  authentication configuration                        stock image
docker-compose.yml
```

## Out of scope

- SSH/RDP/DB session brokering, session recording → v2, via Apache Guacamole (ADR-0001)
- Password vault / credential injection
- Device posture, agents
- SCIM server
- Approval workflow
