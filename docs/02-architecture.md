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
[0017](adr/0017-fail-closed-availability.md) accepted SPOF

Sources for the technical claims: [`docs/07-references.md`](07-references.md).

## Components

| Component | Role | Do we write it? |
|---|---|---|
| **Active Directory** | Single source of truth for identity and `memberOf` membership | Exists |
| **Keycloak** | IdP. LDAP federation to AD, OIDC, MFA | Configured |
| **nginx** | PEP. TLS, carries traffic, `auth_request`, serves static files | Configured |
| **oauth2-proxy** | Authentication: the OIDC dance, session (Redis) | Configured |
| **backend** | **Authorisation decision + `/api` + audit** | **Written** |
| **frontend** | **Portal + admin UI** (buildless static, ADR-0007) | **Written** |
| **Postgres** | application / entitlement / audit_event | Deployed |
| **Redis** | oauth2-proxy session store — mandatory for the kill switch **and** for the 4 KB cookie limit | Deployed |

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
5.      nginx: error_page 401 → 302 ──────► oauth2-proxy /oauth2/start
6.      oauth2-proxy → 302 ───────────────► Keycloak /auth
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
- When the entry expires on TTL, **one summary row per outcome** is written: one
  allow row, and one row per distinct deny reason.
- Writing happens **off the decision path**: it is handed to a bounded channel.
  If the channel is full the request is not blocked; a loss counter increments
  and the event is logged through `tracing`.
- If the raw request stream is needed, structured logs go to stdout and are
  shipped to the SIEM from there (F-23) — full trace without bloating the DB.

This is why the `audit_event` schema **starts** with the `count` / `first_seen` /
`last_seen` / `distinct_path` columns and the table is partitioned by month.
Because the audit record format is treated as immutable (CLAUDE.md), these
cannot be added later.

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
| `GET /api/admin/applications` | admin | Application list |
| `POST/PATCH/DELETE /api/admin/applications` | admin | Defining applications |
| `GET/POST/DELETE /api/admin/entitlements` | admin | AD group ↔ application mapping |
| `GET /api/admin/audit` | admin | Audit record, filtered |
| `POST /api/admin/kill/{sub}` | admin | Kill switch |

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
| `Cookie` | from the client | The session cookie to forward to oauth2-proxy |

The application identity comes from the fixed `X-App-Slug` value in nginx's own
configuration, **not from a client-controlled hostname**: because the subrequest
inherits the main request's headers, `Host` and `X-Forwarded-Host` can be driven
by the client. These headers are written **unconditionally** in every protected
location through a shared `include`.

If any of them is missing the decision cannot be made → **DENY**
(`missing_context`), fail-closed.

**Response contract:**

| What | Rule |
|---|---|
| 200 / 401 / 403 | The only valid codes. **`/decide` never returns 5xx** — if the DB is unreachable, 403 `store_unavailable` |
| `Set-Cookie` | If it came from oauth2-proxy it is **relayed verbatim**; nginx passes it to the browser with `auth_request_set` + `add_header ... always`. Without this, `cookie_refresh` silently stops working (ADR-0006 collapses) |
| `X-Deny-Reason` | The reason on DENY; written to the nginx access log, never shown to the user |

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
- **The portal host (`portal.apps.<domain>`, ADR-0015) is open to every
  authenticated user.** Not through policy, but through a separate `location` in
  `00-auth.conf`. Otherwise an unauthorised user is redirected to `/denied`,
  that page is itself DENYed, and the redirect loops forever.

The portal being open does **not** open the admin endpoints: `/api/admin/*`
separately requires `ADMIN_GROUP` membership and is not cached (see "Management
plane").

## Management plane

`/api/admin/*` is **not protected by the entitlement table.** Because the portal
is open to every user, if the admin endpoints sat under the portal's path anyone
who could reach the portal could grant themselves entitlements.

- Source of authority: a single `ADMIN_GROUP` from the environment (e.g. `OpenBerat-Admins`).
  If it is not in the user's `X-Auth-Request-Groups` list, 403.
- The check is on the handler's first line, **independent of the decision cache** —
  losing admin rights does not wait for a TTL.
- On every state-changing admin endpoint the `Origin` header must equal the
  expected portal origin. Because the portal and the protected applications live
  under the same registrable domain, `SameSite` does not block this request.
- This is the source of the `admin` field returned by `GET /api/me`; hiding
  things in the frontend is only a convenience (ADR-0007).

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

**Decision: v1 sets `proxy_read_timeout` to the N-03 target and states the
limitation rather than hiding it** — an idle connection is cut, a busy one is
not. Revocation on active WebSocket/SSE connections is **explicitly outside the
N-03 guarantee** (ADR-0016), and the Phase 1 measurement exists to show exactly
how large the gap is. If it turns out to matter, the `worker_shutdown_timeout`
route is the next step.

## Data model

```
application
  id, slug, name, icon, upstream_url, external_hostname, enabled

entitlement                       -- "who reaches what"
  id, application_id,
  subject_type ('ad_group' | 'user'),
  subject_id,                     -- AD group name (see warning below) or Keycloak sub
  effect ('allow' | 'deny'),
  path_pattern,                   -- empty = whole application; '/admin/*' = prefix
  expires_at                      -- NULL = no expiry

audit_event                       -- append-only, partitioned by month on ts
  id, ts, actor_sub, actor_name,
  application_id, path, decision, reason,
  src_ip, user_agent, request_id
  -- PK is (id, ts): Postgres requires the partition key in the primary key
  --                 of a partitioned table. Not a detail to discover in Phase 2.
```

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
2. Application missing or enabled=false       → DENY  application_disabled
3. A matching deny entitlement exists         → DENY  explicit_deny
4. No matching (unexpired) allow              → DENY  no_matching_grant
5. Otherwise                                  → ALLOW
```

Every DENY is logged with a `reason`. The message shown to the user is generic —
which rule blocked them is never leaked.

## What does a denied user see?

A bare `403` is unacceptable. With `error_page 403`, nginx redirects to the
portal's "no access" page: which application, who to contact, a request link.
Which rule blocked them is not shown.

Because that page lives on the portal host, nginx **cannot serve it internally**
(`error_page` does not cross into another `server` block):
`error_page 403 = @denied` → `return 302 https://portal.apps.<domain>/denied?app=$host`.
The redirect carries nothing beyond the application name.

## Logout

Three steps; skip one and the user believes they have logged out when they have
not:

1. oauth2-proxy `/oauth2/sign_out` → cookie cleared, Redis session dropped
2. Keycloak RP-initiated logout (`end_session_endpoint`) → the IdP session closes
3. That `sub` is dropped from the backend decision cache

Skip step 2 and the next login hands the session straight back without a
password prompt — the "I logged out" illusion.

## Availability: the price of fail-closed

The system is deliberately fail-closed: no decision means no access. The
operational consequence:

> If `backend` goes down, `auth_request` fails and **every protected
> application becomes unreachable.** The same is true for nginx, oauth2-proxy,
> Redis, Keycloak and Postgres.

This is why the timeout budget is failure-mode design rather than optimisation:
if the backend slows down, nginx waits the default 60 seconds, worker
connections fill up, and the system stops completely. The break-glass config
lives **inside the image** — because nothing is mounted from outside (CLAUDE.md),
nobody should have to build an image at 3 a.m.

Removing the VPN and putting this in its place means placing a single point of
failure in front of every internal application. This is
**accepted** ([ADR-0017](adr/0017-fail-closed-availability.md)) — a security
product that fails open is not a security product — and what makes it acceptable
is the rehearsed break-glass below, not a promise of uptime.

| Measure | In v1? |
|---|---|
| `backend` stateless, horizontally scalable | **Yes**, a design constraint |
| At least 2 instances + nginx upstream health check | No, but the design will not prevent it |
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
                    └─────┬──────────┘
                          │ GET /oauth2/auth
                  ┌───────▼──────────┐
                  │ oauth2-proxy:4180│──► Redis :6379 (session)
                  └───────┬──────────┘
                  ┌───────▼──────────┐
                  │  Keycloak  :8080 │──► Active Directory (LDAPS :636)
                  └──────────────────┘
```

**443 is the only published port.** Every other container publishes nothing and
is reachable only on nginx's network — that isolation is v1's answer to the
upstream-bypass question (`docs/06`). Keycloak's `:8080` is reached by the
browser *through* nginx, not directly; it needs TLS and a stable public hostname
for the OIDC redirect to work at all.

## Directory layout

```
backend/       Rust: /decide, /api, authorisation decision, audit  → Dockerfile
frontend/      portal + admin UI                                   → Dockerfile
nginx/         PEP configuration + static serving                  → Dockerfile
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
