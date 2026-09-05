# TODO

Status: **design complete, no code yet.**
Decisions: `docs/adr/` · Open questions: `docs/06-requirements.md`

---

## Phase 0 — Decisions

- [x] ADR-0001 Scope: web only
- [x] ADR-0002 PEP: nginx `auth_request`
- [x] ADR-0003 OIDC: delegated to oauth2-proxy
- [x] ADR-0004 Backend language: Rust
- [x] ADR-0005 Separate frontend, one directory per container
- [x] ADR-0006 Group membership source: oauth2-proxy header + mandatory `cookie_refresh`
- [x] ADR-0007 Frontend: buildless static (HTML + Alpine.js)
- [x] ADR-0008 Group identity: match by name; `OpenBerat-` prefix; `ADMIN_GROUP` = `OpenBerat-Admins`
- [x] ADR-0009 Policy engine: our own code, with a reversal trigger
- [x] ADR-0010 Lab AD: Samba AD DC
- [x] ADR-0011 nginx application blocks generated from the DB
- [x] ADR-0012 Project name: OpenBerat
- [x] ADR-0013 Licence: GPL-3.0-or-later (`LICENSE` at the root)
- [x] ADR-0014 Why not Pomerium/Authentik — differentiators and the abandon trigger
- [x] ADR-0015 One parent domain; portal at `portal.apps.<domain>`; cookie on `.apps.<domain>`
- [x] ADR-0016 N-03: 6 min for an AD change, 5 s for the kill switch, WebSocket excluded
- [x] ADR-0017 Single point of failure accepted, with a rehearsed break-glass
- [x] ADR-0018 Contributions: DCO (`git commit -s`), no CLA

**Phase 0 is closed.** Everything decidable from the design has been decided;
what remains needs facts about the target environment and is tracked in
`docs/06-requirements.md`, not here. Phase 1 answers several of them by
measurement.

Carried alongside the work, not blocking it:

- [ ] `git init` and the first public commit (there is no repository yet)
- [ ] DCO sign-off check on pull requests once the repository is public — ADR-0018

## Phase 1 — Lab and measurement

Verify the architecture actually works before writing code.
**The three verifications that could invalidate the architecture come first.**

- [ ] `docker-compose.yml`: nginx + oauth2-proxy + redis + postgres + keycloak
      + samba-ad + one sample application + one WebSocket sample.
      Upstream containers expose no `ports`, they sit only on nginx's network.
- [ ] **VERIFY (1):** does oauth2-proxy return `Set-Cookie` while performing
      `cookie_refresh` on `/oauth2/auth`? If the backend does not relay it the
      cookie is never refreshed and **ADR-0006 silently collapses** (`docs/07`)
- [ ] **VERIFY (2):** Keycloak LDAP provider `Cache Policy` — does group membership
      go stale at anything other than `NO_CACHE`? ADR-0006 rests on this claim
- [ ] **VERIFY (3):** does an nginx subrequest itself trigger `auth_request`? If it
      does, the internal HTTP call in the backend can go away. Also: does the
      subrequest inherit the main request's headers (`X-Original-URI` spoofing)?
- [ ] Keycloak LDAP federation → can an AD user log in
- [ ] `userAccountControl` filter → a disabled account cannot log in
- [ ] Group mapper `GET_GROUPS_FROM_USER_MEMBEROF_ATTRIBUTE` → `groups` claim in the token
- [ ] **Nested group test:** does a user in a parent group see the child group?
      If not, switch to `LOAD_GROUPS_BY_MEMBER_ATTRIBUTE_RECURSIVELY`
- [ ] User in many groups → is the cookie size problem gone with the Redis session
- [ ] oauth2-proxy: `set_xauthrequest=true`, `cookie_refresh=5m`, `session_store_type=redis`
- [ ] nginx `auth_request` + `error_page 401 = @signin` (mind the `=`) → login redirect
- [ ] **MEASURE:** double-hop latency with a three-line fake `/decide` (draft N-01/N-02).
      Wait for the real backend and you only see the number that justifies the
      architecture in Phase 3
- [ ] **MEASURE:** remove a user from a group in AD → how many seconds until access
      is cut? Verify the `cookie_refresh` + cache TTL sum, compare with N-03
- [ ] **MEASURE:** an **active** WebSocket connection (steady traffic, not idle) —
      how long does access survive after the user is removed from the group?
      `proxy_read_timeout` is an idle timeout and will not cut it; this measurement
      quantifies the limitation ADR-0016 states rather than testing a fix

**Output:** authentication works end to end, the latencies are known, and there is
still not one line of code.

## Phase 2 — Schema + decision (backend)

- [ ] `backend/migrations/0001_init.sql`: application, entitlement, audit_event
      (`known_user` and `entitlement.conditions` are not in v1 — `docs/02` "Data model")
- [ ] The `audit_event` schema **starts** with its summary columns: `count`,
      `first_seen`, `last_seen`, `distinct_path`, `request_id`. The table is
      partitioned by month and its PK is `(id, ts)` — Postgres requires the
      partition key in the PK. Adding any of this later is a breaking change
      (CLAUDE.md)
- [ ] `backend/src/policy.rs`: the decision function — pure, no DB, no HTTP
- [ ] `policy.rs`: URI normalisation (drop the query, one decode round, resolve
      `..`/`//`, lowercase) + matching **at a segment boundary**
- [ ] **Test:** `/%61dmin/`, `//admin/`, `/x/../admin/`, `/admin` (no slash),
      `/adminx` → does the `/admin/*` deny rule hold in all of them
- [ ] **Test:** double encoding (`%2561`) → DENY `malformed_uri`
- [ ] **Test:** default deny (no match means deny)
- [ ] **Test:** deny overrides allow
- [ ] **Test:** an expired entitlement is ignored
- [ ] The `ADMIN_GROUP` check — a separate pure function, never cached
- [ ] **Test:** an ordinary user with portal access cannot reach `/api/admin/*`
- [ ] `backend/src/store.rs`: the entitlement query + audit writing (off the
      decision path, bounded channel; a full channel does not block the request)

## Phase 3 — `/decide` and closing the chain

- [ ] `backend/src/api.rs`: `GET /decide` — forward the cookie to oauth2-proxy, take
      the identity, decide
- [ ] `/decide` **never returns 5xx**: on a DB error, 403 `store_unavailable`
- [ ] The `Set-Cookie` from oauth2-proxy is relayed verbatim
- [ ] Timeout budget decreasing outward-in: `/decide` 2s → oauth2-proxy 1s → sqlx 500ms
- [ ] Decision cache: key `(cookie_hash, app_slug)`, value **identity + the
      matching rule list + per-outcome counters**; `policy.rs` evaluates the
      cached rules against the normalised path on every hit. Single-flight
      refresh, bounded LRU, `sub → keys` reverse index (`docs/05`)
- [ ] **Test:** cache TTL, key isolation, single-flight (50 concurrent requests → 1 refresh)
- [ ] `backend/Dockerfile`: multi-stage build
- [ ] `nginx/conf.d/00-auth.conf`: `auth_request`, `error_page 401 = @signin`,
      `error_page 403 = @denied` → **302** to the portal host,
      `error_page 500 502 503 504 = @unavailable` → local static page
- [ ] `/oauth2/*` anonymous; the portal host open to every authenticated user
- [ ] **Test:** an unauthorised user sees the `/denied` page (no loop)
- [ ] The `/decide` include: `X-App-Slug` (fixed), `X-Original-URI`,
      `X-Original-Method`, `X-Real-IP`, `X-Request-Id` — written unconditionally
- [ ] `nginx/conf.d/20-apps.conf`: protected applications, **strip** incoming
      `X-Auth-*` headers
- [ ] `proxy_read_timeout 300s` on protected locations — cuts idle long-lived
      connections only; active ones are outside the N-03 guarantee (ADR-0016)
- [ ] `Origin` check on state-changing `/api/admin/*` endpoints
- [ ] Rate limiting (pulled forward from Phase 6 — audit and backend are a single
      point of failure)
- [ ] **Test:** a forged `X-Auth-Groups` grants no access
- [ ] **Test:** a forged `X-Original-URI` / `Host` cannot borrow another
      application's entitlements
- [ ] **Test:** an unauthenticated request is redirected to login
- [ ] `/decide` reachable only from the internal network (`internal;`)
- [ ] Diagnostics: `X-Deny-Reason` into the access log; `request_id` correlating
      nginx with audit

**Exit criterion:** end-to-end access control **and a rehearsed break-glass**
(a second nginx config in the same image, `--profile breakglass`). Everything up
to here is a usable system — and the proof of usability is the break-glass.

## Phase 4 — Minimal admin (before the portal)

So the portal's data does not have to be filled in by hand with SQL.

- [ ] Application CRUD + `upstream_url` validation (scheme/host/port; loopback,
      link-local and infrastructure services rejected)
- [ ] AD group ↔ application mapping (allow/deny)
- [ ] **nginx config generation** (ADR-0011): generate from the template →
      `nginx -t` → reload. If validation fails, the current config stays in effect
- [ ] **Test:** every generated location contains the `X-Auth-*` stripping include
- [ ] `GET /api/me`, `GET /api/apps`

## Phase 5 — Portal + audit + kill switch

- [ ] Portal: reachable applications, buttons with icons
- [ ] The "no access" page — where `error_page 403` lands
- [ ] Empty state: "you have access to no applications"
- [ ] `frontend/Dockerfile`, nginx static serving
- [ ] Audit log viewing + filtering
- [ ] `GET /api/admin/explain?user&host&path` — why the decision was made.
      `policy.rs` is already pure; the screen ops will use most
- [ ] Kill switch: Keycloak `logout-all` → oauth2-proxy Redis session → decision
      cache (the order is fixed)
- [ ] **Test:** access is cut after a kill switch **and the cache does not refill**
- [ ] **Test:** an **idle** WebSocket connection is cut within `proxy_read_timeout`
      (an active one is not — ADR-0016 excludes it, do not assert otherwise)
- [ ] Logout: all three steps (`docs/02`, "Logout")

## Phase 6 — Hardening and packaging

- [ ] **Deprovisioning delay test** — does the N-03 target hold (repeat the Phase 1
      measurement)
- [ ] Security headers, TLS settings, the certificate renewal path
- [ ] Backup/restore procedure, migration rollback
- [ ] Audit retention job (N-04) and partition maintenance
- [ ] Monitoring: decision latency, error rate, cache hit rate, audit loss counter
- [ ] Versioning, release image, offline bundle for air-gapped installation
- [ ] SPDX identifier in `Cargo.toml`, licence headers, Alpine.js MIT notice preserved (ADR-0013)
- [ ] Installation documentation: DNS, wildcard certificate, `ADMIN_GROUP`, first login
- [ ] Load test → fix N-01/N-02 (answer N-07 first, otherwise the test has no target)
- [ ] Backend on 2 instances + nginx health check (HA — after the first deployment)

---

## Later

- SSH/RDP → define Apache Guacamole as a protected application (ADR-0001)
- Per-person time-limited access (JIT access, `expires_at`) + the `known_user`
  table and person selection in admin
- Conditional access (IP, time, `acr`) → the `entitlement.conditions` column is
  added then
- A signed identity JWT to the upstream + a JWKS endpoint (`docs/06`, Security)
- A service-account / machine-to-machine access path (CI, monitoring, mobile)
- Audit hash chain (`prev_hash`) — stays here: ADR-0014 chose differentiators
  that are not audit-led, so it does not enter `0001_init.sql`
- SIEM integration, access reports
- Group name ↔ SID drift auditing
- HA / multiple instances → the decision cache moves to Redis
