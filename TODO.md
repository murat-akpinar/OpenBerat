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
- [x] ADR-0019 Kill switch: the backend keeps a `sub → session` index in Redis
      (the 5 s target of ADR-0016 was otherwise unimplementable — Redis is keyed
      by ticket, not by user). Rests on a Phase 1 verification
- [x] ADR-0020 Frontend packaging: the static files are copied into the nginx
      image at build; no frontend container — a named volume seeds only while
      empty and would serve stale files after the first deploy

**Phase 0 is closed.** Everything decidable from the design has been decided;
what remains needs facts about the target environment and is tracked in
`docs/06-requirements.md`, not here. Phase 1 answers several of them by
measurement.

Carried alongside the work, not blocking it:

- [x] Repository published; `CONTRIBUTING.md`, `SECURITY.md` and the DCO +
      `fmt`/`clippy`/`test` CI (`.github/workflows/ci.yml`) are in place — ADR-0018
- [ ] Publish `SECURITY.md` (drafted in `.rules/`, not in the repository yet)
      before the project takes outside traffic — GitHub renders it in the Security
      tab and wires "Report a vulnerability" to it. Its scope section says "no
      released version yet" and is rewritten when v1 ships

## Phase 1 — Lab and measurement

Verify the architecture actually works before writing code.
**The four verifications that could invalidate the architecture come first.**

- [x] Self-signed wildcard certificate for `*.apps.<domain>` + the hosts file /
      DNS entries. **First item, not a Phase 6 one:** the OIDC redirect and the
      `Secure` session cookie do not work over plain HTTP, so nothing below can
      be tested without it. Which CA issues the *production* certificate stays
      an open question (`docs/06`).
      *Landed as `INSTALL.md` §1–2, executed on the lab host: self-signed
      `*.apps.example.local` (SAN wildcard + apex, 2-year), hosts entries, and
      the `:443` server enabled. Verified live: the presented certificate
      validates against the crt without `-k`, HTTP/2 200 on two wildcard
      hosts, `:80` → 301. Browser-side hosts entries are still needed on the
      machine the OIDC tests will run from*
- [x] `docker-compose.yml`: nginx + oauth2-proxy + redis + postgres + keycloak
      + samba-ad + one sample application + one WebSocket sample.
      **Two networks** (`docs/02`, "Deployment"): the sample applications on
      `edge` with nginx alone; backend, oauth2-proxy, Keycloak, Postgres,
      Redis and samba-ad on `core`. Nothing publishes `ports` except nginx —
      a flat network would let a compromised upstream reach `backend:8081` and
      the Redis sessions directly.
      *Landed as the skeleton (4291470): compose validates, both images build,
      the nginx request log verified against a live container. Not yet a
      running lab — `oauth2-proxy.cfg` and the realm export are empty (their
      items below) and the `:443` server stays commented until the certificate
      item above is done.*
- [x] **VERIFY (1):** does oauth2-proxy return `Set-Cookie` while performing
      `cookie_refresh` on `/oauth2/auth`? If the backend does not relay it the
      cookie is never refreshed and **ADR-0006 silently collapses** (`docs/07`).
      *Answer: yes, one `Set-Cookie` on a `202` — but the relay broke anyway on
      the first wiring. An internal redirect (`try_files … /index.html`,
      `index`, a directory match) restarts nginx's access phase, `auth_request`
      fires a second time, and the second subrequest — with nothing left to
      refresh — overwrites `$auth_cookie` with an empty string. Silent: no
      error, groups just stay frozen for seven days, and every such request
      costs two decisions instead of one. Fixed with `try_files … =404`, which
      serves files in place; measured 2 subrequests → 1. Rule added to
      `nginx/conf.d/README.md`, both halves in `docs/07`*
- [ ] **VERIFY (2):** Keycloak LDAP provider `Cache Policy` — does group membership
      go stale at anything other than `NO_CACHE`? ADR-0006 rests on this claim
- [x] **VERIFY (3):** does an nginx subrequest itself trigger `auth_request`? If it
      does, the internal HTTP call in the backend can go away. Also: does the
      subrequest inherit the main request's headers (`X-Original-URI` spoofing)?
      *Answers: **no** and **yes** — both in `docs/07`. nginx skips the entire
      access phase for a subrequest (`deny all` is ignored in the same
      position), so the chain stays in the backend and ADR-0002 is unchanged;
      `internal;` still holds, because that is checked a phase earlier, but an
      IP ACL on `/decide` would constrain nothing. Headers are inherited
      verbatim: everything the `/decide` include does not overwrite reaches the
      PDP as the client wrote it, so the include now **clears** the `X-Auth-*`
      family as well — `docs/05`'s attack table only ever covered the upstream
      direction. Two more findings on the way: `$request_uri` and
      `$request_method` inside the subrequest are the main request's, so
      `docs/02`'s mapping was right and needs no workaround; and a location that
      answers with `return` is **unprotected**, because `return` runs in the
      rewrite phase before `auth_request` — the probe's own control case caught
      that one, and it is now item 14 in `nginx/conf.d/README.md`*
- [ ] **VERIFY (4):** can the oauth2-proxy Redis session key be derived from the
      session cookie? Log in, read the cookie, list the Redis keys, and delete the
      matching one — access must stop immediately. Repeat after a
      `cookie_refresh` has fired: if the refresh mints a new ticket, the index
      must still find the live session (the new key arrives via the next cache
      miss). **ADR-0019 and with it the 5 s
      kill-switch target rest on this**; if it fails, ADR-0019 falls back to
      option C and ADR-0016 is revised in the same commit
- [ ] Keycloak LDAP federation → can an AD user log in
- [ ] `userAccountControl` filter → a disabled account cannot log in
- [ ] Group mapper `GET_GROUPS_FROM_USER_MEMBEROF_ATTRIBUTE` → `groups` claim in the token
- [ ] **Nested group test:** does a user in a parent group see the child group?
      If not, switch to `LOAD_GROUPS_BY_MEMBER_ATTRIBUTE_RECURSIVELY`
- [ ] User in many groups → is the cookie size problem gone with the Redis session
- [x] oauth2-proxy: `set_xauthrequest=true`, `cookie_refresh=5m`, `session_store_type=redis`
      *All three set in `oauth2-proxy/oauth2-proxy.cfg` and confirmed in the
      running proxy's own startup line. PKCE (`S256`) turned on at the same
      time — Keycloak advertises it and oauth2-proxy leaves it off by default*
- [x] **VERIFY:** which claim oauth2-proxy puts in `X-Auth-Request-User` with
      Keycloak (`sub`? `preferred_username`?) — `X-Auth-Subject` and the
      ADR-0019 index are keyed by the immutable `sub`; if no header carries it,
      the `docs/05` header contract is revised (`docs/07`).
      *It is the `sub`, a UUID; the username arrives separately in
      `X-Auth-Request-Preferred-Username`. `docs/05` said sAMAccountName and is
      corrected — reading `X-Auth-Subject` from it would have keyed the
      kill-switch index on a renameable value. Groups arrive as flat names,
      which is what ADR-0008 matches on*
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

- [x] Keycloak realm is **imported from `keycloak/realm/`** at first boot, not
      clicked together by hand — otherwise `docker compose up` does not produce a
      working realm and the lab is not reproducible (`keycloak/README.md`).
      The committed export carries **no real secrets** (scrubbed client secret,
      no LDAP bind password); how the real secret is injected at import — env
      substitution or a post-import step — is settled here (`docs/07`).
      *Settled: env substitution works, and only as `${VAR}` — `$(env:VAR)` and
      `${env.VAR}` import cleanly and leave the literal placeholder as the
      client secret. Three more traps measured on the way: the file name must
      match the realm name or Keycloak refuses to start; a `clientScopes` array
      **replaces** the built-in scopes, which deletes `profile`/`email` and
      breaks every login with `invalid_scope`; and without an audience mapper
      the token carries no `aud` and oauth2-proxy rejects it. The LDAP
      federation half of this realm waits for samba-ad*
- [ ] Start `INSTALL.md` **while doing all of the above**, not in Phase 6. Phase 1
      is an installation: DNS, the wildcard certificate, the realm import, the
      LDAP bind account, `ADMIN_GROUP` and the first login all happen here.
      Reconstructing them five phases later from memory is how installation
      documentation becomes wrong.
      *First draft landed with the certificate item: prerequisites,
      certificate, name resolution, `.env`, start. Grown since with the OIDC
      client secret, the cookie secret and the lab user password, and with how
      the realm is re-imported*

**Output:** authentication works end to end, the latencies are known, `INSTALL.md`
has a first draft, and there is still not one line of code.

## Phase 2 — Schema + decision (backend)

- [ ] `backend/migrations/0001_init.sql`: application, entitlement, audit_event
      (`known_user` and `entitlement.conditions` are not in v1 — `docs/02` "Data model")
- [ ] The `audit_event` schema **starts** with its summary columns: `count`,
      `first_seen`, `last_seen`, `distinct_path`, plus `first_path` / `src_ip` /
      `request_id` taken from the first request folded into the row — and no
      `user_agent` (`docs/02`, "Data model"). The table is partitioned by month
      and its PK is `(id, ts)` — Postgres requires the partition key in the PK.
      The migration also creates a **DEFAULT partition**: without one, an INSERT
      for an uncovered month errors, and audit writes fail off the request
      path — silently. Adding any of this later is a breaking change — the audit
      record format is immutable (`docs/02`, CONTRIBUTING.md)
- [ ] The backend applies `migrations/` itself on startup (sqlx runtime migrator)
      and **exits if a migration fails** rather than serving on an unknown schema.
      An operator should never have to run a migration by hand on first install
- [ ] `backend/src/policy.rs`: the decision function — pure, no DB, no HTTP
- [ ] `policy.rs`: URI normalisation (drop the query, one decode round, resolve
      `..`/`//`, lowercase) + matching **at a segment boundary**
- [ ] **Test:** `/%61dmin/`, `//admin/`, `/x/../admin/`, `/admin` (no slash),
      `/adminx` → does the `/admin/*` deny rule hold in all of them
- [ ] **Test:** double encoding (`%2561`) → DENY `malformed_uri`
- [ ] **Test:** `%00`, control bytes, invalid UTF-8 after decoding → DENY
      `malformed_uri` (NUL truncation — `docs/05`)
- [ ] **Test:** default deny (no match means deny)
- [ ] **Test:** deny overrides allow
- [ ] **Test:** an expired entitlement is ignored
- [ ] The `ADMIN_GROUP` check — a separate pure function, never cached
- [ ] **Test:** an ordinary user with portal access cannot reach `/api/admin/*`
- [ ] `backend/src/store.rs`: the entitlement query + audit writing (off the
      decision path, bounded channel; a full channel does not block the request)
- [ ] Shutdown flushes the cache's audit counters to the channel before exiting —
      otherwise up to one TTL of summaries is lost on every restart (`docs/02`,
      "Audit granularity"). A hard crash still loses them; that is accepted

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
- [ ] On a cache miss the backend already holds the raw cookie: it records
      `sub → oauth2-proxy session key` in Redis for the kill switch (ADR-0019).
      This is the backend's only Redis use; it stores keys, not tokens. The
      write lands **before** the ALLOW is returned; a failed write is a DENY
      `store_unavailable` — a session the kill switch cannot find must not gain
      access
- [ ] **Test:** index write failure → DENY (Redis accepting reads but refusing
      writes)
- [ ] **Test:** cache TTL, key isolation, single-flight (50 concurrent requests → 1 refresh)
- [ ] **Test:** an entry leaving the cache by any road — TTL, LRU eviction,
      logout, kill switch — flushes its counters to the audit channel first
      (`docs/02`, "Audit granularity")
- [ ] `backend/Dockerfile`: multi-stage build
- [ ] `nginx/conf.d/00-auth.conf`: `auth_request`, `error_page 401 = @signin`,
      `error_page 403 = @denied` → **302** to the portal host,
      `error_page 500 502 503 504 = @unavailable` → local static page
- [ ] `/oauth2/*` anonymous; the portal host open to every authenticated user
- [ ] **Test:** an unauthorised user sees the `/denied` page (no loop)
- [ ] The `/decide` include: `X-App-Slug` (fixed), `X-Original-URI`,
      `X-Original-Method`, `X-Real-IP`, `X-Request-Id` — written unconditionally,
      **and the `X-Auth-*` family cleared** (`proxy_set_header … "";`). The
      subrequest inherits client headers verbatim (VERIFY (3)); the upstream
      strip include does not run on this path
- [ ] `nginx/conf.d/20-apps.conf`: protected applications, **strip** incoming
      `X-Auth-*` headers
- [ ] `proxy_read_timeout 300s` on protected locations — cuts idle long-lived
      connections only; active ones are outside the N-03 guarantee (ADR-0016)
- [ ] `Origin` check on state-changing `/api/admin/*` endpoints
- [ ] Rate limiting (pulled forward from Phase 6 — audit and backend are a single
      point of failure)
- [ ] **Test:** a forged `X-Auth-Groups` grants no access
- [ ] **Test:** a forged `X-Auth-Request-Groups` does not reach `/decide` either —
      the subrequest path, not just the upstream one (VERIFY (3))
- [ ] **Test:** every location carrying `auth_request` answers from the content
      phase — no `return` (VERIFY (3): `return` runs before `auth_request` and
      leaves the location open). Cheap form: grep the generated and
      hand-written blocks
- [ ] **Test:** a forged `X-Original-URI` / `Host` cannot borrow another
      application's entitlements
- [ ] **Test:** an unauthenticated request is redirected to login
- [ ] `GET /healthz` and `GET /readyz` (`docs/02`) — internal network only.
      Without them a fail-closed blackout and a working deny policy look identical
      from outside, and there is nothing for the Phase 6 health check to poll
- [ ] `/decide` reachable only from the internal network (`internal;`)
- [ ] Diagnostics: `X-Deny-Reason` into the access log; `request_id` correlating
      nginx with audit

- [ ] `docs/08-breakglass.md`: the runbook itself — the symptom that justifies
      pulling it (`/readyz` is what tells you), the command, how to verify the
      applications came back, what is unprotected while it is active, and how to
      go back. **It lives in the repository, not on the maintainer's machine:**
      the moment it is needed is the moment one laptop is not enough
- [ ] **Rehearse it** and write the measured time into the runbook. ADR-0017 is
      satisfied by the rehearsal, not by the file existing

**Exit criterion:** end-to-end access control **and a rehearsed break-glass**
(a second nginx config in the same image, `--profile breakglass`). Everything up
to here is a usable system — and the proof of usability is the break-glass.

## Phase 4 — Minimal admin (before the portal)

So the portal's data does not have to be filled in by hand with SQL.

- [ ] Application CRUD + `upstream_url` validation (scheme/host/port; loopback,
      link-local and infrastructure services rejected); `external_hostname`
      must not collide with the reserved `portal` / `auth` hosts (ADR-0011)
- [ ] AD group ↔ application mapping (allow/deny)
- [ ] **nginx config generation** (ADR-0011): generate from the template →
      `nginx -t` → reload. If validation fails, the current config stays in effect
- [ ] **Test:** every generated location contains the `X-Auth-*` stripping include
- [ ] `nginx/conf.d/10-portal.conf`: the portal host — frontend static files,
      `/api/*` → backend
- [ ] `GET /api/me`, `GET /api/apps`
- [ ] Admin mutations and kill switch invocations recorded to the structured
      log — actor, action, target, outcome (F-14, `docs/02` "Management plane")

## Phase 5 — Portal + audit + kill switch

- [ ] Portal: reachable applications, buttons with icons
- [ ] The "no access" page — where `error_page 403` lands
- [ ] Empty state: "you have access to no applications"
- [ ] Frontend files served by nginx — baked into the nginx image at build
      (ADR-0020), no frontend container or volume
- [ ] **VERIFY:** Alpine.js under a `default-src 'self'` CSP — the standard
      build needs `unsafe-eval`; if it fails, vendor the CSP build or amend
      ADR-0007 (`docs/07`)
- [ ] Audit log viewing + filtering
- [ ] `GET /api/admin/explain?user&host&path` — why the decision was made.
      `policy.rs` is already pure; the screen ops will use most
- [ ] Kill switch, four steps in this fixed order (ADR-0019): Keycloak
      `logout-all` → the session keys from the `sub → session` index → that user's
      decision-cache entries → the index entry. Only that user's entries are
      dropped; flushing the whole cache is self-DoS
- [ ] **Test:** access is cut after a kill switch **and the cache does not
      refill**; the dropped entries' counters land in the audit channel, not
      the void
- [ ] **MEASURE:** kill switch end to end — is it under the 5 s of N-03?
      A user still signed in elsewhere is not cut: their entry never existed in
      the index if they never hit `/decide` on this instance
- [ ] **Test:** an **idle** WebSocket connection is cut within `proxy_read_timeout`
      (an active one is not — ADR-0016 excludes it, do not assert otherwise)
- [ ] Logout: all three steps (`docs/02`, "Logout") — the backend step is
      `POST /api/logout`, called **before** the sign-out redirect; reversed, a
      request in the gap refills the cache from the still-live session

## Phase 6 — Hardening and packaging

- [ ] **Deprovisioning delay test** — does the N-03 target hold (repeat the Phase 1
      measurement)
- [ ] Security headers, TLS settings, the certificate renewal path
- [ ] Backup/restore procedure, migration rollback
- [ ] Audit retention job (N-04) and partition maintenance
- [ ] Monitoring: decision latency, error rate, cache hit rate, audit loss counter
- [ ] Versioning, release image, offline bundle for air-gapped installation
- [ ] SPDX identifier in `Cargo.toml`, licence headers, Alpine.js MIT notice preserved (ADR-0013)
- [ ] Finish `INSTALL.md` (drafted in Phase 1): DNS, wildcard certificate,
      `ADMIN_GROUP`, first login, and the prerequisites an operator cannot skip —
      write access to AD for the `OpenBerat-` groups, a common parent domain
      (ADR-0015), a Keycloak service account
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
