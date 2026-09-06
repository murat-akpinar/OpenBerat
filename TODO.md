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
- [x] Publish `SECURITY.md` — now at the repository root, so GitHub renders it
      as the policy in the Security tab. The **"Report a vulnerability" button
      the file sends reporters to is a separate repository setting**, not
      something the file turns on: private vulnerability reporting was off, so
      the first channel in the policy did not exist. Enabled and verified
      (`gh api repos/OWNER/REPO/private-vulnerability-reporting` → `enabled:
      true`). Linked from both READMEs and `CONTRIBUTING.md`, which no longer
      repeats the policy. Its scope section says "no released version yet";
      rewriting it is part of the Phase 6 versioning item

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
      *Blocked with the five boxes below it: `samba-ad` cannot provision on the
      current lab host. Two failures, both in `docs/07` — the DC's short name
      collided with the domain's NetBIOS name (fixed: `dc01` in
      `example.local`), and then provisioning panicked writing the sysvol ACLs
      because the host is an unprivileged LXC and a user namespace refuses
      `security.*` xattrs, as root, outside Docker. Not the image: the same
      wall with Samba 4.15 and 4.22, privileged, unconfined, on a volume, with
      `posix:eadb`. Needs bare metal, a VM or a privileged container
      (ADR-0010, `INSTALL.md`)*
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
- [x] **VERIFY (4):** can the oauth2-proxy Redis session key be derived from the
      session cookie? Log in, read the cookie, list the Redis keys, and delete the
      matching one — access must stop immediately. Repeat after a
      `cookie_refresh` has fired: if the refresh mints a new ticket, the index
      must still find the live session (the new key arrives via the next cache
      miss). **ADR-0019 and with it the 5 s
      kill-switch target rest on this**; if it fails, ADR-0019 falls back to
      option C and ADR-0016 is revised in the same commit
      *Answer: yes — ADR-0019 holds. The Redis key derives from the cookie the
      backend already holds: strip the `|ts|hmac` signature, base64-decode the
      `v2.<handle>.<secret>` ticket, base64url-decode the handle → the live
      `_oauth2_proxy-<hex>` key (matched exactly against a labuser login).
      Deleting it flips the next request 202/200 → 401/302 with no backend in
      front — the oauth2-proxy/Redis layer the kill switch acts on. The key is
      byte-identical across a `cookie_refresh` (only the signed timestamp rotates
      the cookie), so the index written on the first cache miss never goes stale;
      the deletion test was re-run after a refresh had fired and behaved
      identically. Option C is not needed, ADR-0016's 5 s target stands. Both
      halves in `docs/07`; the one-shot test is `verify4.sh` on the lab host.*
- [ ] Keycloak LDAP federation → can an AD user log in
- [ ] `userAccountControl` filter → a disabled account cannot log in
- [ ] Group mapper `GET_GROUPS_FROM_USER_MEMBEROF_ATTRIBUTE` → `groups` claim in the token
- [ ] **Nested group test:** does a user in a parent group see the child group?
      If not, switch to `LOAD_GROUPS_BY_MEMBER_ATTRIBUTE_RECURSIVELY`
- [x] User in many groups → is the cookie size problem gone with the Redis session
      *Yes — and it took the ceiling with it to a place nothing warns about.
      Ramped labuser to 800 generated groups: the session cookie stays **192
      bytes** at every step, one cookie, never chunked; the Redis value carries
      the growth (3.3 KB → 66 KB). But every group name comes back comma-joined
      in one `X-Auth-Request-Groups`, and nginx reads a response header block
      into a **single** `proxy_buffer_size` buffer (4 KB): between 100 and 200
      groups `/oauth2/auth` turned 502 and `auth_request` mapped it to **500 for
      the client** — a total lockout of the accounts with the most AD groups,
      clean `nginx -t`, no warning anywhere. Fixed with `proxy_buffer_size 32k`
      + `proxy_buffers 4 32k` on the subrequest location (raising the first
      alone makes nginx refuse to start); re-measured green through 800 groups.
      Both halves and the numbers in `docs/07`, rule 15 in
      `nginx/conf.d/README.md`*
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
- [x] nginx `auth_request` + `error_page 401 = @signin` (mind the `=`) → login redirect
      *Works end to end: anonymous request → Keycloak → back on the page that
      was asked for. Two things underneath it were not what the configuration
      claimed. The return address went into `?rd=$scheme://$host$request_uri`,
      which nginx cannot percent-encode, so the client's own `&` started a new
      parameter of `/oauth2/start`: `/index.html?a=1&b=2` came back as
      `/index.html?a=1` — a 200 with half the query silently gone — and an
      injected `rd` arrived as a second one (not exploitable; the first wins and
      `whitelist_domains` sits behind it). Fixed by carrying the target in
      `X-Auth-Request-Redirect` and proxying to `/oauth2/start`: the query comes
      back whole and the browser makes one round trip fewer. And the `=` this
      repository calls mandatory was **inert** with a `return` handler — it only
      bites when the error is answered by a proxied response, which is exactly
      what the fix made it. Both halves in `docs/07`, rule 1 in
      `nginx/conf.d/README.md` rewritten, one row added to `docs/05`'s attack
      table; the one-shot test is `verify-signin.sh` on the lab host*
- [x] **MEASURE:** double-hop latency with a three-line fake `/decide` (draft N-01/N-02).
      Wait for the real backend and you only see the number that justifies the
      architecture in Phase 3.
      *Measured (`docs/07`). Five paths, identical content phase, one variable
      changed. **A cache hit costs +74 µs, a cache miss +571 µs, and the whole
      architecture costs +126 µs over the stock oauth2-proxy pattern** — that
      last figure is what ADR-0002 is spending to run the chain inside the
      backend. The `auth_request` machinery itself is free (+6 µs); the hop is
      what costs. N-01 drafted at **< 2 ms** and N-02 at **< 10 ms** in
      `docs/06` — both still loose, because the fake `/decide` does no work and
      the real miss adds the entitlement query and the index write. Method note
      for Phase 6: two rounds in nine had all five paths displaced ~3 ms at once
      by in-guest CPU contention, so the headline is the median of per-round
      p50s, and under contention the double hop degraded first and furthest.*
- [ ] **MEASURE:** remove a user from a group in AD → how many seconds until access
      is cut? Verify the `cookie_refresh` + cache TTL sum, compare with N-03
- [x] **MEASURE:** an **active** WebSocket connection (steady traffic, not idle) —
      how long does access survive after the user is removed from the group?
      `proxy_read_timeout` is an idle timeout and will not cut it; this measurement
      quantifies the limitation ADR-0016 states rather than testing a fix
      *Answer: indefinitely — measured to 500 exchanges, 489 s of them after the
      group was gone (`docs/07`). One connection and one HTTP poller on the same
      cookie and the same authz target: the HTTP path was cut 292 s after the
      group was removed, at the `cookie_refresh` boundary, and the WebSocket
      carried on at 0.2 ms a frame. The two levers an operator would reach for
      do not reach it either — the session was deleted from Redis at the cut
      and the connection ran 195 s with no session at all, and `nginx -s reload`
      (the ADR-0011 path on every application change) left the old worker
      `shutting down` and still serving under the old configuration, 133 s and
      two reloads later. `worker_shutdown_timeout` is unset, so a worker
      accumulates per reload while a long-lived connection is open — new open
      question in `docs/06`. Only restarting nginx cut it, which is an outage,
      not a revocation. Harness: `verify-ws.sh` + `wsclient.py` on the lab host*

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
      the realm is re-imported. §1–§4 then **replayed from a clean checkout** on
      the lab host, following only the document: three things were wrong, all
      of them something the lab host already had and the document never said.
      `certs/` is gitignored so a fresh clone cannot write the key into it; the
      documented `openssl rand -base64 32` cookie secret is **refused** by
      oauth2-proxy (44 characters, non-URL-safe alphabet — and the check is
      strict only because ADR-0006 mandates `cookie_refresh`); and a base64
      `POSTGRES_PASSWORD` breaks `DATABASE_URL` with an error that names the
      port. Fixed, and the replay then ran through to a 200 on the portal
      (`docs/07`). The box stays open for the LDAP bind account and
      `ADMIN_GROUP`, which wait on samba-ad*

**Output:** authentication works end to end, the latencies are known, `INSTALL.md`
has a first draft, and there is still not one line of code.

## Phase 2 — Schema + decision (backend)

- [x] `backend/migrations/0001_init.sql`: application, entitlement, audit_event
      (`known_user` and `entitlement.conditions` are not in v1 — `docs/02` "Data model")
- [x] The `audit_event` schema **starts** with its summary columns: `count`,
      `first_seen`, `last_seen`, `distinct_path`, plus `first_path` / `src_ip` /
      `request_id` taken from the first request folded into the row — and no
      `user_agent` (`docs/02`, "Data model"). The table is partitioned by month
      and its PK is `(id, ts)` — Postgres requires the partition key in the PK.
      The migration also creates a **DEFAULT partition**: without one, an INSERT
      for an uncovered month errors, and audit writes fail off the request
      path — silently. Adding any of this later is a breaking change — the audit
      record format is immutable (`docs/02`, CONTRIBUTING.md)
      *Both landed in one file, checked by `backend/tests/schema.rs` against a
      real Postgres 17. Three things the design documents did not say, decided
      here and written back into `docs/02`: `audit_event` carries **no foreign
      key** to `application` and denormalises `application_slug` beside the id —
      with a key, deleting an application either destroys its audit trail or
      cannot be done, and a decision made for an unknown `X-App-Slug` never had
      a row to point at anyway; the `slug` and `external_hostname` CHECK
      constraints are a security boundary rather than tidiness, because ADR-0011
      interpolates both into generated nginx config straight from the table; and
      the wildcard entitlement (`application_id IS NULL`, `docs/05` rule 4)
      needs `UNIQUE NULLS NOT DISTINCT`, or the one dangerous rule is the only
      one a double-clicked admin form can duplicate. The test skips itself
      without `DATABASE_URL`, so CI grew a Postgres service in the same commit —
      otherwise the migration would reach an operator having never been run.
      Both new assertions were checked by mutation (drop the DEFAULT partition,
      loosen the slug CHECK → both fail)*
- [x] The backend applies `migrations/` itself on startup (sqlx runtime migrator)
      and **exits if a migration fails** rather than serving on an unknown schema.
      An operator should never have to run a migration by hand on first install
      *`store::connect` — connect, migrate, and a failure of either is fatal.
      All four outcomes run against the real binary, not only the test: empty
      database → applied, exit 0; an applied migration edited underneath it →
      `exit 1`; no `DATABASE_URL` → `exit 1`; unreachable database → `exit 1`.
      That last one cost 30 s of the test suite before the pool grew an explicit
      5 s `acquire_timeout` — sqlx's default is 30 s, so an absent Postgres held
      the process half a minute before compose could retry it. `src/lib.rs`
      arrives with this box so integration tests can reach the modules at all.
      Documented in `INSTALL.md` §4: no `psql` on a first install, no migration
      step on an upgrade*
- [x] `backend/src/policy.rs`: the decision function — pure, no DB, no HTTP
- [x] `policy.rs`: URI normalisation (drop the query, one decode round, resolve
      `..`/`//`, lowercase) + matching **at a segment boundary**
      *`decide` takes the **raw** `X-Original-URI` and normalises inside itself
      rather than trusting a caller to have done it — the one hole in this
      design is somebody matching the raw string, and a signature that cannot
      express that closes it. Two attacks the design documents did not list
      were found writing the tests and are now rows in `docs/05`: a Windows
      upstream reads `\` as a separator, so `/x\..\admin/` reaches IIS as
      `/admin/` while a resolver that only knows `/` leaves the deny rule
      unmatched; and `%2f` decodes to a separator, so decoding has to happen
      before resolution rather than after. A third, `;` path parameters that
      Tomcat and Jetty strip, is left open in `docs/06` — folding it changes
      what a legitimate path means, and the answer depends on what runs behind
      the proxy. `char::is_control` is Cc only, so U+2028 is not a control
      character and the test was corrected to claim only what the check does.*
- [x] **Test:** `/%61dmin/`, `//admin/`, `/x/../admin/`, `/admin` (no slash),
      `/adminx` → does the `/admin/*` deny rule hold in all of them
- [x] **Test:** double encoding (`%2561`) → DENY `malformed_uri`
- [x] **Test:** `%00`, control bytes, invalid UTF-8 after decoding → DENY
      `malformed_uri` (NUL truncation — `docs/05`)
- [x] **Test:** default deny (no match means deny)
- [x] **Test:** deny overrides allow
- [x] **Test:** an expired entitlement is ignored
      *Both directions: an expired **deny** stops denying too, which is what
      `docs/05` rule 5 says and is worth seeing in a test rather than assuming*
- [x] The `ADMIN_GROUP` check — a separate pure function, never cached
      *`is_admin` — exact, case-sensitive match. ADR-0008 already chose the
      direction to fail in: a group renamed in AD loses its entitlements.*
- [ ] **Test:** an ordinary user with portal access cannot reach `/api/admin/*`
      *Half done and deliberately left open: the pure half is tested with
      `is_admin` (a portal user, a look-alike group name and a differently
      cased one are all refused), but there is no `/api/admin/*` handler to
      reach until Phase 4. The box closes there, against the endpoint.*
- [x] `backend/src/store.rs`: the entitlement query + audit writing (off the
      decision path, bounded channel; a full channel does not block the request)
      *`rules_for` returns the application and the rules in one call; expiry is
      deliberately **not** filtered in SQL, because the rows live in a cache
      entry for a TTL and `policy.rs` re-checks `expires_at` on every hit —
      filtering at query time would freeze the answer and keep an expired grant
      alive for the rest of the TTL. Both of those, and the `application_id IS
      NULL` wildcard join, were checked by mutation. `Audit::record` uses
      `try_send` and never waits: a blocking send would put the audit write back
      on the decision path, so a slow Postgres would become a slow `/decide`
      and, through the timeout budget, a denial. A dropped summary increments
      `audit_dropped()` and logs. The decision vocabulary is one enum for both
      the column and the code — an allow row's reason is `allowed` (`docs/02`).*
- [x] Shutdown flushes the cache's audit counters to the channel before exiting —
      otherwise up to one TTL of summaries is lost on every restart (`docs/02`,
      "Audit granularity"). A hard crash still loses them; that is accepted
      *Closed with the cache below. SIGTERM and SIGINT both caught, then the
      order: flush the cache, drop every audit sender, wait for the writer. The
      first live run hung forever on that wait — the **sweeper task** holds an
      `Arc` of the cache, so a sender never dropped and the writer never
      finished; Docker's SIGKILL would have taken the queue with it, and the
      test suite could not have found it because nothing there runs `main`. The
      sweeper is aborted first now, and the drain is bounded at 5 s so a stuck
      Postgres reports the loss instead of waiting for the kill.*

## Phase 3 — `/decide` and closing the chain

- [x] `backend/src/api.rs`: `GET /decide` — forward the cookie to oauth2-proxy, take
      the identity, decide
      *Identity is read from oauth2-proxy's **response** and from nowhere else,
      so a forged `X-Auth-Request-Groups` on the way in cannot reach the
      decision even with nginx out of the picture — there is a test for it
      rather than a claim. The whole thing was then run as the real binary
      against a real Postgres and a stand-in oauth2-proxy: anonymous → 401,
      allow → 200 with the four identity headers, `/%61dmin/users` →
      `explicit_deny`, unknown slug → `application_disabled`, nothing listening
      → `auth_unavailable`. `main.rs` now serves, so the container no longer
      exits at startup and `INSTALL.md` §4 starts it.*
- [x] `/decide` **never returns 5xx**: on a DB error, 403 `store_unavailable`
      *And 403 `auth_unavailable` when it is oauth2-proxy rather than Postgres —
      a new reason, in `docs/02`. One reason for both would have been cheaper
      and would leave the operator restarting the wrong service.*
- [x] The `Set-Cookie` from oauth2-proxy is relayed verbatim
      *On **every** outcome, not only on 200. oauth2-proxy refreshes the session
      on the subrequest before the decision exists, so relaying it only on an
      allow means a denied user never refreshes again and their groups freeze
      until the cookie expires — ADR-0006 collapsing quietly, one denial at a
      time. `docs/02` says so now.*
- [x] Timeout budget decreasing outward-in: `/decide` 2s → oauth2-proxy 1s → sqlx 500ms
      *All three: `proxy_connect_timeout 1s` + `proxy_read_timeout 2s` on the
      subrequest location, oauth2-proxy at 1 s inside the backend, the
      entitlement query at 500 ms. nginx's default is 60 s, which is how a slow
      backend becomes a stopped system rather than a denied request.*
- [x] Decision cache: key `(cookie_hash, app_slug)`, value **identity + the
      matching rule list + per-outcome counters**; `policy.rs` evaluates the
      cached rules against the normalised path on every hit. Single-flight
      refresh, bounded LRU, `sub → keys` reverse index (`docs/05`)
      *`cache.rs`. Three things came out different from the sketch. **No
      session cookie means no key at all** rather than a key over an empty
      value: if `COOKIE_NAME` ever drifts from `oauth2-proxy.cfg`, hashing what
      was found would give every user the same key and the first to fill an
      entry would hand their identity to everyone else — a total authorisation
      failure with no error anywhere. A miss per request is the cheap way to be
      wrong, and there is a test for it. The chunk suffix (`_0`, `_1`) has to be
      **digits** for the same family of reasons: a client can set any cookie it
      likes on the shared domain (ADR-0015), and a prefix match would let
      `_oauth2_proxy_anything` move its own key on every request. **Eviction is
      by insertion order, not LRU** — under one uniform TTL the oldest entry is
      also the one closest to expiring, while an LRU would evict a fresh entry
      nobody had asked for yet; `docs/05` says so now. Single-flight is 16 fill
      locks rather than one per key: nothing to clean up, and two keys sharing a
      shard only serialise their misses.*
- [x] On a cache miss the backend already holds the raw cookie: it records
      `sub → oauth2-proxy session key` in Redis for the kill switch (ADR-0019).
      This is the backend's only Redis use; it stores keys, not tokens. The
      write lands **before** the ALLOW is returned; a failed write is a DENY
      `store_unavailable` — a session the kill switch cannot find must not gain
      access
      *`session.rs`. The derivation was not trusted to a round-trip test —
      `session_key` was run over a cookie from a live `ob-login.sh` login on
      `vaultscan`, and the key it produced was present in that Redis at that
      moment. Two things only the real cookie showed: the outer layer is
      **padded standard** base64 while the handle inside is URL-safe and
      unpadded, so a decoder that assumes one alphabet silently fails on the
      other; and the decoded handle **is** the key as ASCII, not bytes needing
      hex encoding. Both in `docs/07`. The write is ordered before the cache
      insert as well as before the ALLOW — cache first would let the next hit
      allow with no index behind it. An authenticated cookie that yields no
      derivable key is also a DENY: it is a session the kill switch could never
      find, which is the same hole by a different road. The index entry expires
      after 8 days, longer than `cookie_expire` on purpose — too long only means
      deleting a key that has already gone.*
- [x] **Test:** index write failure → DENY (Redis accepting reads but refusing
      writes)
      *Not simulated: a real Redis with `CONFIG SET maxmemory 1`, which is the
      state ADR-0019 names — reads keep working, writes get OOM. The request
      denies with `store_unavailable`. CI grew a Redis service alongside the
      Postgres one so this runs there too. Then confirmed against the running
      binary: an allowed request wrote
      `openberat:sessions:sub-labuser → _oauth2_proxy-…` with an 8-day TTL.*
- [x] **Test:** cache TTL, key isolation, single-flight (50 concurrent requests → 1 refresh)
      *All three, and the single-flight one counts calls at the stand-in
      oauth2-proxy: fifty concurrent requests on a cold key → **one**. A hit
      then costs nothing upstream, and a hit on `/admin/users` still denies —
      what is cached is the rule list, not the verdict, so a deny can never be
      skipped by two paths colliding on one key.*
- [x] **Test:** an entry leaving the cache by any road — TTL, LRU eviction,
      logout, kill switch — flushes its counters to the audit channel first
      (`docs/02`, "Audit granularity")
      *Five roads, each walked and the summary read back off the channel: TTL
      sweep, the capacity bound, `drop_sub` (logout and the kill switch),
      shutdown, and one the list did not have — an entry **replaced by a
      refill**, which is an exit road like any other. Then confirmed against the
      running binary: 21 requests wrote **zero** rows while the entry lived, and
      SIGTERM produced exactly two — one allow with `count=20, distinct=20`, one
      deny with `count=1` — which is the whole of what "count decisions,
      summarise rows" was supposed to mean.*
- [x] `backend/Dockerfile`: multi-stage build
      *Written with the compose skeleton in Phase 1 and only confirmed here:
      the image builds from a clean context with the modules, migrations and
      the three new dependencies in it, and the container it produces is what
      the local stack below ran.*
- [x] `nginx/conf.d/00-auth.conf`: `auth_request`, `error_page 401 = @signin`,
      `error_page 403 = @denied` → **302** to the portal host,
      `error_page 500 502 503 504 = @unavailable` → local static page
      *Split across four files rather than one, because `nginx.conf` includes
      `conf.d/*.conf` into the `http` block and a bare `location` there is a
      syntax error — the shared pieces are `errors.inc`, `decide.inc` and
      `protected.inc`, and `00-auth.conf` holds only what belongs at http
      level. The README table said otherwise and is corrected. One more
      correction the writing forced: the unavailable handler takes **no `=`**.
      With it nginx answers with the handler's status — 200 for a static
      file — and an outage becomes indistinguishable from a working page. The
      `=` on `error_page 401` is still load-bearing for the opposite reason.*
- [x] `/oauth2/*` anonymous; the portal host open to every authenticated user
      *Both confirmed against the running stack: the portal answers 200 to any
      authenticated user without consulting `/decide`, and an unknown vhost now
      answers 404 rather than being served by the default server — with a
      wildcard certificate, the first `:443` block otherwise answers for every
      name in the domain.*
- [x] **Test:** an unauthorised user sees the `/denied` page (no loop)
      *`/admin/users` → 302 to `portal…/denied?app=sample.apps.example.local`,
      and that page answers 200. One hop, no loop. `/%61dmin/users` takes the
      same road, which is `policy.rs`'s normalisation showing up at the far end
      of the chain rather than in a unit test.*
- [x] The `/decide` include: `X-App-Slug` (fixed), `X-Original-URI`,
      `X-Original-Method`, `X-Real-IP`, `X-Request-Id` — written unconditionally,
      **and the `X-Auth-*` family cleared** (`proxy_set_header … "";`). The
      subrequest inherits client headers verbatim (VERIFY (3)); the upstream
      strip include does not run on this path.
      Also `proxy_buffer_size 32k` + `proxy_buffers 4 32k`: `/decide` returns the
      user's whole group list in one header, and the 4 KB default turns a
      many-group user into a 500 (measured, `docs/07`)
      *`decide.inc`. `X-App-Slug` comes from `$app_slug`, `set` once per server
      block — a variable rather than a literal only so the include can stay
      shared; the value is still nginx's, never the request's. A server that
      forgets to set it sends empty and the backend denies `missing_context`,
      which is the right direction to fail in.*
- [ ] **Check the backend's own HTTP client header limit** the same way — it
      reads oauth2-proxy's response, which carries that same group list. The
      nginx half is measured; this half is not
- [x] `nginx/conf.d/20-apps.conf`: protected applications, **strip** incoming
      `X-Auth-*` headers
      *Hand-written for the two lab samples, and deliberately shaped as the
      template ADR-0011 will generate in Phase 4: a constant `$app_slug`, two
      includes, one `proxy_pass`. Nothing per-application is left to remember.*
- [x] **Strip the `_oauth2_proxy` session cookie before proxying** — a `map`
      rewriting `$http_cookie` in the shared include, applied to every protected
      location **and to the Keycloak host**, which forwards it today. An upstream
      that receives it holds a credential valid for every host on
      `.apps.<domain>` (`docs/05` attack table, ADR-0015). `docs/05` already
      names the test; nothing built the thing it tests
      *Done, and it is a rewrite of the header rather than dropping it: an
      application that loses its own cookies is broken, not secured. Confirmed
      against the running stack — the upstream saw `mode=valid; app_pref=dark`
      and no `_oauth2_proxy`. The Keycloak host has it too.*
- [x] `proxy_read_timeout 300s` on protected locations — cuts idle long-lived
      connections only; active ones are outside the N-03 guarantee (ADR-0016)
      *Set in `protected.inc`, alongside the `Upgrade`/`Connection` pair a
      WebSocket needs. Verified: `101 Switching Protocols` through the PEP.*
- [ ] `Origin` check on state-changing `/api/admin/*` endpoints
      *Waits for Phase 4: there is no `/api/admin/*` handler to put it on, and
      a check written against an endpoint that does not exist is a check nobody
      ever ran. It belongs in the same commit as the first admin mutation.*
- [x] Rate limiting (pulled forward from Phase 6 — audit and backend are a single
      point of failure)
      *Two zones, both per address: 50 r/s for decisions with a burst of 100 —
      one page of fifty assets is fifty decisions — and 5 r/s for the login
      flow, which is the sharper limit because every request through it reaches
      Keycloak. `limit_req_status 429` and not 503, or `error_page` would catch
      it and serve the "unavailable" page, telling the user the access control
      service is down when it is working exactly as configured. Both numbers
      are guesses and are written down as guesses: N-07 is still open, and the
      case that breaks them first is a site behind NAT where one address is an
      office. Noted in `docs/06` beside N-07.*
- [x] **Test:** a forged `X-Auth-Groups` grants no access
      *Against the running stack, not a unit test: a client sending
      `X-Auth-Groups: OpenBerat-Admins`, `X-Auth-Subject: root` and
      `X-Auth-Request-User: root` reached the upstream with
      `X-Auth-Groups: OpenBerat-Finance` and `X-Auth-Subject: sub-labuser` —
      the verified identity, overwriting all of it.*
- [x] **Test:** a forged `X-Auth-Request-Groups` does not reach `/decide` either —
      the subrequest path, not just the upstream one (VERIFY (3))
      *`X-Auth-Request-Groups: OpenBerat-Admins` on a path the user's real
      groups are denied still denies. Two independent things have to fail for
      this to pass: `decide.inc` clears the family on the subrequest, and the
      backend reads identity only from oauth2-proxy's response.*
- [x] **Test:** every location carrying `auth_request` answers from the content
      phase — no `return` (VERIFY (3): `return` runs before `auth_request` and
      leaves the location open). Cheap form: grep the generated and
      hand-written blocks
      *A CI job rather than a grep, because the thing being checked is
      brace-scoped and follows `include`: it expands the `.inc` files, finds
      every `location` block that ends up carrying `auth_request`, and fails on
      a `return` or a `try_files` that does not end in `=CODE`. Both checks were
      confirmed by breaking the config on purpose — `nginx -t` stays happy in
      both cases, which is the entire reason this exists. It runs over the
      generated blocks too, once Phase 4 writes them.*
- [x] **Test:** a forged `X-Original-URI` / `Host` cannot borrow another
      application's entitlements
      *Three forgeries, all refused: `X-Original-URI: /` on a request for
      `/admin/users`, `X-Forwarded-Host: portal…`, and `X-App-Slug: ws` naming
      an application the user can reach. Each is overwritten by the include
      before the subrequest leaves nginx. `X-Request-Id` too — the upstream saw
      nginx's `$request_id`, not the client's.*
- [x] **Test:** an unauthenticated request is redirected to login
      *302 into the login flow with the query string whole —
      `/reports?a=1&b=2` came back intact, which is the Phase 1 finding about
      `rd=` still holding now that the handler lives in a shared include.*
- [x] `GET /healthz` and `GET /readyz` (`docs/02`) — internal network only.
      Without them a fail-closed blackout and a working deny policy look identical
      from outside, and there is nothing for the Phase 6 health check to poll
      *Internal by omission rather than by rule: nothing in nginx proxies them
      and the backend sits only on `core`. `/readyz` **names** the dependency
      that is down rather than answering 503 bare — with Postgres unreachable
      `/decide` answers 403 for everybody, which from outside is a policy that
      denies everybody, and the name is the whole difference. Live: Redis
      stopped → `unreachable: redis` / 503, `/healthz` still 200 because it
      answers a different question, and both back to 200 when Redis returned.
      No compose `healthcheck:` yet — the runtime image carries no HTTP client
      to poll with, which is a Phase 6 packaging question.*
- [x] `/decide` reachable only from the internal network (`internal;`)
      *`internal;` specifically, not an IP ACL: nginx skips the access phase for
      a subrequest, so `deny all` in that position does nothing (VERIFY (3)).
      A direct request answers 404 against the running stack. The other half is
      the network split — the backend is on `core`, which no protected
      application joins.*
- [x] Diagnostics: `X-Deny-Reason` into the access log; `request_id` correlating
      nginx with audit
      *One line answers both questions now — measured end to end:
      `user="labuser" deny="explicit_deny" id=4f10…` in nginx, and the
      `audit_event` row with **the same id** carrying `actor=labuser
      reason=explicit_deny path=/admin/secret`. Getting the `user` half needed a
      contract change: `/decide` returned the identity headers on a 200 only, so
      a denied line could say why but not who — which is the one question anyone
      asks about a denial. It now returns them on a DENY too. Nothing is proxied
      upstream after a deny so nothing is rewritten from them, and they never
      reach the client: `auth_request` response headers stop at nginx. `docs/02`
      updated.*

- [x] `docs/08-breakglass.md`: the runbook itself — the symptom that justifies
      pulling it (`/readyz` is what tells you), the command, how to verify the
      applications came back, what is unprotected while it is active, and how to
      go back. **It lives in the repository, not on the maintainer's machine:**
      the moment it is needed is the moment one laptop is not enough
      *Plus a `nginx-breakglass` compose service behind `profiles: [breakglass]`
      and a second complete nginx configuration inside the same image. It takes
      the same `:443`, so the two cannot run at once and there is no state where
      half the traffic is authorised. Incoming `X-Auth-*` are **still** stripped
      while it is active: an upstream that trusts those headers cannot tell the
      PEP has been bypassed, and leaving them alone would turn "no
      authorisation" into "authorisation the client writes for itself". Every
      request is logged with a `BREAKGLASS` prefix and answered with
      `X-OpenBerat-Breakglass: active`, so the window is greppable afterwards
      and "is it still on?" is one curl.*
- [x] **Rehearse it** and write the measured time into the runbook. ADR-0017 is
      satisfied by the rehearsal, not by the file existing
      *Rehearsed on a local `docker compose` stack with the backend stopped —
      the real outage, not a simulated one. **2.4 s off → on, 4.4 s back**,
      both from the first command to the verification passing. Two things the
      rehearsal found that reading the procedure would not have: the first
      attempt silently started a **stale `openberat-nginx` image** — a container
      that came up, published `:443` and was not listening on it, with nothing
      in `docker compose ps` to say so, which is why both services now share one
      `image:` name; and the verification after going back has to be "not 200"
      rather than "302", because with the chain still broken a correctly
      restored nginx answers with the unavailable page and a check insisting on
      a redirect would read that as failure. Both are in the runbook.*

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
- [ ] Versioning, release image, offline bundle for air-gapped installation.
      Rewrite the `SECURITY.md` scope section — it says there is no released
      version yet, which stops being true here
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
