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
- [x] ADR-0021 A protected application learns who the user is from the trusted
      `X-Auth-*` headers; isolating the upstream stops being a deployment
      default and becomes a requirement, because with this mechanism a
      reachable port is impersonation (measured, `docs/07`)
- [x] ADR-0022 Audit retention: the operator sets `AUDIT_RETENTION_MONTHS`
      (default 12) and a month leaves the database as a dropped partition —
      N-04 answered as a mechanism with a default, not as a number
- [x] ADR-0023 Versioning and release: one semantic version for the whole
      product, taken from `backend/Cargo.toml`; the release artifact is one
      tarball holding the tagged source and every image, because an air-gapped
      site cannot build any of them

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
      repeats the policy. Its scope section said "no released version yet";
      rewritten with the Phase 6 versioning item, which is where the supported
      versions table came from (ADR-0023)

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
- [x] **VERIFY (2):** Keycloak LDAP provider `Cache Policy` — does group membership
      go stale at anything other than `NO_CACHE`? ADR-0006 rests on this claim
      *Answer: it goes stale everywhere except `NO_CACHE`, and the worst of it
      is not the delay. At `DEFAULT` a group removed in AD survived a
      **brand-new login** — fresh session, fresh token — and was still there
      180 s later; `MAX_LIFESPAN` bounds it to its own window. So "Keycloak
      queries AD at login" is a property of the setting, not of Keycloak, and
      at `DEFAULT` nothing bounds the deprovisioning delay: not
      `cookie_refresh`, not the decision cache, not logging out. `NO_CACHE` is
      now a second mandatory line in ADR-0006's consequences next to
      `cookie_refresh`, failing the same silent way. Two more findings on the
      way, both in `docs/07`: a realm export that declares a `subComponents`
      block gets **only** the mappers it names — Keycloak's seven defaults are
      suppressed, and without `username` every LDAP user arrives with a null
      one and the import dies; and the `userAccountControl` filter does keep
      `labdisabled` out of the directory answer. The DC itself provisions on a
      KVM guest that is not a user namespace, at 262 MiB idle; the fixture is
      `samba-ad/fixture.sh` and the split-host lab wiring is in `INSTALL.md`*
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
- [x] Keycloak LDAP federation → can an AD user log in
      *Yes, and the credential never leaves AD. `labuser` logging in proves
      little — it predates the provider — so the test used `labfed`, created in
      AD after the realm was running and deleted afterwards: first-ever login
      through the real flow answered `/api/me` as `labfed`. The half worth
      keeping is the password rotation. With `editMode: READ_ONLY` the
      credential Keycloak stores carries a `federationLink` and no hash, so the
      bind is delegated on every login: changed in AD, the old password is
      refused on the very next one and the new one works — no sync period, no
      restart — and `sub` is unchanged, because it comes from `objectGUID`,
      which is what lets the ADR-0019 index key on it. Deleting the account in
      AD stops the login and drops the imported user. One trap: Keycloak listed
      `labfed` **before** any login, because with `importEnabled` a user search
      is itself an LDAP query — that list is a lookup cache, not a record of
      who has access. `docs/07`; harness `ob-login-pw.sh` on the lab host*
- [x] `userAccountControl` filter → a disabled account cannot log in
      *It cannot, and the filter is not what stops it. Tested with `labuac`,
      created in AD after the realm was running and enabled first, so the same
      credential is known to work and only the disable bit changes. With the
      filter the account is invisible and the login fails `user_not_found`; an
      already-imported user is removed. With the filter genuinely gone the login
      still fails, now `invalid_user_credentials` — AD refuses the bind, which
      `editMode: READ_ONLY` delegates on every login. What the filter alone
      stops is the **import**: without it Keycloak lists a leaver as
      `enabled: true`, because it does not read `userAccountControl`, and any
      path not ending in an AD bind reaches a live account. `docs/03`'s "leavers
      keep logging in" is corrected. F-10 measured on the same account: a
      session already open was cut between t+272 s and t+282 s, at the
      `cookie_refresh` boundary, worst case 330 s — inside N-03. Two instrument
      traps cost a wrong first answer, both in `docs/07`: `kcadm --fields
      config` omits this filter, and `kcadm update -f` merges rather than
      replaces, so removing a key from the file removes nothing*
- [x] Group mapper `GET_GROUPS_FROM_USER_MEMBEROF_ATTRIBUTE` → `groups` claim in the token
      *It does, read out of the token itself rather than out of
      `X-Auth-Request-Groups` — every earlier group observation on this stack
      was oauth2-proxy's rendering of the claim, not the claim. The harness
      drives the authorization-code flow itself and stops at the callback so the
      code is unspent, then exchanges it with its own PKCE verifier. Flat names
      in both tokens, and live within one login: a group created in AD and a
      membership added were in the next token with no sync and no restart,
      removing the membership took it back out. **The claim is a union, not a
      projection of `memberOf`** — the imported group survives its deletion in
      AD, and re-assigning it inside Keycloak put the name back in the token
      with nothing in AD behind it. Neither `READ_ONLY` nor the
      `(cn=OpenBerat-*)` filter reaches that path, and `ADMIN_GROUP` is matched
      on this claim, so reading AD does not tell you who holds admin.
      `docs/02` and `docs/03` are corrected and the reconciliation question is
      new in `docs/06`. Harness `verify-groupclaim.sh` on the lab host; both
      sides restored*
- [x] **Nested group test:** does a user who is only a *transitive* member of an
      `OpenBerat-` group see it?
      *No, and the way it fails is worth knowing: on
      `GET_GROUPS_FROM_USER_MEMBEROF_ATTRIBUTE` the token carries **no `groups`
      claim at all** — absent, not empty — so a nested-group directory denies
      every such user rather than granting them the wrong thing.
      `LOAD_GROUPS_BY_MEMBER_ATTRIBUTE_RECURSIVELY` put `OpenBerat-Finance` in
      the next token with one field changed and no restart. The finding that was
      not predicted: it resolved **across `Finance-All`**, which the
      `(cn=OpenBerat-*)` filter excludes from import — the filter bounds what the
      claim can name, not what may be traversed to reach it, so under that
      strategy anyone nested below `OpenBerat-Admins` through a group with any
      name holds `ADMIN_GROUP`. The performance cost is not measured; four
      groups cannot show it. `docs/03`'s example was stated in the wrong
      direction and is corrected; ADR-0006's reversal trigger 3 has an answer
      and does not fire. Harness `verify-nested.sh` on the lab host; the mapper
      is restored*
- [x] **VERIFY:** does the LDAP group filter `(cn=OpenBerat-*)` exclude a group
      whose `cn` contains a comma? A group named `Payroll,OpenBerat-Admins`
      reaching the claim is a management-plane escalation, measured in Phase 2
      (`docs/07`), and this filter is the only thing that stops it (ADR-0008
      mitigation 1).
      *Yes, and the control case is what says so: the group is in AD and in
      `labuser`'s `memberOf`, and with the filter in place the claim carries
      `OpenBerat-Finance` alone. Emptying that one field — no restart, no sync —
      put `["Payroll,OpenBerat-Admins", "OpenBerat-Finance"]` in the next token,
      `admin: true` in `/api/me` and a **200** on `/api/admin/applications`.
      `labnested` rode along as the positive control (claim absent →
      `["Finance-All"]`), so the quiet baseline is the filter working rather than
      the write failing. ADR-0008 mitigation 1 holds and is no longer an
      assertion. Not predicted: while the filter is wide the excluded groups are
      **imported into Keycloak** and narrowing it again does not remove them —
      the claim goes clean on the next login, but the realm keeps a group named
      `Payroll,OpenBerat-Admins` until someone deletes it, one assignment away
      from being live. `INSTALL.md` says so now. Harness `verify-commafilter.sh`
      on the lab host; realm and filter restored*
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
- [x] **MEASURE:** remove a user from a group in AD → how many seconds until access
      is cut? Verify the `cookie_refresh` + cache TTL sum, compare with N-03
      *Measured (`docs/07`), two runs. A client polling every 2 s was cut
      **283 s** after the group left AD, at the `cookie_refresh` boundary; the
      directory itself contributed **zero**, because at `NO_CACHE` Keycloak
      reported the group gone in the same second. The sum is a real ceiling and
      it is reachable: a cache entry minted at t+296 — four seconds before the
      boundary — carried **16 consecutive 200s past it** and the cut came at
      t+328, `SessionAge: 5m27.187s`. So `cookie_refresh` + TTL = **330 s** is
      the worst case, inside N-03's 360 s with 30 s to spare. The mechanism is
      not a sum of two delays, though: 150 polls produced 10 consultations of
      `/oauth2/auth`, exactly one TTL apart, because a cache hit never reaches
      oauth2-proxy at all — the cache decides **when the refresh is attempted**.
      Harness: `verify-n03.sh` on the lab host, driven from the workstation.
      The Phase 6 repeat of this box qualified the 283: it is the delay of this
      run, not of the product — the cut lands at a fixed session age, so only
      the 330 s ceiling is a number about the system.*
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
      federation half landed with VERIFY (2): the export now carries the
      provider, its eight mappers and no local users at all*
- [x] Start `INSTALL.md` **while doing all of the above**, not in Phase 6. Phase 1
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
      (`docs/07`). Closed with §4, "Active Directory": the read-only bind
      account and its non-expiring password, the two group traps and the four
      DNs an installation changes in the realm export. The `ADMIN_GROUP` trap
      was written before it had been tried, so it was measured (`docs/07`) —
      pointed outside `(cn=OpenBerat-*)` it takes the real admin from 200 to
      403 with everybody else, while `/api/me` still lists the group and says
      `"admin": false`*

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
- [x] **Test:** an ordinary user with portal access cannot reach `/api/admin/*`
      *Closed against the endpoint, route by route rather than on the one route
      that was already covered: seven methods and paths, a valid `Origin` and
      bodies that would really work, so the group check is the only thing left
      that can refuse and a hole would show up as a written row. All 403,
      nothing written, each refusal logged with the actor. The same seven
      answer 200/204 for `labadmin`, which is what stops seven 403s from being
      seven typos — the guard is a `route_layer`, so it covers a handler only
      if the handler was registered on `admin::routes()`, and the kill switch
      is the next route to be added (Phase 5). Verified live on the lab too:
      through nginx, as a real logged-in portal user, with the client supplying
      its own `X-Auth-Groups: OpenBerat-Admins` — still 403, because that is
      where the portal's `/api/` strip kills it.*
      **What this found.** The group list is comma-joined into one header and
      split back apart here, so a single group *named* `Payroll,OpenBerat-Admins`
      arrives as two and the second is `ADMIN_GROUP`. Measured end to end: an
      ordinary portal user in that one group got `admin: true`, a 200 on
      `/api/admin/applications` and a **201 on a wildcard entitlement**. It
      cannot be fixed on this side — oauth2-proxy flattens the claim array
      before the request arrives — so the control is the Keycloak group filter,
      which ADR-0008, `docs/05`, `INSTALL.md` and both READMEs now call
      mandatory instead of advisable. The one half the backend *can* refuse it
      does: an `ad_group` entitlement whose `subject_id` contains a comma is a
      rule that could never match, and is now a 400 rather than a silently dead
      row. `docs/07`, harness `verify-comma.sh` on the lab host.
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
- [x] **Check the backend's own HTTP client header limit** the same way — it
      reads oauth2-proxy's response, which carries that same group list. The
      nginx half is measured; this half is not
      *Measured (`docs/07`): **~408 KB, about 16,000 group names.** 15,000
      groups (380 KB) pass, 20,000 (510 KB) fail. It is hyper's header buffer
      and not the 1 s budget — raising that to 20 s changed nothing, which is
      the experiment that separates the two. An order of magnitude above the
      32 KB nginx needs for the same list, so nginx stays the binding
      constraint. The unpleasant part is the failure mode: it denies with
      `auth_unavailable`, which reads as "oauth2-proxy is down" and sends an
      operator to restart the wrong service.*
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
- [x] `Origin` check on state-changing `/api/admin/*` endpoints
      *Landed with the first admin mutation, as planned, and as **middleware**
      rather than a line in each handler: a guard written per handler is a
      guard somebody forgets on the handler added at 3 a.m., and the one it is
      forgotten on is the one that grants entitlements. `GET`/`HEAD` are
      exempt; everything else needs an `Origin` equal to `PORTAL_ORIGIN`, and a
      **missing** `Origin` is a refusal rather than a pass. Tested with an
      admin acting from `sample.apps.example.local` — same-site, which is
      precisely why `SameSite` cannot do this job (ADR-0015).*
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

- [x] Application CRUD + `upstream_url` validation (scheme/host/port; loopback,
      link-local and infrastructure services rejected); `external_hostname`
      must not collide with the reserved `portal` / `auth` hosts (ADR-0011)
      *`admin.rs`. The validation is a trust boundary, so it uses the `url`
      crate rather than a hand-rolled parser, and it refuses on **three** axes
      rather than the two the ADR lists: the service names, the reserved
      addresses, and the **ports**. An admin typing `http://10.1.2.3:5432`
      walks straight past a name check, and nothing legitimate behind this
      proxy speaks Postgres, Redis or LDAP over HTTP — so 5432, 6379, 389, 636,
      3268 and 3269 are refused whatever the host. Private ranges are
      deliberately allowed: every real upstream is on one. Credentials, paths
      and query strings in `upstream_url` are refused too — it becomes a
      `proxy_pass`, and a path there silently rewrites every request. `slug`
      and `external_hostname` are **not patchable**: both are written into
      generated nginx blocks and into every audit row naming the application,
      so renaming one silently reassigns history.*
- [x] AD group ↔ application mapping (allow/deny)
      *`/api/admin/entitlements`, with the four field checks duplicated from the
      schema so a typo comes back as a sentence rather than a 503 with a
      constraint name in the log. Creating a **wildcard** entitlement — no
      `application_id`, so it applies to every application present and future
      (`docs/05` rule 4) — is logged as its own action at `warn`, not folded
      into the ordinary stream: it is the one grant nobody should be able to
      make by accident.*
- [x] **nginx config generation** (ADR-0011): generate from the template →
      `nginx -t` → reload. If validation fails, the current config stays in effect
      *The backend renders and **stages**; the install-test-rollback happens in
      the nginx container, which is the only place an `nginx -t` can run. It is
      test-then-keep and never write-then-hope: writing straight to `apps.conf`
      would let a file nginx cannot parse take the proxy down at its next
      restart, long after the admin who caused it has gone home. Measured both
      ways — an application defined through the API was reachable four seconds
      later with nobody touching a file, and a deliberately corrupt staged file
      left the previous configuration serving, wrote the `nginx -t` error where
      the admin can read it, and survived a container restart. The hand-written
      `20-apps.conf` is deleted: two sources for the same `server_name` is a
      conflict nginx resolves silently by taking the first.
      **Two bugs this found, both only visible on a first install.** Deleting
      `20-apps.conf` removed the only thing declaring `$deny_reason`, and nginx
      refuses to start when `log_format` names an undeclared variable — so a
      fresh install, with no applications defined yet, could not boot the proxy
      at all. The variables are declared at http level now (rule 17). And the
      backend runs as `nobody` while the shared volume seeds from the image's
      directory, so without a `chown` in the Dockerfile the first application an
      admin defines is saved and never published, with one log line to say so.*
- [x] **Test:** every generated location contains the `X-Auth-*` stripping include
      *The renderer is a pure function and this is a unit test over it: each
      generated server has exactly one `location /`, and each pulls in
      `protected.inc`, `decide.inc` and `errors.inc`. Also that it emits no
      `return` — that would run before `auth_request` and leave the location
      open, with `nginx -t` reporting success. A row that fails validation is
      **skipped rather than rendered**: the schema and the API both refuse such
      a row, so one arriving here means it got in another way, and one bad
      record must not take every other application down with it.*
- [x] `nginx/conf.d/10-portal.conf`: the portal host — frontend static files,
      `/api/*` → backend
      *Its own `location /api/`, with the identity written from the
      `/oauth2/auth` subrequest and every client-supplied `X-Auth-*` cleared
      first — a client posting `X-Auth-Groups: OpenBerat-Admins` straight at
      `/api/admin/*` is the whole attack, and this is where it dies. One
      correction to `docs/02` fell out of writing it: the backend reads
      **`X-Auth-Groups`**, not `X-Auth-Request-Groups`. It is an upstream on
      this path like any other, and the shared strip clears the
      `X-Auth-Request-*` family everywhere — reading the cleared family here
      would need one location that must *not* run the shared strip, which is
      exactly the "forget it in one place" hazard the include exists to remove.*
- [x] `GET /api/me`, `GET /api/apps`
      *`/api/apps` runs **`policy::decide`** over the same rules the PEP would
      use, at each application's root, rather than reimplementing "can reach"
      in SQL. A second implementation would eventually disagree with the first,
      and the disagreement shows up either as a button that 403s or — worse —
      as an application the portal hides while the PEP allows it. One query for
      all applications, and a LEFT JOIN rather than an inner one: an
      application with no matching rule still has to come back, because "no
      rule" is a decision (`no_matching_grant`) and not an absence. Tested that
      a deny at the root takes the button away and a disabled application is
      not a button.*
- [x] Admin mutations and kill switch invocations recorded to the structured
      log — actor, action, target, outcome (F-14, `docs/02` "Management plane")
      *Both halves now: `admin actor="labadmin" action="create_application"
      target=wiki outcome="ok"`, and the kill switch the same way at `warn`
      with the session count beside it —
      `action="kill" target=<sub> outcome="ok" sessions=1`. The count is the
      operator's answer to "did it find anything", and a failed step logs which
      step. Refusals are logged naming the guard that turned them away. Not in
      `audit_event`: that table's rows are decision summaries and its format is
      immutable (`docs/02`).*

## Phase 5 — Portal + audit + kill switch

- [x] Portal: reachable applications, buttons with icons
      *`index.html` + `portal.js` + `portal.css`, and **no Alpine.js** — a
      read-only list of what `/api/apps` returned needs no reactivity, and
      leaving it out is what lets the page run under `default-src 'self'`
      today instead of waiting on the CSP question below. ADR-0007 chose *no
      build step*, not *Alpine on every page*, so this is inside it.
      Everything an admin typed is written with `textContent`: the portal is
      the one host every user opens and its cookie is valid across
      `.apps.<domain>` (ADR-0015), so an application named
      `<img src=x onerror=…>` would otherwise be stored XSS. A CI job
      (`frontend`) fails the build on `innerHTML`, `eval`, inline `<script>`
      and inline handlers, because there is no build step and no linter to
      catch a contributor re-introducing one. Verified live on the lab: an
      `OpenBerat-Finance` entitlement makes the button appear for `labuser`,
      and a second application with no rule at all stays absent (F-04/F-05).
      Rendered in Firefox against a stubbed API in all three states — the
      injected name is drawn as text, and clipping the icon box was needed
      because nothing validates the `icon` column.*
      *Given its visual language afterwards, before the login theme so that
      theme has something to inherit: tokens at the top of `portal.css`, a
      paper/ink/gold palette taken from what a **berat** is, one `logo.svg`
      serving as both header mark and favicon, and a gradient rule repeated on
      all three pages so they read as one product. `--gold` never carries text
      — `--gold-ink` does, which is what holds the palette at AA. Red is the
      denied page alone; the outage page's block is gold, because a user who
      meets the same red rule on both cannot tell "policy said no" from "the
      decision path is down". Each card gained the application's hostname,
      derived in the browser, since two applications can share a name.
      One nginx change came with it: `portal.css` and `logo.svg` are served
      without `auth_request` (`docs/02`, fourth anonymous entry). The outage
      page comes from `location /`'s `error_page`, so a stylesheet fetched
      through that location hit the same failing subrequest the page reports
      and came back as the outage page — bare, in exactly the outage it exists
      to explain. Verified with the container running and no oauth2-proxy at
      all: both files 200 while `/` and `/denied` 500 into the styled page.*
- [x] The "no access" page — where `error_page 403` lands
      *The route was already wired and tested in Phase 3; what landed on it was
      a placeholder that said the real page "arrives in Phase 5". Now it names
      the refused application, says what to do, and links back to the portal.
      The application name comes out of `?app=`, which nginx fills from the
      matched `$host` — but anyone can type that URL, so it is written with
      `textContent` and only when it still matches a hostname. Without the
      second half the sentence itself is the injection: `?app=… contact
      security@attacker` is a page telling a user, in the product's own voice
      and on the product's own host, who to send their credentials to.
      Rendered in Firefox in all three states — named, unnamed, crafted — and
      verified end to end on the lab: a user with no entitlement gets 302 to
      `portal…/denied?app=whoami.apps.example.local`, following it ends 200 in
      one hop with no loop, and `denied.js` comes back from the nginx image.
      **Not** shown: a per-application owner or request link, which `docs/02`
      used to promise. Nothing writes that column, and an endpoint that serves
      it to any authenticated user answers "does application X exist" for
      applications they cannot reach — `docs/02` now says so instead.*
- [x] Empty state: "you have access to no applications"
      *The same branch of the same file, so it landed with the portal. It is
      **not** the error branch: `/api/apps` answers 503 when Postgres is down,
      and drawing that as "you can reach nothing" tells the user their access
      was revoked when the truth is an outage. The two say different things.*
- [x] Frontend files served by nginx — baked into the nginx image at build
      (ADR-0020), no frontend container or volume
      *Already how `nginx/Dockerfile` was written; this is the first change
      that exercised it. `docker compose build nginx` on the lab, and
      `portal.js` and `portal.css` come back 200 with `application/javascript`
      and `text/css` from the image — no volume, no frontend container.*
- [x] **VERIFY:** Alpine.js under a `default-src 'self'` CSP — the standard
      build needs `unsafe-eval`; if it fails, vendor the CSP build or amend
      ADR-0007 (`docs/07`)
      *Answered by running it, in a browser rather than on the lab — a CSP is
      enforced by the browser, not by nginx. The standard build **loads** under
      the policy and then evaluates nothing: `window.Alpine` is present, every
      binding keeps its fallback text, and the page reports `script-src blocked
      eval` twice. So `@alpinejs/csp@3.17.1` is vendored at
      `frontend/src/vendor/alpine.js`. The surprise was how little that costs:
      the CSP build ships a parser, not a property-name lookup, so inline
      `x-data="{ n: 41 }"`, ternaries, `&&`, member calls with arguments,
      assignment in `x-on`/`x-init`, `x-for` and the magics all work — only
      arrow functions and template literals are refused, and both belong in the
      `Alpine.data()` object anyway. ADR-0007's consequence and the `docs/07`
      Unverified entry are rewritten with the measurement. CI keeps it: the
      `frontend` job now fails if anything under `vendor/` regains `eval(` or
      `new Function`, since the standard build looks like nothing but a larger
      file. The CSP header itself is still not set on any host (Phase 6
      security headers) — the frontend is merely proven to survive one.*
- [x] **The login page is ours, not Keycloak's** — a Keycloak login theme in
      `keycloak/themes/`, `loginTheme` set in the realm export, and the IdP
      hostname named for what a user sees rather than for the software behind
      it. Today the realm ships `"loginTheme": "keycloak"`, so the one screen
      every user meets first is stock Keycloak on a second hostname. No code,
      and ADR-0003 is untouched — but it is the one thing here that changes
      something already built: a theme is read at runtime, not imported like
      the realm, so `keycloak/` needs the `Dockerfile` it does not have yet
      (stock image today) and `docker-compose.yml` swaps `image:` for
      `build:`. Bind-mounting the theme instead is the config drift the rules
      forbid; the realm mount is exempt because it is import data, not running
      configuration.
      **Not** an own login form posting to Keycloak's direct grant — that puts
      the password through our backend, breaks the TOTP intent in `docs/06`,
      and throws away the one decision that keeps OIDC code out of this
      repository.
      *A child of `keycloak.v2` that overrides **no template**: `theme.properties`,
      one stylesheet, one message. Copying the `.ftl` files in would mean owning
      FreeMarker across Keycloak upgrades, and a template that stops matching its
      theme breaks the one page nobody can route around. The palette is copied
      from `portal.css` — the two are served by different processes and cannot
      share a sheet, so the tokens are the only thing making the two hostnames
      one product; the portal's three-pixel gradient rule is now on the login
      card too, and the mark is not duplicated (`keycloak/Dockerfile` copies
      `frontend/src/logo.svg` in, the ADR-0020 trick). `keycloak/` got the
      Dockerfile it lacked and compose swapped `image:` for `build:`. Screenshotted
      in both colour schemes, which corrected the CSS twice: PatternFly's
      `--dark-100` variables are aliases only *sometimes*, and its dark palette
      assigns the button's colour **on the button element**, where no `:root`
      override of any specificity can reach it (`docs/07`). Verified on the lab
      with a real `ob-login.sh` login, not just a 200 on the stylesheet. The
      hostname half needed nothing: it has been `auth.apps.<domain>` since the
      vhost was written. ADR-0005's directory listing still says "stock image" —
      left as the historical record it is, the way its stale `frontend/` line
      already is*
- [x] Audit log viewing + filtering
      *`GET /api/admin/audit`, the API half only — the admin screens do not
      exist yet for applications or entitlements either, and the two boxes
      after this one add endpoints the same screen would have to grow, so
      building it now means building it twice. Filters: `actor`, `app`,
      `decision`, `reason`, `since` (inclusive) / `until` (exclusive).
      Two decisions, both the same rule — an audit viewer must never answer
      with a list that is quietly not the list asked for. A filter the backend
      cannot honour is a **400 rather than ignored** (`deny_unknown_fields` plus
      an enum for `decision`): ignoring one widens the result, and the admin
      then reads "these are the denials" off a page with allows on it. And the
      cursor is a **keyset** `(ts, id)`, not an OFFSET — rows arrive at the head
      of this ordering while an admin pages through it, so OFFSET repeats page
      one on page two, and once the N-04 retention job deletes from the tail it
      skips rows instead. `limit` caps at 1000; unbounded is a self-DoS on a
      table designed to grow. Verified on the lab against rows the real decision
      path wrote (`verify-audit.sh`), with invariants rather than fixtures — a
      filter tested on a column holding one distinct value cannot tell narrowing
      from ignoring, so what is asserted is that the halves add back up to the
      whole (`allow` + `deny` == all, `since=T` + `until=T` == all) and that
      paging with `limit=3` walks all 20 rows exactly once.*
- [x] `GET /api/admin/explain?user&host&path` — why the decision was made.
      `policy.rs` is already pure; the screen ops will use most
      *`policy::explain` **annotates, it does not decide**: the verdict is
      `decide`'s own and each rule is marked matched/expired beside it, so the
      screen and the PEP cannot drift into disagreeing about one request. The
      rows come from the decision path's own predicate, now written once
      (`store`'s `applicable!`) rather than copied — an explain answering from a
      different rule set sends an admin to fix the wrong rule. `groups` is a
      **required** parameter, not defaulted to none: the backend keeps no
      directory, and answering without them drops every group rule and reports a
      denial that would not happen. An expired grant is shown matched **and**
      expired rather than dropped, because "it ran out on Tuesday" and "there
      was never a grant" are different answers. Verified on the lab by making
      both answers for the same request — `labuser` through nginx and an admin
      through the API — over twelve paths including the normalisation attacks;
      all twelve agreed (`docs/07`). Two things that run corrected: a deny
      reaches the browser as a **302 to `/denied`**, not a 403, so the harness
      checks the redirect target too; and `/admin%00` never reaches the PEP at
      all, nginx refuses it first. The one disagreement left is deliberate and
      written down — this reads the table while the PEP may still be serving a
      cache entry, so for up to `cache::TTL` the explanation is ahead of the URL.*
- [x] Kill switch, four steps in this fixed order (ADR-0019): Keycloak
      `logout-all` → the session keys from the `sub → session` index → that user's
      decision-cache entries → the index entry. Only that user's entries are
      dropped; flushing the whole cache is self-DoS
      *`POST /api/admin/kill/{sub}`, and `{sub}` is parsed as a **UUID**: it is
      interpolated into a Keycloak Admin API path, and Keycloak's `sub` is the
      user id (`docs/07`), so nothing legitimate is refused by insisting on one
      while `../` would otherwise reach a different admin endpoint with the
      service account's rights. That service account is its own client with
      `manage-users` and no browser flow — `manage-users` is the narrowest role
      Keycloak has for `logout-all`, and putting `KC_ADMIN_PASSWORD` in the
      backend's environment would hand password resets to whoever reads it. A
      step that fails **stops the ones after it**: carrying on would report a
      kill nobody got and would delete the index entry that makes the call
      retryable. A `sub` no user has is a 404, not a 503 — an operator
      mid-incident reads 503 as "the system is broken".*
- [x] **Test:** access is cut after a kill switch **and the cache does not
      refill**; the dropped entries' counters land in the audit channel, not
      the void
      *The oauth2-proxy stand-in learned the one behaviour the kill switch
      rests on — a ticket whose Redis key is gone is a 401 — so "access is cut"
      is an assertion about the kill switch and not about the fixture. After the
      kill the next request reaches oauth2-proxy again (the entry really left
      the cache) and comes back 401, and the dropped entry's counters arrive on
      the audit channel with the right count and path total. Also tested: both
      failure answers stop at step 1 and leave the index entry behind, and a
      `sub` that is not a UUID never reaches Keycloak at all.*
- [x] **MEASURE:** kill switch end to end — is it under the 5 s of N-03?
      A user still signed in elsewhere is not cut: their entry never existed in
      the index if they never hit `/decide` on this instance
      ***0.085 s** from the admin's POST to the first refusal — two orders of
      magnitude under the 5 s (`docs/07`). All four steps checked for the mark
      they should leave rather than inferred from the end state; the one that
      matters most is Keycloak, because without it the browser is redirected to
      a live SSO session and signed straight back in, and the kill switch would
      look instantaneous while cutting nothing.
      **The measurement found a hole and it is now closed.** A user who had
      signed in and stayed on the portal was invisible: the index was written
      only on a `/decide` miss and the portal does not go through `/decide`, so
      the kill reported `sessions:0` and cut nothing for the five minutes until
      `cookie_refresh`. Every user is in that state between signing in and
      opening their first application — exactly when the kill switch is
      reached for. Every authenticated `/api` call records the session now, and
      the portal's `/api/` location stops stripping the session cookie (the one
      exception to rule 16, written out where it is made: the key is derived
      from that cookie, and this upstream is the PDP, which `/decide` already
      hands the same cookie).*
- [x] **Test:** an **idle** WebSocket connection is cut within `proxy_read_timeout`
      (an active one is not — ADR-0016 excludes it, do not assert otherwise)
      *Both halves in one run, on one vhost with one timeout and one cookie, so
      the contrast is the result rather than two runs compared across two
      configurations: the silent connection died at **t+300.002 s** and the
      talking one was still trading frames at t+420 s (`docs/07`). Through the
      **committed** configuration this time — the vhost is generated from the
      `application` table and its location includes `protected.inc`, so the
      300 s under test is the shipped value. The clock turned out to start at
      the last read from the **upstream**, not at the upgrade: `echo-server`
      greets a connection with one frame and the close landed 300.000 s after
      it, to the millisecond.
      What the run does **not** support is calling this a revocation. The close
      is a TCP close, the reconnect is re-authorised — and the idle timer runs
      beside the session's staleness rather than after it, so an idle connection
      cut at 300 s reconnects into a session that can still be 330 s stale. The
      worst case is near **630 s**, past the six minutes, which is why ADR-0016
      excludes every upgraded connection and not only the busy ones.*
- [x] Logout: all three steps (`docs/02`, "Logout") — the backend step is
      `POST /api/logout`, called **before** the sign-out redirect; reversed, a
      request in the gap refills the cache from the still-live session
      *All three run inside `POST /api/logout` now, not two of them afterwards,
      and the reason is a control run rather than a preference. Written as the
      box describes it — backend first, browser walks `/oauth2/sign_out` after —
      step 2 silently did not happen: Keycloak will not end a session without an
      `id_token_hint`, the hint comes from oauth2-proxy's `backend_logout_url`,
      and that token lives inside the session the backend had just deleted.
      Measured: the IdP session survived and the next request signed the user
      back in with no password. So the backend asks oauth2-proxy to sign out
      first, then deletes the key, the cache entries and — `SREM`, not `DEL` —
      this session's index membership, so the same user's other browser stays
      killable. 0.084 s from the click to access gone, against N-03's 5 s
      (`docs/07`).*

## Phase 6 — Hardening and packaging

- [x] **Deprovisioning delay test** — does the N-03 target hold (repeat the Phase 1
      measurement)
      *Both runs repeated against the current chain. **It holds, and nothing
      Phases 2-5 added put a term in the path:** the cut lands at session age
      `5m2.6s` ordinarily and `5m27.7s` at the ceiling, where Phase 1 read
      `5m2.1s` and `5m27.2s`, and the consultation grid is still exactly 30 s.
      The ceiling is unchanged at `cookie_refresh` + cache TTL = **330 s**
      against N-03's 360 s. The kill switch's index write sits on the cache-miss
      path — the same request that does the refresh — and cost nothing.
      **The repeat also corrected what to publish.** 283 s was a property of the
      experiment, not of the system: the cut happens at a fixed session age, so
      the delay measured from the AD change is that age minus how late the
      change fell after the session was minted. The same behaviour measured
      272.6 s, 283.2 s, 314.2 s and 316.7 s across four runs. Only the ceiling
      is a number about the product (`docs/07`).*
- [x] **One real application, integrated end to end** — Jenkins behind the
      proxy, reached from the portal, with no second password prompt, and the
      recipe written into `INSTALL.md` (§7).
      *Jenkins 2.555.1 on its own host, across the LAN rather than on the
      compose network. On our side the whole integration is **one `application`
      row and one `entitlement`** — no code, no migration, no configuration
      file; on its side, a security realm that reads `X-Auth-Username` and
      `X-Auth-Groups`. Measured: one login at the portal, then `GET /` returns
      **200** with no login form in the body and `whoAmI` says `labuser`; with
      no cookie, 302 to Keycloak. Two more measurements settled
      [ADR-0021](docs/adr/0021-application-identity-trusted-headers.md) rather
      than assuming it — **a forged `X-Auth-Username` sent straight to the
      published port impersonates an admin from any host on the LAN**, and the
      shared-browser identity confusion that mechanism belongs to the *other*
      option: the header is read per request, so user B carrying user A's
      application cookie is still served as B (`docs/07`).*
      *The bypass was then closed on the lab host with the `DOCKER-USER` rule
      from `INSTALL.md` §7 and both directions re-measured: the forged request
      from an unrelated host is dropped, the same request from the PEP's address
      still answers 200, the proxy path is unchanged and the build agent — which
      reaches the controller over the Docker bridge — never noticed.*
- [x] Security headers, TLS settings, the certificate renewal path
      *Two new files, `nginx/conf.d/tls.inc` and `security.inc`, both at http
      level and both shared with the break-glass configuration. The certificate
      moves there too, so no `server` block carries a copy — including the
      blocks ADR-0011 generates, which is four places that can no longer drift.
      **The trap this box is really about is `add_header`:** nginx inherits it by
      **replacement**, so one header set in a location drops every header above
      it — and the three locations that relay the refreshed session cookie by
      hand are exactly the portal, the admin API and `protected.inc`, which is
      every application. CI fails the build if a location with an `add_header`
      does not pull `security.inc` back in (README rules 19 and 20).
      **One header had to come back out.** `Referrer-Policy` at http level
      *relaxed* what upstreams had already chosen — measured, Keycloak sends
      `no-referrer` and Jenkins `same-origin`, and a browser takes the last of
      two — so it is on the portal's own HTML only, next to the CSP. Of the TLS
      settings only `ssl_ciphers` changes anything: the stock image accepts
      `AES128-SHA`, RSA key exchange with no forward secrecy, under the cookie
      that is valid for every host on `.apps.<domain>`.
      **Renewal is a file swap and a reload** — 400 requests spanning it, none
      failed — plus one `docker compose restart oauth2-proxy` while the
      certificate is self-signed, which is where the run that "passed" turned
      out to have been a harness reporting success on a login that 500'd
      (`docs/07`, `INSTALL.md` §1).*
- [x] Backup/restore procedure, migration rollback
      *One database, one `pg_dump`, and `INSTALL.md` §9. Everything else on the
      host is derived or in the repository, so it is deliberately **not** backed
      up — which only became true in this box: the generated nginx blocks were
      written by mutation handlers alone, so a restored database gave every
      application a hostname nginx had never heard of. The backend now renders
      them at startup too (ADR-0011), and the restore completes with nobody
      touching a row.
      **The first procedure written down did not work.** `pg_dump --clean` was
      supposed to make one command restore both onto an empty database and over
      a live one; it stops at `cannot drop inherited constraint
      "audit_event_default_pkey"` — `audit_event` is partitioned and the default
      partition inherits the key. Emptying the schema first is what covers both.
      Measured: dump 0.3 s, in-place restore 1.0 s, and after deleting both
      volumes the application answered 200 again **59 s** later, of which 3.4 s
      is the restore and the rest is Keycloak importing its realm. Rolling a
      version back is restoring that dump — the older binary refuses to start
      against a schema migrated past it (`docs/07`).*
- [x] Audit retention job (N-04) and partition maintenance
      *N-04 was open because the period is the operator's, not ours; ADR-0022
      answers it as a mechanism with a default instead — `AUDIT_RETENTION_MONTHS`,
      12 months, fatal at startup if it is not a whole number, because this is
      the only background task in the product that deletes. The unit is months
      because the unit that leaves is a month: `audit_event` has been
      partitioned since `0001_init.sql` and an expired month is one `drop
      table`, not a pass over every row in it. The default partition is never
      dropped — it is what stops an `INSERT` for an uncovered month failing off
      the request path — so expired rows in it are deleted at the same cutoff.
      **The interesting half is the failure:** a month whose rows are already in
      the default partition cannot be split out from under them, Postgres
      refuses with `updated partition constraint for default partition would be
      violated by some row`, and a run that treated that as fatal would keep
      expired data forever. It is logged and the expiry continues; the month
      after heals itself. Both halves are tested, and both assertions were seen
      to fail against a deliberately broken implementation.*
- [x] Monitoring: decision latency, error rate, cache hit rate, audit loss counter
      *`GET /metrics`, Prometheus text format, hand-written — the exposition is
      four line shapes and the counters were already named in the code
      (`Deny::as_str`, `store::audit_dropped`), so a client library would have
      been a second vocabulary for the same words. It sits with `/healthz` and
      `/readyz` on the internal network, which is the reason **nothing in it
      carries a user, a `sub` or an application**: nginx proxies none of the
      three, so anything that can open port 8081 can read it, and a per-user
      label would make a scrape a way to enumerate who is signed in.
      **The two series that matter are the ones the fail-closed rule hides.**
      `store_unavailable` and `auth_unavailable` answer 403 exactly like a
      policy denial does, so from outside an outage looks like a strict policy;
      per-reason counters are the only place the difference shows (INSTALL.md
      §10). N-01 and N-02 are histogram bucket **edges** rather than something
      to interpolate, so the fraction meeting each target is read off the
      exposition.
      Measured on the live chain: every cache hit **under 0.25 ms** against
      N-01's 2 ms, a warm miss 2 ms or under in four of five samples, and the
      only request that came near N-02 was the first one after a restart —
      a cold connection pool, not the decision. Not a load result; that is the
      box below. The counters were checked by making them move by exactly what
      the traffic did, and all three false alarms the run produced were the
      harness reading a status code where the answer was in the `Location`, the
      body, or a `# HELP` line (`docs/07`).*
- [x] Versioning, release image, offline bundle for air-gapped installation.
      Rewrite the `SECURITY.md` scope section — it says there is no released
      version yet, which stops being true here
      *Three things that looked separate and were one (ADR-0023). **An
      air-gapped site cannot build this product** — the backend compiles against
      crates.io, two images install packages and Keycloak resolves Maven on
      first start — so the release has to be images that already exist, and once
      it is a set of images the version is a property of the set. One semver for
      the whole product, from `backend/Cargo.toml` and nowhere else; the backend
      logs it and publishes `openberat_build_info`, so a running deployment can
      name itself instead of the operator reading an image tag.
      `release.sh` writes one tarball — the tagged source plus `docker save` of
      every image the release compose references. **420 MB for 0.1.0**, and no
      second online-only artifact, because two artifacts would mean testing two.
      **The lab left the default compose in the same change:** `samba-ad`,
      `sample-app` and `sample-ws` are behind `--profile lab` now. ADR-0010 said
      the DC ships in nothing, and until this box the only thing making that
      true was the order of arguments in `INSTALL.md` §5.
      Installed on the lab after deleting every image the bundle claims to
      carry, so nothing on the host could stand in for a missing one:
      `--pull never` refuses by name, the six images load, and a real login
      reaches Jenkins. **The number worth keeping is the gap between 33 s and
      88 s** — the backend answers `/readyz` at 33 s while the portal is still
      answering 500, because `/readyz` covers Postgres and Redis and says
      nothing about oauth2-proxy's OIDC discovery. The first run of the test
      called that a failure; on a first install the signal is the portal
      redirecting, not a container being up (`docs/07`).
      The tag itself is not cut here: a release a script can make by itself is
      one that can be made by accident (ADR-0023).*
- [x] SPDX identifier in `Cargo.toml`, licence headers, Alpine.js MIT notice preserved (ADR-0013)
      *`Cargo.toml` already carried `license = "GPL-3.0-or-later"`; what was
      missing was the per-file notice — two SPDX lines on 40 files, after a
      shebang or a doctype and before anything else — and the MIT notice, which
      turned out not to be *preserved* at all: the published `@alpinejs/csp`
      minified build ships **no** banner, so one is prepended. It has to be in
      the file rather than only in the vendor README because that file is served
      to every browser that opens the portal, and a README is not attached to
      the copy they receive. Both checksums are recorded now, published and
      vendored, so an upgrade stays verifiable.
      **The sweep broke the lab, and only the lab could have shown it.**
      `sqlx::migrate!` checksums every file in `backend/migrations/`, so two
      comment lines in `0001_init.sql` made it a different migration and the
      backend refused to start — correctly: the alternative is serving decisions
      against a schema it was not built for. Locally every test passed, because
      they all begin by dropping the schema and re-applying migration 1 to an
      empty database. Migrations are out of the sweep, CI now fails a migration
      that *gains* a header, and the rule is in `CONTRIBUTING.md`.
      Verified live afterwards: `nginx -t` accepts every `.conf` and `.inc`, the
      login theme still pulls `css/openberat.css` — a comment in
      `theme.properties` would have failed silently by falling back to stock —
      and both notices reach a browser (`docs/07`).*
- [x] Finish `INSTALL.md` (drafted in Phase 1): DNS, wildcard certificate,
      `ADMIN_GROUP`, first login, and the prerequisites an operator cannot skip —
      write access to AD for the `OpenBerat-` groups, a common parent domain
      (ADR-0015), a Keycloak service account
      *All of the listed items were already written; what the checklist did not
      name is what was missing. **§6 said applications are defined "through the
      admin API" and never showed a call**, so the document could be followed to
      the end and leave nothing behind the proxy. The two calls are in it now,
      with the `Origin` requirement, what `upstream_url` refuses and why,
      what each entitlement field means, and `/api/admin/explain` as the check
      to make before a user does. Also added: two checks at the end of §5 that
      separate an outage from a strict policy, and a pointer to the break-glass
      runbook from §10 — an operator reading about monitoring is the one who
      will need it.
      Run literally on the lab, cookie and all (`verify-install6.sh`): the
      no-`Origin` 403, the infrastructure-upstream 400, `"nginx":"staged"`, the
      302 to `/denied` before any entitlement, 200 after one, `explain` agreeing
      with the PEP and refusing to guess without `groups`, and the delete.
      Two things the document got wrong until it was executed — `DELETE`
      answers 200 with a body rather than 204, and the `Origin` guard is the
      first thing a curl-driven admin hits (`docs/07`).
      The draft banner is gone: the file is complete for v1.*
- [x] Load test → fix N-01/N-02 (answer N-07 first, otherwise the test has no target)
      ***The parenthetical turned out to be wrong, and that is the first
      result.** N-01 and N-02 *are* the targets; N-07 would only have said
      whether the capacity is enough, and it never gated the measurement.
      Both hold, with room. A cache hit is **11–29 µs** from 1 to 64 concurrent
      connections — 100% under N-01's 2 ms to 32, 99.8% at 64, and 99.9% of
      16 540 decisions in a sustained run of 19 200 requests that returned 200
      to every one of them. A cache miss is **2.7–4.7 ms** and **31 of 31 were
      under N-02's 10 ms** at 1, 2, 4, 8 and 16 first visits at once; the mean
      does not climb with concurrency, because a miss waits on the oauth2-proxy
      hop, the Redis write and the query rather than on CPU.
      **What the run actually found is where the cost is.** At 32 connections
      nginx uses 138% of two cores and the backend 11% — the decision is about
      **one per cent** of what serving the request costs, so tuning it further
      buys nothing and the first instance to add under load is nginx.
      **And what a real user meets first is neither.** As shipped, from one
      address, 400 requests at four connections get 32 answers and 368 × 429:
      `00-auth.conf` allows 50 r/s with a burst of 100 per address and refuses
      the rest before `/decide` is consulted. Fifty people behind one NAT
      address at a request a second are already at it. That number is what N-07
      is really for, and it stays open with the two options the measurement
      leaves written down (`docs/06`).
      Two numbers were thrown away for the same reason — the load generator and
      `docker stats` share the two cores under test. A sampled run read 383 r/s
      with 14% failures where a clean one read 750 r/s with none, and the miss
      path read 17.6 ms taken straight after a saturation run against 2.7 ms on
      a quiet host (`docs/07`).*
- [ ] Backend on 2 instances + nginx health check (HA — after the first deployment)
      *Not started: N-06 puts HA outside v1 and the box waits on a first real
      deployment. Two things are known before it opens, both from measurement.
      **nginx OSS has no `health_check` directive** — only passive
      `max_fails`/`fail_timeout`, which ejects an instance after users have
      already met the failure — so the check has to be NGINX Plus, a patched
      build, or something outside nginx that polls `/readyz` and rewrites the
      upstream list, the shape ADR-0011 already uses (`docs/07`). And the load
      test says **the first instance to add is nginx, not the backend**: at 32
      connections nginx used 138% of two cores and the backend 11%.
      The open design question is the decision cache. It is instance-local, and
      a kill switch that clears one instance's cache leaves the other serving
      the old answer for up to a TTL — which is ADR-0016's 5 s target, broken.
      That needs an ADR before any second instance runs.*

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
