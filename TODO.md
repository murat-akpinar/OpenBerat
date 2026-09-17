# TODO

Status: **phases 0–7 are closed, every box below is closed with it, and nothing
is tagged.** What closed each phase, and the 148 boxes that did it, moved to
[`docs/09-history.md`](docs/09-history.md). The set below has not moved there
yet — it is a backlog rather than a phase, and it moves as a unit or not at all.
**A tag is still a deliberate manual act** ([ADR-0023](docs/adr/0023-versioning-and-release.md)).

The backlog below is what came out of reading an enterprise SSO roadmap
(`tmp/`, not in Git) against this product. Most of that document is somebody's
deployment project — phases, a responsibility matrix, Kubernetes, an API
gateway — and none of that is product work; what it *did* surface is a short
list of places where this repo either ships one profile where four are wanted,
or claims something nothing checks. **§ numbers below cite that document.**
What was read and refused is at the bottom, with the reason, because a refusal
nobody wrote down gets re-litigated.

Decisions: `docs/adr/` · Open questions: `docs/06-requirements.md`

---

## Closed

- [x] **The realm ships exactly one security profile, and the roadmap wants
      four.** Read off `keycloak/realm/openberat-realm.json`, the shipped values
      are `ssoSessionIdleTimeout` 1800, `ssoSessionMaxLifespan` 36000,
      `accessTokenLifespan` 300 — which is §9.2's *internal, low-risk* row to
      the minute, and no other row. External (15–30 min idle, 4–8 h max), admin
      (10–15 min, 2–4 h) and critical-application profiles have no expression
      here at all. Two settings are not merely conservative but **absent**:
      `passwordPolicy` (§16 wants length, complexity and history) and
      `revokeRefreshToken` (§16 and the §23 risk table both name refresh-token
      rotation; without it a stolen refresh token is good for a full
      `ssoSessionMaxLifespan`). `failureFactor` is 10 where §16 says 5.
      *The password policy and `failureFactor` are realm edits and cost nothing.
      Rotation is not: `revokeRefreshToken` changes what oauth2-proxy's
      `cookie_refresh` is doing, and `cookie_refresh` is one of the two terms in
      the **measured 330 s** of N-03 (`docs/07`). So it is a re-measurement, not
      a setting. And per-profile TTLs are a question this product has not
      answered: it has one realm and one session cookie, so "admin sessions
      expire sooner" has nowhere to live yet — that is an ADR, not a box.*
      **Closed: one setting changed, two measured into staying as they are,
      one question moved to `docs/06`** (all four in `docs/07`, harness
      `verify-realmprofile.sh`). `failureFactor` is **5**; the reason that
      holds up is AD's, not the roadmap's: while Keycloak's lock holds no bind
      reaches AD, right password or wrong, so `failureFactor` is the burst a
      domain lockout threshold has to survive (`keycloak/README.md`). The same
      run found the README wrong — the lock does not double; 60 s through the
      ninth failure, 120 s at the tenth. **`passwordPolicy` stays absent**: a
      64-character policy let a 24-character AD password log in, because a
      `READ_ONLY` federation never consults it. **`revokeRefreshToken` stays
      off**: the premise was a stealable refresh token, and none exists outside
      the server — the cookie is a 176-byte ticket and the Redis value is
      ciphertext (`docs/04`). Per-profile session lengths are an open question
      in `docs/06`, "Security, still open", because the only place they could
      live is a decision-time input nothing supplies yet.

- [x] **`/api/admin/*` is all-or-nothing, and the roadmap wants an auditor.**
      F-12 binds the whole management plane to one group; §14.1 splits it six
      ways (Realm Admin, Client Admin, User Admin, Auditor, Security Admin,
      Integration Admin) and §14.2 asks for least privilege. Most of that split
      is Keycloak's own admin console and not ours. **One subset of it is
      genuinely this product's and genuinely missing: read-only.** The audit and
      explain screens exist ([ADR-0026](docs/adr/0026-audit-explain-screen-in-v1.md)),
      the write screens exist and are separately rate-limited
      ([ADR-0033](docs/adr/0033-admin-write-screens.md)) — so the seam is
      already cut, and what is missing is a second group that reaches the first
      set and not the second.
      *Needs an ADR before code: a second group means a second name in
      `.env.example`, and [ADR-0008](docs/adr/0008-group-identity-name.md) owns
      how group names are matched. It also owes a requirement ID in `docs/06`.*
      **Closed: [ADR-0034](docs/adr/0034-read-only-management-group.md), F-15.**
      `AUDITOR_GROUP` (default `OpenBerat-Auditors`) reaches every `GET`/`HEAD`
      under `/api/admin/*` and nothing else, decided by method in the one guard
      every management route passes — the split the `Origin` check already
      relied on — rather than by a second route list that would drift.
      `ADMIN_GROUP` stays a superset. The group carries `openberat-mfa` too, so
      ADR-0032's "nobody else" is superseded in part: what an auditor reads is
      every user's access history, the whole `explain` map and who is signed in.
      Tested red first (`policy.rs`, and the integration suite's route
      enumeration now asserts the auditor's answer for every route), then on the
      lab (`verify-auditor.sh`, `docs/07`): OTP enrolment after the password,
      five reads 200, six writes and a forged-header write 403 with both tables
      byte-identical, and an admin's identical write answering 200.

- [x] **Configuration-as-Code is asserted and nothing verifies it.**
      §24's success criterion is "the configuration can be re-installed from
      Git", and `docker-compose.yml` already claims the stronger version — the
      realm is *reproduced* by re-importing the export, which is why the lab H2
      database deliberately gets no volume. But the rule that keeps the export
      true is a hand rule in `CLAUDE.md` ("if you changed it in the UI, export
      it again"), and **nothing anywhere compares the export in Git against the
      running realm.** This is the same failure this repo already refuses
      everywhere else: a value written in two places where only one of them is
      checked.
      *The cheap shape is a script that pulls the running realm through the
      admin API, normalises what is expected to differ (ids, timestamps, the
      resolved `${...}` placeholders) and diffs the rest — runnable by hand,
      then in CI. It is also the only item here that would have caught the
      previous box: a `failureFactor` somebody raised in the console.*
      **Closed: `keycloak/realm-drift.sh`, a `realm export` job in CI, and one
      correction to the export itself** (measured in `docs/07`, harnesses
      `verify-realmdrift.sh` and `verify-realmdrift-prod.sh`). It compares the
      running realm not with the file but with a **fresh import of the file in
      a throwaway container**: the export names only what differs from
      Keycloak's defaults, so a comparison with the file would have missed
      `registrationAllowed`, which nothing in the export mentions. Four kinds of
      drift were made on the live lab realm and all four were reported —
      including one nested in the LDAP component and a hand-made group carrying
      `openberat-mfa` — then restored, and it read clean again. It answers the
      same on `INSTALL.md` §5's production shape, where drift survives a
      restart; there the database override is what keeps the reference from
      reading the very realm it is checking (`Import skipped`). **The first run
      found a real difference on a realm nobody had touched:** Keycloak writes
      `multivalued` into the groups mapper on every token it issues, so every
      installation differed from its own export the moment somebody logged in.
      The export now carries it. CI imports the export, requires a clean read,
      then raises `failureFactor` and requires a failure.

- [x] **Break-glass is written and timed at nothing.** `docs/08` and
      [ADR-0030](docs/adr/0030-breakglass-generated-blocks.md) describe the way
      back in; §24 gives the equivalent criterion a number — a rollback to the
      old login **under 10–15 minutes**. [ADR-0017](docs/adr/0017-fail-closed-availability.md)
      is why the number is not optional: a phase does not close on a procedure
      being *written*, only on its having been run.
      *Run it against the lab, with a clock, and put the figure in `docs/07`.
      If it does not fit, the procedure is what changes, not the target.*
      **Closed: 2.8 s end to end against a 600–900 s target, and the run found
      a limit of the procedure that no workstation rehearsal could have**
      (`docs/07`, `docs/08` rehearsal record, harness `verify-breakglass.sh`).
      **1.1 s** off → on with the clock started at the `/readyz` probe `docs/08`
      opens with, **1.5 s** back — measured to *enforced access with the chain
      repaired*, not to nginx restarting. The limit: **break-glass restores the
      route, not the access.** The lab's Jenkins answered **403** through it,
      cookie or no cookie, because it takes its identity from the `X-Auth-*`
      headers break-glass clears on purpose
      ([ADR-0021](docs/adr/0021-application-identity-trusted-headers.md) from the
      other side) — confirmed off the proxy entirely, where the same anonymous
      request is 403 and one carrying a header is 200. Nothing the PEP can do
      during the window: forwarding those headers would forward whatever the
      client wrote. `docs/08` now names the class of application this hits and
      says the move is on the upstream. Two smaller corrections came with it —
      the diagnostic table promised "connection refused" where Compose actually
      answers `wget: bad address`, and the first run polled *Jenkins* for the
      200 that means break-glass is serving, reporting its own 600 failed polls
      as an 11.8 s swap. Everything else held: a row published before the
      incident became a break-glass host, forged `X-Auth-*` and a real session
      cookie reached the upstream 0 times, the portal 404s, and the restored
      proxy carries zero break-glass includes.

- [x] **The audit partitions have never been restored.**
      [ADR-0022](docs/adr/0022-audit-retention.md) drops a month as a partition
      and defaults to twelve; §17.3 and §24 both want a restore that has
      actually been performed, and §17.3 additionally wants a stated recovery
      target. Encrypted backups (§12) are the operator's; **a restore drill is
      ours**, because the schema is ours and a partitioned table is exactly the
      shape that restores wrong.
      *A drill on the lab, and one figure in `docs/07`. No new feature.*
      **Closed: 1.6 s against a new 15-minute target (N-08), and the drill found
      the rollback evidence file recovering nothing** (`docs/07`, harness
      `verify-partrestore.sh`). The restore itself is clean over a table with
      monthly partitions — 252 rows in two partitions plus an empty third came
      back attached, per-partition counts and the `md5` of every audit `id`
      identical, and `maintain_audit`'s own `pg_inherits` query still finds the
      restored month to expire, which is the failure the box was worried about:
      a partition restored as a plain table answers every query and silently
      stops expiring. **The finding is the other dump.** §9's
      `pg_dump -a -t 'audit_event*'` taken before a version rollback writes one
      `COPY` per partition *naming that partition*, and the schema a rollback
      loads it into has only `audit_event_default` — **0 of 253 rows recovered**,
      stopped at `relation "public.audit_event_2026_08" does not exist`. The
      `*` was documented as load-bearing because "the rows are in
      `audit_event_default`", a reason that expired the day the retention job
      shipped. `--load-via-partition-root` is now on that command: measured four
      ways, it recovers everything into a freshly migrated schema and still puts
      the rows back in their own months where those months exist. The lab also
      showed ADR-0022's self-healing case live — no `audit_event_2026_09` at
      all, because the backend was down across the month boundary and September's
      rows reached the default partition before the partition could be created.

- [x] **Three attack scenarios named by §24 have no check.** The success
      criteria ask for brute-force, **token replay** and **MFA bypass** to be
      tested; `CLAUDE.md` step 3 already requires the attack to be tested rather
      than the happy path, and the existing suite does that for forged
      `X-Auth-*`, double encoding, `/x/../admin/` and post-kill-switch cache
      refill. These three are simply not among them. Token replay in this
      product's terms is one subject with two source addresses inside one
      window — `audit_event.src_ip` already holds what the query needs, which is
      why it sat in **Later** as a report; §16 promotes it to a control.
      *Brute-force and MFA bypass are realm behaviour and belong in the lab
      script, not in `cargo test`. Say which is which when the box opens.
      Brute-force has a lab run now, from the box above
      (`verify-realmprofile.sh`, `docs/07`) — the lockout, what reaches AD
      during it; what is still owed is making it a check rather than a run.*
      **Closed: two lab checks, one `cargo test` — and the third scenario was
      broken in our own code** (`docs/07`, harness `verify-attacks.sh` with
      `brute`, `mfa`, `replay-a`/`replay-b`). Brute force and MFA bypass are
      the realm's and are now asserted rather than observed: the **right**
      password is refused while the five-failure lock holds and earns no
      session, and three ways past the second factor — a wrong OTP code, a
      `grant_type=password` at the token endpoint with and without the client
      secret, and a service-account bearer token — all answer 302 or
      `unauthorized_client`. **Token replay was ours and the box's premise was
      wrong:** `src_ip` held the *first* request's address and a replayed
      cookie is the same cache entry, so the second address was folded into the
      owner's row — measured on the deployed backend as `172.19.0.1:3`, one row
      for three requests from two places. The counters are now keyed on
      `(outcome, src_ip)`; red first in `cache.rs` and through `/decide` to
      Postgres, then on the lab: `172.19.0.1:2` + `192.168.1.112:1`, and the
      report finds the subject at two addresses. The run's own finding is that
      `172.19.0.1` is **Docker's bridge gateway** — every client on the host
      NATs to it whatever it binds, so a one-host version of this check would
      have passed against the broken code, and the record separates clients
      only as far as the last NAT in front of nginx. Not built: the alerting
      half (F-23 already ships the stream) and an `acr` input to `/decide`,
      which stays the `docs/06` question.

- [x] **Backend on 2 instances + nginx health check (HA — after the first
      deployment).** N-06 puts HA outside v1 and the box waited on a first real
      deployment. §17.1's "Keycloak must never run single-node in production" is
      the same box seen from the roadmap's side, and the product's answer is
      already written down rather than shipped — `start-dev` + embedded H2 is
      lab-only and the production form is INSTALL.md §5.
      Two things were known before it opened, both from measurement.
      **nginx OSS has no `health_check` directive** — only passive
      `max_fails`/`fail_timeout`, which ejects an instance after users have
      already met the failure — so the check has to be NGINX Plus, a patched
      build, or something outside nginx that polls `/readyz` and rewrites the
      upstream list, the shape ADR-0011 already uses (`docs/07`). And the load
      test says **the first instance to add is nginx, not the backend**: at 32
      connections nginx used 138% of two cores and the backend 11%.
      The design question the cache raised was **answered**:
      [ADR-0031](docs/adr/0031-decision-cache-multi-instance.md) keeps the cache
      in memory and broadcasts its invalidations over the Redis ADR-0019 already
      requires, both transports measured (`docs/07`). What this box still owed
      it was the subscriber itself, the rule that an instance with no live
      subscription serves no cache hits, and a decision about the gap that rule
      leaves — a connection alive at TCP level with a wedged reader.
      **Closed: the subscriber, the rule, a heartbeat the gap turned out to
      need — and the health check deleted rather than built** (`docs/07`,
      harnesses `verify-ha.sh` and `verify-ha-wedge.sh`). Two instances run on
      `--scale backend=2` with no configuration change, and **the second thing
      known before it opened was wrong**: nginx OSS needs no active check here.
      `decide.inc` proxies through a variable, so the `resolver` hands back both
      addresses per request and `proxy_next_upstream error timeout` — nginx's
      own default — retries the survivor **inside the same request**; 30 of 30
      requests were served with one instance stopped. What the failure costs is
      the request that finds it: `proxy_connect_timeout`, 1.04 s worst, then
      that peer is skipped for ten seconds. So no poller, and `docs/02`'s "ejects
      an instance after users have already met the failure" is corrected. The
      broadcast itself: both instances holding live entries for one session, a
      kill switch served by either, **0.11–0.14 s** to refused on both against
      ADR-0016's 5 s — red first in `cargo test`, where removing the publish
      leaves the second instance answering 200. **The gap ADR-0031 named was
      real and is now closed rather than written down.** `docker pause` on Redis
      is exactly its shape — no FIN, no RST, every socket ESTABLISHED — and
      without a heartbeat the instance served **16 of 16 stale ALLOWs and never
      noticed**. A `PING` on the subscribed connection itself (5 s between
      beats, 5 s for the answer) brings the first refusal to **8.5–9.2 s**.
      `/readyz` already answered 503 throughout, which is the honest limit of
      the experiment: it would have caught *this* failure too, but it cannot
      report on the connection the rule is about, and it cannot make the
      instance stop trusting its own cache. Not done: any instance count under
      load — the load figures are all single-instance and `vaultscan` runs the
      generator itself, which is why N-06 still keeps HA outside v1.

---

## Later

The roadmap did not add much here; mostly it **sharpened items already on this
list**, which is the more useful outcome — each one below now names the shape
somebody else's architecture document expects it to arrive in.

- Conditional access (F-21) → the `entitlement.conditions` column. Beyond IP,
  time and `acr`, §8.3 wants the decision to be able to read **`network_zone`**,
  **`user_type`** and **`identity_provider`**, and §10 wants a **per-application
  MFA level** — which is where [ADR-0032](docs/adr/0032-admin-mfa.md) already
  routed it ("a rule on an entitlement rather than a property of a login"). A
  fifth is the session's age, if `docs/06`'s shorter-session question is answered
  with yes. One column, five inputs; they arrive together or the column is
  designed twice.
- **Step-up MFA** for a critical operation (§10.3 Faz 3). A different thing from
  the above: it is re-authentication *inside* a session, so it needs a way for
  an upstream to demand it — and this product deliberately tells upstreams
  nothing but `X-Auth-*` ([ADR-0021](docs/adr/0021-application-identity-trusted-headers.md)).
  Blocked on that, not on effort.
- A signed identity JWT to the upstream + a JWKS endpoint (`docs/06`, Security).
  This is [ADR-0021](docs/adr/0021-application-identity-trusted-headers.md)'s
  option C and it is also §5.3's whole model — the upstream as an OAuth2
  resource server checking signature, `iss`, `aud` and `scope` itself. The ADR's
  reversal trigger is the condition; the roadmap is a second reason it will be
  asked for.
- A service-account / machine-to-machine access path (CI, monitoring, mobile).
  §6.6 names the shape: **Client Credentials**, and for the high-assurance case
  **mTLS + an IP allowlist** on top. `/decide` is cookie-keyed today
  ([ADR-0001](docs/adr/0001-scope-v1-web-only.md), web only), so this is a
  second entry path and not a flag.
- Per-person time-limited access (JIT access, `expires_at`) + the `known_user`
  table and person selection in admin.
- Audit hash chain (`prev_hash`) — stays here: ADR-0014 chose differentiators
  that are not audit-led, so it does not enter `0001_init.sql`.
- SIEM integration (F-23), access reports (F-24). §16 and §19 want login,
  logout, token and admin events in the SIEM; F-14's structured log stream is
  where they already are.
- Group name ↔ SID drift auditing.
- **A second identity source, brokered by Keycloak** (§5.6, §6.5 — e-Devlet in
  that document's case, an external IdP in general). AD is the only source today
  ([ADR-0006](docs/adr/0006-group-membership-source.md)). The federation half is
  Keycloak configuration; the half that is ours is the decision reading
  `identity_provider`, which is the conditional-access column again.
- **Rate limiting and a WAF in front of externally published applications**
  (§16). Rate limiting exists for exactly one thing today — admin write screens,
  [ADR-0033](docs/adr/0033-admin-write-screens.md). A WAF is the operator's box,
  but where it sits relative to the PEP is a documented deployment, so it is
  ours to write.
- **Secrets from a manager rather than `.env`** (§12: Vault / External Secret
  Manager). Today `.env` + environment variables, deliberately. An installation
  that already runs Vault should not have to fork the compose file.
- **Environment separation** (§18: dev / test / preprod / prod, separate secrets
  and separate realm per environment). N-05 is one machine and `docker compose
  up`; the roadmap's separation is a deployment document, not a feature — but
  it is a document this repo does not have.
- **Token-signing key rotation** (§12). Keycloak's to perform; the product's to
  say what breaks while it happens, because oauth2-proxy caches JWKS.
- **An application onboarding document** (§20). The intake table (§20.1) and the
  eleven-item test list (§20.3 — login, bad login, MFA, refresh, timeout, global
  logout, role mapping, upstream token validation, unauthorised access, SIEM
  lines, rollback) is a checklist this product can be *held to*, and every item
  on it maps onto something already built. The cheapest real deliverable on
  this page.
- SSH/RDP → define Apache Guacamole as a protected application (ADR-0001).
- HA / multiple instances → see the box above.

---

## Read and refused

The roadmap's own scope, and why it does not become work here. Kept so it is not
re-litigated every time somebody reads that document.

| §  | What it asks for | Why not |
|---|---|---|
| 5.4, 5.8, 17.1 | API Gateway / Apinizer, Kubernetes, F5, Infinispan | The roadmap's infrastructure layer. **nginx *is* the PEP here** ([ADR-0002](docs/adr/0002-pep-nginx-auth-request.md)) and N-05 is one machine with `docker compose up`. A gateway in front is a deployment somebody may have; it is not a component this product grows. |
| 6.4 | SAML, Form/Password Injection, dual login | [ADR-0001](docs/adr/0001-scope-v1-web-only.md) is web-OIDC only, and "password vault / credential injection" is on `docs/06`'s explicit out-of-scope list. Note where this product already sits in that section's own priority order: **3 and 4, header-based authentication and gateway adaptation** — which is [ADR-0021](docs/adr/0021-application-identity-trusted-headers.md) option A, decided on measurement. |
| 13.3 | Applications detect logout over back-channel | **Global logout already works**, and not by accident: portal sign-out calls oauth2-proxy's `/oauth2/sign_out`, whose `backend_logout_url` hits Keycloak's `end_session_endpoint` with the session's own `id_token` — in that order, because the `id_token` lives inside the session being destroyed (`docs/02`, measured `docs/07`). What is *not* ours is an upstream running its own OIDC: ADR-0021 says whoever installs that owns the second session, back-channel logout included. |
| 7.1, 15.1 | internal / external / partner realm segmentation | One realm, and the issuer URL in `docker-compose.yml` names it directly. Segmentation is a deployment topology this product neither needs nor prevents; it would change the compose file, not the code. |
| 7.3 | `APP_*_ACCESS` AD group naming | The naming is the operator's. [ADR-0008](docs/adr/0008-group-identity-name.md) fixes only what this product must fix — matching by name, an `OpenBerat-` prefix, and `ADMIN_GROUP`. |
| 20.4, 21, 22 | Approvals, the responsibility matrix, the phase plan | Somebody's project management. Real work, not this repo's. |
| 24 | Login performance "within the target time" | Already measured and tighter than the roadmap asks: N-01 **11–29 µs** mean, N-02 under 10 ms on 31 of 31 concurrent first visits (`docs/07`). |
