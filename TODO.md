# TODO

Status: **phases 0–7 are closed and nothing is tagged.** What closed each phase,
and the 148 boxes that did it, moved to [`docs/09-history.md`](docs/09-history.md).
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

## Open

- [ ] **The realm ships exactly one security profile, and the roadmap wants
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

- [ ] **`/api/admin/*` is all-or-nothing, and the roadmap wants an auditor.**
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

- [ ] **Configuration-as-Code is asserted and nothing verifies it.**
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

- [ ] **Break-glass is written and timed at nothing.** `docs/08` and
      [ADR-0030](docs/adr/0030-breakglass-generated-blocks.md) describe the way
      back in; §24 gives the equivalent criterion a number — a rollback to the
      old login **under 10–15 minutes**. [ADR-0017](docs/adr/0017-fail-closed-availability.md)
      is why the number is not optional: a phase does not close on a procedure
      being *written*, only on its having been run.
      *Run it against the lab, with a clock, and put the figure in `docs/07`.
      If it does not fit, the procedure is what changes, not the target.*

- [ ] **The audit partitions have never been restored.**
      [ADR-0022](docs/adr/0022-audit-retention.md) drops a month as a partition
      and defaults to twelve; §17.3 and §24 both want a restore that has
      actually been performed, and §17.3 additionally wants a stated recovery
      target. Encrypted backups (§12) are the operator's; **a restore drill is
      ours**, because the schema is ours and a partitioned table is exactly the
      shape that restores wrong.
      *A drill on the lab, and one figure in `docs/07`. No new feature.*

- [ ] **Three attack scenarios named by §24 have no check.** The success
      criteria ask for brute-force, **token replay** and **MFA bypass** to be
      tested; `CLAUDE.md` step 3 already requires the attack to be tested rather
      than the happy path, and the existing suite does that for forged
      `X-Auth-*`, double encoding, `/x/../admin/` and post-kill-switch cache
      refill. These three are simply not among them. Token replay in this
      product's terms is one subject with two source addresses inside one
      window — `audit_event.src_ip` already holds what the query needs, which is
      why it sat in **Later** as a report; §16 promotes it to a control.
      *Brute-force and MFA bypass are realm behaviour and belong in the lab
      script, not in `cargo test`. Say which is which when the box opens.*

- [ ] Backend on 2 instances + nginx health check (HA — after the first deployment)
      *Not started: N-06 puts HA outside v1 and the box waits on a first real
      deployment. §17.1's "Keycloak must never run single-node in production" is
      the same box seen from the roadmap's side, and the product's answer is
      already written down rather than shipped — `start-dev` + embedded H2 is
      lab-only and the production form is INSTALL.md §5.
      Two things are known before it opens, both from measurement.
      **nginx OSS has no `health_check` directive** — only passive
      `max_fails`/`fail_timeout`, which ejects an instance after users have
      already met the failure — so the check has to be NGINX Plus, a patched
      build, or something outside nginx that polls `/readyz` and rewrites the
      upstream list, the shape ADR-0011 already uses (`docs/07`). And the load
      test says **the first instance to add is nginx, not the backend**: at 32
      connections nginx used 138% of two cores and the backend 11%.
      The design question the cache raised is **answered**:
      [ADR-0031](docs/adr/0031-decision-cache-multi-instance.md) keeps the cache
      in memory and broadcasts its invalidations over the Redis ADR-0019 already
      requires, both transports measured (`docs/07`). What this box still owes
      it is the subscriber itself, the rule that an instance with no live
      subscription serves no cache hits, and a decision about the gap that rule
      leaves — a connection alive at TCP level with a wedged reader.*

---

## Later

The roadmap did not add much here; mostly it **sharpened items already on this
list**, which is the more useful outcome — each one below now names the shape
somebody else's architecture document expects it to arrive in.

- Conditional access (F-21) → the `entitlement.conditions` column. Beyond IP,
  time and `acr`, §8.3 wants the decision to be able to read **`network_zone`**,
  **`user_type`** and **`identity_provider`**, and §10 wants a **per-application
  MFA level** — which is where [ADR-0032](docs/adr/0032-admin-mfa.md) already
  routed it ("a rule on an entitlement rather than a property of a login"). One
  column, four inputs; they arrive together or the column is designed twice.
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
