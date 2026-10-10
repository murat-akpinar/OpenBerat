# TODO

Status: **the security audit run-1 boxes below are open**; nothing is tagged. Every phase and every box is
closed; what closed each one — the measurement, the thing that turned out to be
wrong, the ADR it forced — is in
[`docs/09-history.md`](docs/09-history.md), 157 boxes of it: phases 0–7, the
backlog that came out of reading an enterprise SSO roadmap against the finished
product, and the second-factor reset that ADR-0035 left behind it.
**A tag is still a deliberate manual act** ([ADR-0023](docs/adr/0023-versioning-and-release.md)).

What is left on this page is **not** scheduled work. `Later` is the standing
backlog — nothing on it is started, and most items name the shape somebody
else's architecture document expects them to arrive in. `Read and refused` is
kept underneath it so the refusals are not re-litigated every time that roadmap
is read again.

Decisions: `docs/adr/` · Open questions: `docs/06-requirements.md`

---

## Open — security audit run-1 (2026-10-10)

Report lives outside the repo (`~/security-audit-skill/OpenBerat/run-1/`).
Closed so far: resubscribe cache flush, duplicate session cookie
(leads 7/11/12), h2c / upstream cookie Domain / `;` on the auth host
(leads 2/6/9), realm `admin-cli` (lead 3), `upstream_url` host charset
(lead 8), path readings (leads 4/5, ADR-0037), one network per application
(lead 1, ADR-0038), part of the hardening notes (`5514dfa`, nonce), the stale
`dist/` bundle (deleted), and all of it deployed and measured on the lab
(`docs/07`, "Security audit run-1").

- [ ] **Every session dies at its first `cookie_refresh`.** Measured on the lab
  2026-10-10 with an unlocked, unexpired AD account (`lablock`) as the control:
  `/api/me` 200 until 300 s, 302 to Keycloak at 315 s; oauth2-proxy logs
  `error refreshing access token … session is invalid, removing session` and
  Keycloak logs no refresh error. Suspect `23cea56`
  (`insecure_oidc_skip_nonce = false`), not yet proven: the A/B run with the
  nonce check off on the lab was not made. Find the cause, fix it, and measure
  that a control session survives the refresh.
- [ ] Lead 10 again: `docs/07` says AD expiry is **refuted** because the session
  ended at the first refresh, but every session ends there (box above), so the
  run proves nothing. Re-run expiry after the fix and correct `docs/07`.
- [ ] VERIFY: an AD account locked out (`lockoutTime`) keeps its session past
  `cookie_refresh`? Run once 2026-10-10 (threshold 3, `lockoutTime` set,
  computed UAC 16, a good-password bind refused): 302 at 305 s, but the
  unlocked control died the same way, so it is void. Re-run after the fix;
  `lablock` stays in the lab AD for it, the threshold is back at 0.

The hardening notes that were not applied, triaged 2026-10-10. Each was checked
against `main` and still holds. The ones below touch a security boundary;
the rest are under `Later` or `Read and refused`.

- [ ] The second-factor reset's privileged-target refusal reads
  `users/{id}/groups` with no `max` (`keycloak.rs`), so it trusts Keycloak's
  paging default to show every group. Ask with an explicit bound, or check
  `ADMIN_GROUP`/`AUDITOR_GROUP` membership directly; a test where the
  privileged group is past the first page.
- [ ] The backend takes `X-Auth-*` from any peer that reaches `backend:8081`
  (`main.rs` binds `0.0.0.0`). The repo's `samba-ad` is on `core`, and `docs/02`
  tells operators to attach Prometheus there; either can forge an admin. Needs
  an ADR first: a secret header only nginx sets, or Prometheus and the DC off
  `core`.
- [ ] Keycloak's service account holds `manage-users`, which is more than the
  four calls the backend makes, and the realm export defines **local** groups
  `OpenBerat-Admins` / `OpenBerat-Auditors`: the backend secret plus a
  route to the Admin API could add a local user to `ADMIN_GROUP`. Decide
  between fine-grained admin permissions (v2) and dropping the local group
  definitions; ADR-0036's "cannot set a password" holds only because the LDAP
  provider is `READ_ONLY`, and has to say so (`docs/07` Unverified).
- [ ] ADR-0006 asks for a configuration test and none exists: `cookie_refresh`
  set, `NO_CACHE` on the LDAP provider, and `accessTokenLifespan` ≤
  `cookie_refresh` — the refusal measured for lead 10 rests on all three. A CI
  grep or a Rust test that reads the realm export and `oauth2-proxy.cfg`.
- [ ] The auth host forwards every path under `/realms/openberat/`, including
  `clients-registrations/` and `broker/`; anonymous client registration then
  depends on Keycloak's import defaults. Narrow it to what the login flow uses,
  and refuse `%25` in the path as `;` already is.
- [ ] Pin the OTP policy in the realm export (`otpPolicyType`, algorithm,
  digits, look-ahead, `CodeReusable`) so a Keycloak upgrade cannot change the
  second factor's strength silently.
- [ ] `nginx.rs` `stage()` writes every publication through one fixed
  `{name}.writing` path: two concurrent admin writes fail one of them (the
  audit measured 50 of 50) and an older snapshot can be staged last. A unique
  temp name, publications serialised under `pg_advisory_xact_lock`, and a
  test with two interleaved calls. `publish_status` also answers `staged`
  when `NGINX_CONF_DIR` is unset.
- [ ] Refuse the literal `change-me` values from `.env.example` at startup;
  the backend client secret guards a `/token` endpoint the internet can reach.
- [ ] `/api/admin/explain` trims whitespace around group names and `/decide`
  does not, so the two can disagree; one shared split, tested.
- [ ] Before the first tag: `release.sh` builds images from the working tree
  rather than the archived `$ref`, records mutable tags rather than digests,
  and ships no `SHA256SUMS`. CI's actions are pinned by tag, not SHA, and
  checkout keeps its credentials.

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
- **N-01 and N-02 under concurrency, on more than one instance.** The HA box
  closed on correctness, not on load: `--scale backend=2` is measured for
  failover and for the kill switch reaching both instances, and every latency
  figure in `docs/07` is still single-instance. It is also the reason N-06
  keeps HA outside v1, and what `INSTALL.md`'s closing note points here for. The
  obstacle is the lab, not the code: `vaultscan` runs the load generator on the
  machine under test.
- **Security audit run-1, the smaller notes.** None reaches past a boundary
  today; each narrows something already bounded.
  - A `killed:{sub}` tombstone checked on the miss path: closes the in-flight
    miss accepted in `admin.rs` and a brand-new session indexed between the
    kill's `SMEMBERS` and `DEL`, which lives until `cookie_refresh`.
  - Entitlement delete, application delete/disable and slug reuse publish on
    `openberat:invalidate` instead of waiting out the 30 s TTL.
  - `validate_upstream` is an exact-name denylist: container names, core IPs on
    unlisted ports and a public name resolving to `127.0.0.1` pass it. An
    allowlist of application networks would bound it; and the `upstream_url`
    CHECK in a new migration could match the API's host charset.
  - The 16-shard fill lock is taken before oauth2-proxy has authenticated the
    cookie, so junk cookies compete with real refills; `Index::record` has no
    client-side timeout and holds a shard on a wedged Redis.
  - Application networks are not `internal`: a compromised upstream has egress.
  - The per-flow `_oauth2_proxy_<id>_csrf` cookies still reach Keycloak and the
    upstreams for their 15 min.
  - A WebSocket tunnel is outside per-request path authorisation as well as
    revocation; ADR-0016 says only the latter.
  - Cosmetic: `members()` without `max` caps the Users tab's `privileged` flag
    at 100; the entitlement audit line logs the untrimmed subject; a missing
    `application_id` answers 503 rather than 400; `logredact.inc` redacts only
    the last `code=`; `logo.svg`'s location carries no CSP.

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

Security audit run-1's notes that are decided or accepted by design, kept for
the same reason.

| Note | Why not |
|---|---|
| Refuse any path holding `#`, `\` or `%2F` | ADR-0037 chose evaluating every reading over refusing them; legitimate `/job/feature%2Ffoo/` keeps working. |
| Compose runs Keycloak `start-dev` | The lab default; the production form is INSTALL.md §5. |
| `validate_icon` accepts `javascript:` | Its one sink is `img.src` behind a `^/[^/]` check and the CSP; an `img` does not run script. |
| Trust-on-first-use second-factor enrolment | Accepted in ADR-0035/0036. |
| `/oauth2/sign_out` by cross-site GET | Logout CSRF signs the user out; no identity is gained. |
| A narrower-`Path` session cookie set by a compromised application | Two session cookies is `ambiguous_session` and refused (`4a339b7`). |
| `$upstream_http_set_cookie` relays one value | The Redis session store emits one cookie. |
| `Entry.counters` per source IP has no cap | Bounded by the TTL and the per-address rate; marked `ponytail:` in `cache.rs`. |
