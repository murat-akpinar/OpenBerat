# TODO

Status: **one box is open**, and nothing is tagged. Every phase and every box
before it is closed; what closed each one — the measurement, the thing that
turned out to be wrong, the ADR it forced — is in
[`docs/09-history.md`](docs/09-history.md), 156 boxes of it: phases 0–7, and the
backlog that came out of reading an enterprise SSO roadmap against the finished
product.
**A tag is still a deliberate manual act** ([ADR-0023](docs/adr/0023-versioning-and-release.md)).

What is left on this page is **not** scheduled work. `Later` is the standing
backlog — nothing on it is started, and most items name the shape somebody
else's architecture document expects them to arrive in. `Read and refused` is
kept underneath it so the refusals are not re-litigated every time that roadmap
is read again.

Decisions: `docs/adr/` · Open questions: `docs/06-requirements.md`

---

## Open

- [ ] **A way to reset a user's second factor from the management plane.**
      [ADR-0035](docs/adr/0035-mfa-for-every-user.md) made MFA everybody's, and
      with it made a lost or replaced phone a routine helpdesk task rather than
      a rare one. [ADR-0032](docs/adr/0032-admin-mfa.md)'s answer — the Keycloak
      admin console under `KC_ADMIN_PASSWORD` — was sized for a handful of
      admins: it makes a routine task reach for the realm-master credential, and
      a credential reached for often is a credential that gets shared.

      **Measured already** (`docs/07`), so the shape is not in doubt: the
      backend's existing service account, the one the kill switch uses, answers
      **200** to a username query and to reading a user's groups, and its
      `DELETE` on a credential answers **404** rather than 403. The permission is
      already held — only the HTTP surface is missing. No new secret, no new
      role, no compose change.

      **The decision this needs an ADR for is the scope, not the mechanism.**
      The intended shape, to be argued in the ADR rather than assumed here:
      `ADMIN_GROUP` only (`AUDITOR_GROUP` is GET-only and excluded by the guard
      that already exists), **refusing a target in `ADMIN_GROUP` or
      `AUDITOR_GROUP`** — resetting a privileged account's second factor stays a
      terminal call, the way revocation did
      ([ADR-0024](docs/adr/0024-no-admin-ui-in-v1.md)) — and **refusing self**,
      since an admin who is already past MFA gains nothing and a stolen session
      gains durability. Audited like every other management-plane write.

      One thing the shape has to solve before it is a button: **the admin UI has
      no user directory.** The only place a person appears is the Live tab, over
      the kill-switch index ([ADR-0028](docs/adr/0028-live-sessions-endpoint.md)),
      and somebody who cannot log in will never be in it. Either the admin types
      a username and the backend resolves it, or this grows a user list — and a
      user list is a surface this product has deliberately never had
      (`known_user` is still on `Later`, unstarted).

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
