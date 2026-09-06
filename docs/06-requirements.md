# 06 — Requirements and Open Questions

> This is a **living** file. When an open question is answered it is deleted from
> here and the decision is written to `docs/adr/`.

## Functional requirements

### v1 — non-negotiable

| ID | Requirement |
|---|---|
| F-01 | The user signs in via SSO through Keycloak; Keycloak verifies the identity against AD. |
| F-02 | A protected application cannot be reached without an identity (fail-closed). |
| F-03 | The applications a user can reach are derived from AD group membership. |
| F-04 | The portal lists only the applications the user can reach. |
| F-05 | An application not shown in the portal cannot be reached by direct URL either. |
| F-06 | An admin can define applications (name, target address, icon). |
| F-07 | An admin can map AD group ↔ application (allow/deny). |
| F-08 | Every access decision enters the audit record; rows are written summarised — counters plus a single summary row (`docs/02`, "Audit granularity"). |
| F-09 | An admin can terminate all of a user's sessions immediately (kill switch). |
| F-10 | A user disabled in AD loses access within a defined period. |
| F-11 | Path-based authorisation: a single path of an application (`/admin/*`) can be bound to its own rule. |
| F-12 | Management endpoints (`/api/admin/*`) are bound to a separate AD group (`ADMIN_GROUP`); portal access does not grant admin rights. |
| F-13 | An application defined by an admin becomes genuinely reachable through generated nginx configuration (ADR-0011). |
| F-14 | State-changing admin actions and kill switch invocations are recorded: actor, action, target, outcome — the structured log stream in v1 (`docs/02`, "Management plane"). |

### v2 — later

| ID | Requirement |
|---|---|
| F-20 | Per-person time-limited access (JIT access), via `expires_at`. |
| F-21 | Conditional access: IP range, MFA level (`acr`), time window. The `entitlement.conditions` column is added in this release. |
| F-23 | The audit log is shipped to a SIEM (syslog/webhook). |
| F-24 | Access reports: "what can user X reach", "who can reach application Y". |

### Explicitly out of scope

- SSH/RDP/DB session brokering and session recording → Apache Guacamole if needed
- Password vault / credential injection
- Device posture, agents
- Approval workflow, ticket integration
- In-application role management (the upstream's job)

## Non-functional requirements

| ID | Requirement | Target |
|---|---|---|
| N-01 | Authorisation decision latency (cache hit) | **< 2 ms** *(drafted from measurement; fixed under load in Phase 6)*. Measured overhead of the hop itself: **+74 µs** (`docs/07`). The cache entry must carry the identity too, otherwise this is unreachable — `docs/05`. |
| N-02 | Authorisation decision latency (cache miss) | **< 10 ms** *(drafted from measurement; fixed under load in Phase 6)*. Measured: **+571 µs** for the double hop, before the entitlement query and the index write, which do not exist yet (`docs/07`). |
| N-03 | Revocation delay | **≤ 6 min** for an AD change, **≤ 5 s** for the kill switch ([ADR-0016](adr/0016-n03-revocation-targets.md)). Measured for the AD change: **330 s**, a reachable ceiling rather than a tail — `cookie_refresh` + cache TTL, with 30 s of margin left. Re-measured in Phase 6 against the finished chain and unchanged; the ceiling is the only figure that is a property of the system, because the cut lands at a fixed session age and the delay from the AD change moves with how late the change fell after the session was minted (`docs/07`). Measured for the kill switch: **0.085 s** end to end (`docs/07`), on the session index of [ADR-0019](adr/0019-kill-switch-session-index.md). WebSocket/SSE connections already upgraded are excluded from the guarantee, idle or active — measured, `docs/07`. |
| N-04 | Audit log retention period | **? — depends on KVKK and internal policy** |
| N-05 | Must come up with `docker compose up` on a single machine | v1 |
| N-06 | High availability (HA) | No in v1; the design will not prevent it |
| N-07 | Target concurrent users | **? — undecided** |

## Open Questions

Questions that need an answer and will change the design. Delete as they are
answered and write the decision to `docs/adr/`.

### Decided ✅

| Topic | Decision | ADR |
|---|---|---|
| Scope | Web only (SSH/RDP in v2, via Guacamole) | [0001](adr/0001-scope-v1-web-only.md) |
| PEP | nginx + `auth_request`, no proxy of our own | [0002](adr/0002-pep-nginx-auth-request.md) |
| OIDC login | Delegated to oauth2-proxy | [0003](adr/0003-oidc-oauth2-proxy.md) |
| Backend language | Rust (axum + sqlx) | [0004](adr/0004-stack-rust.md) |
| Structure | Separate frontend, one directory per container, Docker | [0005](adr/0005-frontend-backend-split.md) |
| Group membership source | oauth2-proxy header + mandatory `cookie_refresh` | [0006](adr/0006-group-membership-source.md) |
| Frontend | Buildless static (HTML + Alpine.js), no npm | [0007](adr/0007-frontend-buildless-static.md) |
| Group identity, prefix, `ADMIN_GROUP` | Match by name; `OpenBerat-` prefix; `ADMIN_GROUP` defaults to `OpenBerat-Admins` | [0008](adr/0008-group-identity-name.md) |
| Policy engine | Our own code in `policy.rs`, with a written reversal trigger | [0009](adr/0009-policy-engine-own-code.md) |
| Lab AD | Samba AD DC, with Windows Server as the escalation path | [0010](adr/0010-lab-ad-samba.md) |
| nginx application blocks | Generated from the `application` table | [0011](adr/0011-nginx-config-generation.md) |
| Project name | OpenBerat | [0012](adr/0012-project-name-openberat.md) |
| Licence | GPL-3.0-or-later; not sold, no dual licensing | [0013](adr/0013-licence-gpl.md) |
| Why not Pomerium/Authentik | Three differentiators + one to confirm; abandon trigger written down | [0014](adr/0014-differentiator-vs-pomerium.md) |
| Common parent domain, portal address, cookie scope | Required; portal at `portal.apps.<domain>`; cookie on `.apps.<domain>` | [0015](adr/0015-single-parent-domain.md) |
| N-03 revocation targets | 6 min / 5 s, upgraded connections excluded | [0016](adr/0016-n03-revocation-targets.md) |
| Single point of failure | Accepted, with a rehearsed break-glass | [0017](adr/0017-fail-closed-availability.md) |
| Outside contributions | DCO (`git commit -s`), no CLA | [0018](adr/0018-contributions-dco.md) |
| Finding a user's oauth2-proxy session for the kill switch | The backend keeps a `sub → session` index in Redis | [0019](adr/0019-kill-switch-session-index.md) |
| Frontend packaging | Static files copied into the nginx image at build; no frontend container | [0020](adr/0020-frontend-in-nginx-image.md) |
| AD group strategy | `GET_GROUPS_FROM_USER_MEMBEROF_ATTRIBUTE` | `docs/03`, `docs/07` |

### 🔴 Needs an answer about the target environment

These cannot be decided from the design; they are facts about the customer's AD,
network and policy. Phase 1 exists partly to establish them.

- [ ] **Are nested groups used in AD?** Still a question about the customer's
      directory, but no longer about the consequence. Measured in Phase 1
      (`docs/07`): a user who is only a transitive member gets **no `groups`
      claim at all** on the default strategy — denied everything, not granted
      the wrong thing — and `LOAD_GROUPS_BY_MEMBER_ATTRIBUTE_RECURSIVELY` fixes
      it from the next login, including across intermediate groups the
      `(cn=OpenBerat-*)` filter excludes.
- [ ] **Wildcard certificate: internal CA or Let's Encrypt?** ADR-0015 makes the
      certificate mandatory but not its source. If it is baked into the image,
      renewal means an image build, and expiry takes **every** application down
      at once. This is a **production** question; the Phase 1 lab does not wait
      for it — a self-signed wildcard is enough there, and the lab needs one from
      its first day because the OIDC redirect and the `Secure` cookie do not work
      over plain HTTP.
- [ ] MFA: **wanted** (maintainer intent, 2026-09-05) as TOTP — the user scans a
      QR once and types the code from a phone app (Google Authenticator,
      FreeOTP…). The basic form is **Keycloak realm configuration only**, no
      code in this repository (`docs/03`, "MFA"). Still open, and
      environment-dependent: for everyone at login, or per application — the
      per-application form reads `acr` and is F-21, v2. When it is switched on
      is free: config can land in any phase without touching the roadmap.
- [ ] **Do the protected applications strip path parameters?** Tomcat and Jetty
      drop `;jsessionid=…` from a segment, so `/admin;x/` reaches the
      application as `/admin/` while `policy.rs` sees a segment that matches no
      deny rule. Folding `;` the way `\` is folded (`docs/05`) would close it
      and would change what a legitimate path containing `;` means, so the
      answer depends on what runs behind the proxy. Until it is answered, an
      application on a Java stack should carry its deny rules one segment
      higher.
- [ ] Is Kerberos/SPNEGO (passwordless domain SSO) wanted?
- [ ] Is there more than one AD domain / forest?
- [ ] Audit log retention period (N-04) — KVKK and internal policy.
- [ ] Target concurrent user count (N-07), and how many applications, users and
      AD groups. Without N-07 the Phase 6 load test has no target. **How many
      groups a single user is in is now a sizing input, not only a load-test
      one:** the whole list travels in one header on every decision, and the
      nginx buffer that reads it is set from this number (`docs/07`).
      **The rate limits are set from it too** — `00-auth.conf` currently guesses
      50 r/s per address for decisions and 5 r/s for the login flow, and the
      case that breaks them first is a site behind NAT, where one address is an
      entire office.

### 🔴 Security, still open

- [ ] **How does a protected application learn who the user is?** The portal
      lists an application and the click reaches it without a second OpenBerat
      login — that part is built. Whether the *application* then asks for a
      password is undecided, and it is the difference between a product and a
      link collection. Two mechanisms, and neither is free:
      **(1) trusted headers.** The application is configured to believe
      `X-Auth-Username` / `-Email` / `-Groups`, which `protected.inc` already
      writes and already strips from the request side. No code, no per-application
      registration. It does hand the comma problem to a second consumer: the
      groups header is comma-joined, so an application deriving its own roles
      from it inherits the `Payroll,OpenBerat-Admins` attack, and the
      `(cn=OpenBerat-*)` filter measured in `docs/07` stops being a mitigation
      for `ADMIN_GROUP` alone. Its entire security rests on "only nginx can reach that
      port" — a network assumption, and one that a single wrong compose line
      breaks in silence. It is the question below, with the stakes raised: under
      (1) a bypass is not information disclosure, it is impersonation.
      **(2) the application runs its own OIDC against Keycloak.** The click
      redirects, Keycloak already holds the user's SSO session, the user types
      nothing. No header to forge. But it mints a **second session, with its own
      lifetime, that nothing of ours controls** — and on a shared browser that
      is an identity confusion bug: user A logs out, user B logs in and is
      authorised by us as B, while the application still holds A's cookie and
      serves them as A. The audit record then names B for A's actions. The fix
      is OIDC back-channel logout, which is a **third** thing the application
      must support, on top of (2) itself.
      (2) also adds a registration the design does not have: every such
      application needs its own Keycloak client, so an application exists in two
      places — the `application` table ([ADR-0011](adr/0011-nginx-config-generation.md))
      and Keycloak — with nothing keeping them in step. Whichever is chosen, the
      answer belongs in `INSTALL.md` and in the Phase 6 integration item, because
      an operator cannot guess it.
- [ ] **Can upstream applications be reached bypassing nginx?** Three answers:
      (a) network isolation (the v1 default: upstreams on `edge` with nginx
      alone, the decision chain on `core` — `docs/02`, "Deployment"), (b) mTLS,
      (c) a **short-lived
      signed identity JWT** to the upstream plus a JWKS endpoint. (c) is the one
      that stands up to an audit, and it is a small piece of work.
      [ADR-0015](adr/0015-single-parent-domain.md) raised its priority: with a
      shared session cookie, a compromised protected application is a realistic
      path to the rest of the system. **And the question above raises it
      again:** if applications are integrated by trusting `X-Auth-*`, then (a)
      is the only thing standing between a reachable upstream port and
      impersonating any user, so (a) stops being a deployment default and
      becomes a security control that has to be tested.
- [ ] **Should `worker_shutdown_timeout` be set, and to what?** Measured
      (`docs/07`): it is the only lever short of restarting nginx that reaches a
      WebSocket already up, and without it ADR-0011's reload-per-application-change
      leaves one `shutting down` worker behind per reload while such a connection
      is open. Setting it bounds both — but it also bounds *ordinary* reloads, so
      the value is a trade between how long a revoked long-lived connection may
      survive and how abruptly a normal config change cuts requests in flight.
      An ADR, not a config tweak, because it changes what
      [ADR-0016](adr/0016-n03-revocation-targets.md) excludes.
- [ ] **Nothing reconciles the group claim against AD.** F-03 and F-12 both
      derive authorisation from AD group membership, but measured (`docs/07`)
      the `groups` claim is AD's `memberOf` **union** whatever groups Keycloak
      holds locally — including a group AD no longer has. So an operator
      auditing "who holds `ADMIN_GROUP`" by reading AD gets an answer that can
      be wrong, and F-14 does not cover it: the grant happens in Keycloak, not
      through `/api/admin/*`. Either the product reconciles the two (a periodic
      check, or refusing a claim entry with no AD group behind it) or it says
      plainly that Keycloak's group tree is part of the trusted base. The
      second is cheaper and probably right — but it has to be written down,
      because `docs/02` and `docs/03` used to imply the first.
- [ ] **How does an operator get into the machine when the identity chain is
      down?** [ADR-0017](adr/0017-fail-closed-availability.md) requires that host
      access does not depend on this product; the concrete mechanism (out-of-band
      admin path, its own credentials, how it is audited) is not designed yet.

