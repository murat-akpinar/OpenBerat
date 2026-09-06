# 0021 — A protected application learns who the user is from trusted headers

- **Status:** Accepted
- **Date:** 2026-09-06

## Context

The portal lists an application, the click reaches it and no second OpenBerat
login appears. That part is built. What the **application** does next was
undecided, and it is the difference between a product and a link collection: if
it then asks for its own password, nothing has been integrated.

`protected.inc` already writes `X-Auth-Subject`, `-Username`, `-Email` and
`-Groups` from the verified identity, and clears the request-side spellings so a
client cannot supply its own. Any answer that needs more than those headers
needs something the design does not have: per-application registration
([ADR-0011](0011-nginx-config-generation.md) keeps an application in exactly one
place, a table row), or code in a path that currently has none.

Both candidate mechanisms were tried against a real application — Jenkins
2.555.1, on its own host, behind the proxy — rather than argued
(`docs/07`, "One real application").

## Options

| Option | Pro | Con |
|---|---|---|
| **A — trusted headers** | No code, no registration, nothing minted; the headers already exist and most enterprise applications have a reverse-proxy authentication mode. Measured: log in once, click the icon, land signed in as `labuser`, no login form in the body | Its entire security is that only the PEP can reach the upstream. Measured: a forged `X-Auth-Username` sent straight to the published port impersonates any user, from any host on the LAN |
| B — the application runs its own OIDC against Keycloak | Nothing to forge; the application verifies a signature it fetched itself | A second session with its own lifetime that nothing of ours controls, so logout and the kill switch stop at our edge; needs OIDC back-channel logout, a *third* thing the application must support; and a Keycloak client per application, so an application exists in two places with nothing keeping them in step |
| C — a short-lived signed identity JWT from the PEP, plus JWKS | A bypass stops being impersonation: the upstream verifies rather than trusts | We mint, rotate and serve keys, and the application must support JWT header authentication. Jenkins does not, and neither does most of what an operator wants to put behind this |

## Decision

**A, and the isolation it depends on is promoted from a deployment default to a
requirement of the product.** The claim under A is not "headers are safe"; it is
"the upstream is unreachable except from the PEP", and that is now something
`INSTALL.md` states and a security review is expected to test, not a diagram in
`docs/02` that happens to be drawn that way.

Two things measured on the way settle the comparison rather than assume it:

- **A has no shared-browser identity confusion, and B does.** The header is read
  per request, so it wins over the application's own session: user B logging in
  on the browser that still carries user A's `JSESSIONID` was served as B, and
  that application cookie on its own — without our session — was redirected to
  login rather than honoured (`docs/07`). Under A the application's session
  cannot outlive our gate, because every request passes the gate. Under B it can,
  and that is the audit record naming the wrong person.
- **The application is not a second authorisation point, so it does not need to
  be a good one.** Jenkins is configured full-control-once-logged-in and denies
  anonymous: which user may reach it is our decision, taken before the request
  arrives.

B is not forbidden. An application that already speaks OIDC keeps working behind
the proxy and the proxy remains the authorisation point — but the product does
nothing for it, and whoever installs it owns the second session, back-channel
logout included.

**The reversal trigger, in the sense of [ADR-0009](0009-policy-engine-own-code.md):**
C gets built the first time either of these is true — an upstream that cannot be
isolated (a port that has to stay open, a host somebody else administers), or a
deployment where whoever runs the application is not whoever runs the proxy. At
that point the network assumption is no longer an assumption anyone can hold, and
a signature is the only thing that still holds.

## Consequences

- **`docs/06`'s "can upstreams be reached bypassing nginx?" loses its first
  answer as an option.** Network isolation was one of three; it is now required,
  and mTLS or C are hardening on top of it. The reason is measured and specific:
  under A a bypass is not information disclosure, it is impersonation — a forged
  `X-Auth-Username: labadmin` with no cookie authenticated as `labadmin` in
  `OpenBerat-Admins` (`docs/07`). `denyAnonymousReadAccess` does not close it;
  nothing on the application side does.
- **`INSTALL.md` carries the recipe and the isolation requirement in the same
  section**, because an operator cannot guess either, and the second one fails
  silently when it is skipped.
- **The application inherits the comma problem.** The group list travels
  comma-joined in one header and the application splits the same string the
  backend does ([ADR-0008](0008-group-identity-name.md), mitigation 1), so an
  application deriving its own roles from `X-Auth-Groups` inherits the escalation
  the `(cn=OpenBerat-*)` filter is the control for. The filter now protects two
  consumers, not one.
- **What arrives is not the AD group list.** Measured: oauth2-proxy's
  `keycloak-oidc` provider appends Keycloak realm and client roles as `role:`
  entries, so one AD group leaves as seven names (`docs/07`). Harmless to
  `ADMIN_GROUP`, which is matched by exact name and never equals `role:…` — and
  the operator's problem for an application that maps the header onto its own
  permissions.
- Nothing in this repository changed to make Jenkins work: no code, no
  migration, no new configuration file. The whole integration is one application
  row, one entitlement and a setting on the application. That is the property
  worth keeping — an application costs a row, not a release.
- Reversing to C later costs a key, an endpoint and a rollout: both mechanisms
  can run at once during it, because C adds a header rather than removing these.
