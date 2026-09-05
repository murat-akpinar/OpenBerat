# 0015 — One parent domain, portal included

- **Status:** Accepted
- **Date:** 2026-09-05

## Context

ADR-0002 recorded, as an unresolved constraint, that every protected application
must sit under a common parent domain or the oauth2-proxy session cookie cannot
be shared. It has been the most critical unanswered question since; Phase 1's
`docker-compose.yml` cannot be written without an answer, and the portal's own
address is entangled with it.

Two separate things were being asked as one:

- **Whether** the deployment requires a common parent domain (a design decision).
- **Which** domain the portal lives under (a security boundary decision).

The first is ours to make. The second determines how wide the session cookie's
`Domain` attribute is — that is, which set of hosts can read a cookie that
authenticates every request in the system.

## Options

For the portal's placement, given applications at `*.apps.<domain>`:

| Option | Cookie `Domain` | Hosts that can read the session cookie |
|---|---|---|
| **`portal.apps.<domain>`** | `.apps.<domain>` | Only the protected applications and the portal |
| `portal.<domain>` | `.<domain>` | **Every host in the organisation's domain**, including anything unrelated |
| A separate registrable domain | not shareable | None — the flow breaks |

## Decision

**A common parent domain is a v1 installation prerequisite, and the portal lives
under it: `portal.apps.<domain>`.**

The system does not work around a missing parent domain. Supporting applications
on unrelated domains means a separate redirect flow and a separate cookie per
domain — a materially different authentication design, for an environment we
have no evidence exists. This goes in the installation documentation as a
requirement, next to DNS and the wildcard certificate.

The portal goes *inside* `apps` rather than beside it because that is the
narrower boundary. With `portal.<domain>` the cookie has to be scoped to
`.<domain>` and is then sent to every host in the organisation's domain,
including hosts this product has never heard of. Scoping to `.apps.<domain>`
limits it to hosts that are, by construction, behind the PEP.

## Consequences

- Installation prerequisites, all operator-side: a wildcard DNS record for
  `*.apps.<domain>` and a wildcard certificate covering it. `docs/06` still
  carries the certificate question (internal CA or Let's Encrypt), and ADR-0011
  already notes an admin can add an application but cannot create name
  resolution.
- Cookie `Domain` is `.apps.<domain>`, `Secure`, `HttpOnly`, `SameSite=Lax`.
- **`__Host-` cannot be used**, and this closes that question rather than
  answering it favourably: the prefix requires a host-only cookie, which by
  definition cannot be shared across subdomains. Sharing the cookie is the whole
  mechanism, so the prefix is unavailable in any variant of this design.
- **`SameSite` therefore does not protect the admin API**: the portal and the
  protected applications are same-site, so a request from a compromised
  protected application to `/api/admin/*` is not blocked by the browser. The
  `Origin` check on state-changing admin endpoints (`docs/02`, "Management
  plane") is not defence in depth — it is the only defence, and it is
  mandatory.
- A compromised protected application must **not** see the session cookie of a
  user who visits it. An earlier version of this bullet called that exposure
  inherent, and it is not: the cookie reaches an upstream only if nginx forwards
  the `Cookie` header verbatim, so nginx strips the `_oauth2_proxy` cookie
  before proxying (`docs/05`, "Header spoof protection") — identity travels in
  the `X-Auth-*` headers. What *is* inherent to the shared cookie: a script
  injected into one application runs same-site with all the others, and the
  browser attaches the cookie to the requests it makes. That is why the `Origin`
  check above and the upstream-bypass question in `docs/06` (option (c), a
  short-lived signed identity JWT) still matter.
- The wildcard certificate becomes a single point of expiry: when it lapses,
  every application goes down at once (`docs/06`).
