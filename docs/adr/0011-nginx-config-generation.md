# 0011 — nginx configuration for protected applications is generated from the DB

- **Status:** Accepted
- **Date:** 2026-09-05

## Context

F-06 requires an admin to be able to define applications (name, target address,
icon), and the `application` table has an `upstream_url`. But the nginx
configuration for protected applications (`20-apps.conf`) is written by hand and
baked into the image (`CONTRIBUTING.md`) — meaning **no component reads
`upstream_url`.**
The admin screen can only map entitlements to applications that were already
added by hand, and adding a new application requires rebuilding the image.

This also blocks the portal demo: Phase 4 does not work until the data is filled
in by hand with SQL.

## Options

| Option | Pro | Con |
|---|---|---|
| A — Hand-written config, admin only maps entitlements | Zero extra work | F-06 shrinks; an image build per application, unsustainable by the second customer |
| **B — Config generation + `nginx -t` + reload** | F-06 is genuinely met; nginx stays on static config | The generated config is a security boundary; validation is mandatory |
| C — One wildcard block, `proxy_pass` resolved dynamically from the DB | No config generation | A direct SSRF door; needs an extra component (njs/lua) on nginx OSS |

## Decision

**B.** The backend generates an nginx `server`/`location` block per application
from the `application` table, validates it with `nginx -t`, and reloads if it
passes. If validation fails, **the current config stays in effect** and the
error is returned to the admin.

C was rejected: choosing the upstream address from the DB at request time turns
a single bad record in the admin UI into an internal-network redirect hole.

## Consequences

- **The "configuration is baked into the image" rule is relaxed for this one
  file** (`CONTRIBUTING.md`). nginx's core configuration (`00-auth.conf`,
  `10-portal.conf`) is still in the image; only the generated application blocks
  live in a shared volume.
- The shared `include` that strips incoming `X-Auth-*` headers is **part of the
  template** for every generated location, not optional. Forget it in the
  template and the security claim falls for every generated application — so the
  template gets a test.
- `upstream_url` is a trust boundary input: scheme (http/https), host and port
  are validated; loopback and link-local addresses (`127.0.0.0/8`,
  `169.254.0.0/16`) and infrastructure services (Postgres, Redis, Keycloak
  admin) are rejected.
- `external_hostname` is validated the same way: it must not collide with the
  reserved hosts — `portal` (ADR-0015) and `auth` (the Keycloak host,
  `docs/02` "Deployment") — or a generated application block would shadow the
  portal or the login flow.
- DNS records and the wildcard certificate are **still the operator's job**. An
  admin can add an application but cannot create name resolution. This goes in
  the installation documentation.
- Open connections survive a reload (nginx behaviour), but frequent reloads pile
  up workers; reloads are debounced.
- This is Phase 4's subject. Until Phase 3, config is written by hand.
- **An application stays one row.**
  [ADR-0021](0021-application-identity-trusted-headers.md) chose the identity
  mechanism that needs no second registration precisely to keep this true: the
  alternative gives every application a Keycloak client as well, and two records
  with nothing keeping them in step.
