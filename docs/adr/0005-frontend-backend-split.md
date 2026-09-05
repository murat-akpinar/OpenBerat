# 0005 — Separate frontend, one directory per container

- **Status:** Accepted
- **Date:** 2026-09-05

## Context

The product's real face is the **portal**: the user signs in with their AD
account, sees buttons for the applications their AD `memberOf` entitlements
allow, and clicks. An admin UI (defining applications, mapping entitlements,
viewing the audit record) will be added to it.

Should this UI be rendered server-side in the same process as the backend, or
served from nginx as a separate static application?

## Options

| Option | Pro | Con |
|---|---|---|
| Server-side templates (inside Rust) | One component, no build step, one language | Every HTML change means a Rust compile; friction grows as UI work grows |
| Separate frontend served by nginx | The UI is developed independently; nginx is already there and serving static files is its actual job | One more build chain; the `/api` contract has to be written down |

## Decision

**A separate `frontend/`**, served statically by nginx, taking its data from the
`backend`'s `/api/*` endpoints.

The deciding factor is that the UI is not a by-product in this project but the
**main product**: the portal screen is what "putting a UI on Keycloak" actually
means. Since UI work dominates, making an HTML change wait for a Rust build is
the wrong trade. nginx is already mandatory as the PEP (ADR-0002), and serving
static files costs it nothing extra.

**Directory layout: one directory per container, with its Dockerfile beside it.**

```
backend/       Rust API + authorisation decision  → Dockerfile
frontend/      portal + admin UI                  → Dockerfile
nginx/         PEP + static serving               → Dockerfile
keycloak/      realm export                       (stock image)
oauth2-proxy/  authentication config              (stock image)
docker-compose.yml
```

The frontend's **technology is not the subject of this ADR** — it was decided
separately in [ADR-0007](0007-frontend-buildless-static.md).

## Consequences

- The `/api` contract must be **written down** between the two components; it
  lives in `docs/02`.
- The frontend makes no authorisation decisions. The portal only *displays*; the
  access decision is made on the nginx → backend `/decide` path on every
  request. Going directly to an address not shown in the portal still returns 403.
- The frontend's `/api/apps` call also requires an identity; there are no
  anonymously reachable endpoints.
- Configuration is **baked into** the images, no bind mounts — so a running
  system cannot drift.
- ~~One more build chain (Node) enters CI.~~ **Invalidated by ADR-0007:** a
  buildless static UI was chosen, so there is no Node step in CI.
