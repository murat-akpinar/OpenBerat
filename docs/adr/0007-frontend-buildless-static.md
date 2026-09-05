# 0007 — Frontend: a static UI with no build step

- **Status:** Accepted
- **Date:** 2026-09-05

## Context

ADR-0005 made the frontend a separate component but deliberately left its
technology open.

The screens: the portal (a list of icon buttons), the "no access" page, and
admin (application CRUD, AD group ↔ application mapping, an audit log table).
Five or six screens in total, with no complex client-side state management.

The team's background is mostly Rust and infrastructure; there is almost no JS
in the repositories.

## Options

| | Buildless static (HTML + CSS + Alpine.js) | SPA (Vite + React/Svelte) |
|---|---|---|
| Build chain | **None** — nginx serves the files directly | Node + npm + Vite |
| Dependency tree | 1 vendored file (~15 KB) | Hundreds of packages |
| Team familiarity | High | Low |
| Admin CRUD ergonomics | Adequate | Better |
| Supply chain attack surface | Almost none | Wide |

## Decision

**A static UI with no build step:** HTML + CSS + [Alpine.js](https://alpinejs.dev)
(a single file vendored into the repository). nginx serves the contents of
`frontend/` directly.

Two reasons were decisive:

1. **The scale does not call for it.** An SPA framework is unnecessary for five
   or six screens that list JSON coming from the server. The loss of admin CRUD
   ergonomics is real but small.
2. **This is a security product.** A system that performs network access control
   arriving with hundreds of npm packages contradicts its own claim and makes it
   harder to audit. No CDN is used; Alpine.js is copied into the repository and
   its version is bumped by hand.

This decision is **reversible**: if the admin UI genuinely gets complex, a build
chain is opened inside `frontend/`, and neither the `/api` contract nor the
other components are affected.

## Consequences

- ~~`frontend/Dockerfile` performs no build, it only packages the assets.~~
  **Revised by [ADR-0020](0020-frontend-in-nginx-image.md):** there is no
  `frontend/Dockerfile` at all — the nginx image copies `frontend/src/` at
  build. No Node step in CI either way.
- Alpine.js version upgrades are manual and visible in the commit — a deliberate
  choice.
- No sources are pulled from an external CDN. Whether the CSP can avoid
  `unsafe-eval` depends on which Alpine.js build is vendored — the standard one
  evaluates expressions with `new Function()` (`docs/07`, "Unverified").
- No authorisation decision is made in the UI; hiding admin screens is a
  convenience, and `/api/admin/*` is separately authorised in the backend.
