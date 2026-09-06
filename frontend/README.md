# frontend

The portal and admin UI. Served statically by nginx, taking its data from the
`backend`'s `/api/*` endpoints.

**Screens**

| Screen | Contents |
|---|---|
| Portal | The applications the user can reach per their AD `memberOf` entitlements — buttons with icons |
| No access | The page shown when an unauthorised application is requested |
| Admin · Applications | Defining applications (name, icon, target address) |
| Admin · Entitlements | AD group ↔ application mapping (allow / deny) |
| Admin · Audit | Viewing and filtering the audit log |

**Technology (ADR-0007):** HTML + CSS + Alpine.js — one vendored file, no build
step, no npm, no CDN. The portal (`index.html`, `portal.js`, `portal.css`) uses
**no Alpine**: it draws a list `/api/apps` already decided, and reactivity buys
nothing there. Alpine arrives with the first admin screen, and with it the
`unsafe-eval` question `docs/07` still has open.

**Two rules, checked by the `frontend` job in CI** because there is no build
step and no linter to catch a breach:

1. Anything from `/api/*` is written with `textContent`, never as markup. An
   admin types the application name and icon and nothing validates them; the
   portal is the one host every user opens and its session cookie is valid for
   every application on `.apps.<domain>` (ADR-0015).
2. No inline `<script>` and no inline event handlers, so a `default-src 'self'`
   CSP needs no `unsafe-inline`.

**Packaging (ADR-0020):** no Dockerfile and no container here — the nginx image
copies `frontend/src/` at build time.
