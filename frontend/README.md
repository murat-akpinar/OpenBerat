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
nothing there. Alpine is for the admin screens, and the vendored file is the
**CSP build** — `src/vendor/alpine.js`, provenance in the README beside it. The
standard build would cost `unsafe-eval` and was measured doing exactly that
(`docs/07`); write expressions accordingly, no arrow functions and no template
literals in attributes.

**Three rules, checked by the `frontend` job in CI** because there is no build
step and no linter to catch a breach:

1. Anything from `/api/*` is written with `textContent`, never as markup. An
   admin types the application name and icon and nothing validates them; the
   portal is the one host every user opens and its session cookie is valid for
   every application on `.apps.<domain>` (ADR-0015).
2. No inline `<script>` and no inline event handlers, so a `default-src 'self'`
   CSP needs no `unsafe-inline`.
3. Nothing under `src/vendor/` compiles expressions — no `eval(`, no
   `new Function`. Rule 1 does not apply there (Alpine writes markup for
   `x-html` by design); this one replaces it, because upgrading to the standard
   Alpine build would look like nothing but a larger file and would cost
   `unsafe-eval`.

**Packaging (ADR-0020):** no Dockerfile and no container here — the nginx image
copies `frontend/src/` at build time.
