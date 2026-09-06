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
step, no npm, no CDN. Nothing here yet but a placeholder `index.html`; Alpine
arrives with the first screen that needs it (TODO.md Phase 4).

**Packaging (ADR-0020):** no Dockerfile and no container here — the nginx image
copies `frontend/src/` at build time.
