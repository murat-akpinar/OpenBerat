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
| Unavailable | Served from `error_page` when the decision path does not answer |

**Design.** A *berat* is a sealed warrant granting a right, which is what this
product issues on every request — so the ground is paper, the text is ink and
the accent is gold leaf, rather than the cool grays every other identity
product already wears. The tokens live at the top of `portal.css` and are the
only place a colour is written. `--gold` is **decorative and never carries
text**; where an accent has to be read, `--gold-ink` does it. That split is the
only reason the palette holds WCAG AA, so it is a rule and not a preference.

The mark is one file, `logo.svg`, used as the header image and as the favicon,
in a single colour so it survives both grounds without a media query inside it.
The wordmark is CSS — `letter-spacing`, not typed spaces, so a screen reader
still says "OpenBerat". The gradient rule under the header is the signature: the
same three pixels on all three pages, which is what makes them read as one
product rather than three files.

`portal.css` and `logo.svg` are served **without `auth_request`**
(`10-portal.conf`, `docs/02` "Anonymous endpoints"). The outage page comes from
`location /`'s `error_page`, so a stylesheet fetched through that location
would hit the same failing subrequest the page is reporting and come back as
the outage page itself — bare, in exactly the outage it exists to explain.

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
