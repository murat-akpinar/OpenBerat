# frontend

The portal. Served statically by nginx, taking its data from the `backend`'s
`/api/*` endpoints. **There are no admin screens** — v1 administers through
`/api/admin/*` ([ADR-0024](../docs/adr/0024-no-admin-ui-in-v1.md),
`INSTALL.md` §6).

**Screens**

| Screen | Contents |
|---|---|
| Portal | The applications the user can reach per their AD `memberOf` entitlements — buttons with icons |
| No access | The page shown when an unauthorised application is requested |
| Unavailable | Served from `error_page` when the decision path does not answer |

**Design.** A *berat* is a sealed warrant granting a right, which is what this
product issues on every request. Gold leaf is the accent, and gold leaf is meant
to be seen against something dark — so the ground is near-black, lit from the
top corners the way a lamp lights a document, and the panels are the warrant
laid on top of it. **Dark only:** `backdrop-filter` glass over a light ground
reads as dirt, so a light theme would be a second design and not a second
palette.

The tokens live at the top of `portal.css` and are the only place a colour is
written. `--gold` is **decorative and never carries text**; where an accent has
to be read, `--gold-ink` does it. That split is the only reason the palette
holds WCAG AA, so it is a rule and not a preference — and the ratios are
computed against the *worst* ground, both glows overlapping at full strength
under a panel's scrim, not against the flat `--ground` (`docs/07`).

Two rules follow from the aurora and are easy to break by accident. A panel is a
**dark scrim first and a sheen second** (`--panel`, then `--sheen`): the scrim is
what keeps those ratios true wherever a panel drifts over the glow, so a panel
painted with a plain white alpha is a contrast bug. And long-form text never sits
on a lit patch — the last layer of the aurora is a scrim that pulls the middle of
the page back to the flat ground, which is why the glows stay at the top edge.

The gradient rule under the header is the signature: the same three pixels on all
three pages *and on the login card*, which is what makes them read as one product
rather than four files.

**Branding — one place per asset.**

| Asset | Lives at | Reaches the login screen by |
|---|---|---|
| Colours, glass, aurora | `src/portal.css` `:root` | copied by hand into `keycloak/themes/openberat/login/resources/css/openberat.css`, whose header says so. Two files, one palette: **if one moves, move the other** |
| Mark | `src/logo.svg` | `keycloak/Dockerfile` copies it to the theme's `img/logo.svg` |
| Favicon | `src/logo.svg` for the portal; `keycloak/themes/openberat/login/resources/img/favicon.ico` for the login page | Keycloak's template hardcodes `img/favicon.ico`, and a theme cannot change that without owning the template — so the `.ico` is the one derived file committed. Regenerate it from the mark, never draw it: `magick -background none frontend/src/logo.svg -define icon:auto-resize=16,32,48 keycloak/themes/openberat/login/resources/img/favicon.ico` |
| Typeface | not bundled — `system-ui` | one token each side: `body { font: ... }` here, `--pf-v5-global--FontFamily--*` in the theme |

To bundle a face instead of `system-ui`: put the `.woff2` in `src/font/`, add an
`@font-face` to `portal.css`, and copy it into the theme the way the Dockerfile
already copies the mark. The licence goes in `docs/07`'s licence table, which is
what CI's licence job and the release bundle read.

`portal.css` and `logo.svg` are served **without `auth_request`**
(`10-portal.conf`, `docs/02` "Anonymous endpoints"). The outage page comes from
`location /`'s `error_page`, so a stylesheet fetched through that location
would hit the same failing subrequest the page is reporting and come back as
the outage page itself — bare, in exactly the outage it exists to explain.

**Technology (ADR-0007, [ADR-0027](../docs/adr/0027-frontend-no-framework.md)):**
HTML + CSS, no build step, no npm, no CDN — and **no framework**. Every page is
plain DOM calls: `createElement`, `textContent`, `append`. There is nothing
vendored; `src/vendor/` held the Alpine CSP build until the one screen it was
kept for turned out not to want it.

The reason is rule 1 below. It is enforced by a CI grep and nothing else,
because ADR-0007 bought no build step to catch a breach — and that grep is exact
against `innerHTML` and its family, and blind to a templating attribute like
`x-html`. One rule guarded by two greps is how a rule ends up half-guarded.

**Two rules, checked by the `frontend` job in CI:**

1. Anything from `/api/*` is written with `textContent`, never as markup. An
   admin types the application name and icon through the API and nothing
   validates them for display; the
   portal is the one host every user opens and its session cookie is valid for
   every application on `.apps.<domain>` (ADR-0015).
2. No inline `<script>` and no inline event handlers, so a `default-src 'self'`
   CSP needs no `unsafe-inline`.

**Packaging (ADR-0020):** no Dockerfile and no container here — the nginx image
copies `frontend/src/` at build time.
