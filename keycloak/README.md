# keycloak

| File | Contents |
|---|---|
| `realm/openberat-realm.json` | Realm export — LDAP federation, group mapper, clients. So the lab is reproducible. |
| `themes/openberat/login/` | Our login theme. The one screen every user meets before anything else. |
| `Dockerfile` | Bakes the theme into the image. The realm export stays a mount. |

**The realm is mounted, the theme is baked.** They look alike and are not: the
export is *import data*, read once at first boot into Keycloak's own database,
while a theme is read at runtime on every login. Configuration a running system
serves is baked into the image so it cannot drift, so the theme is copied in and
`keycloak/` has a `Dockerfile` — the image is no longer stock.

**The theme overrides no template.** It sets `parent=keycloak.v2` and ships a
palette, a header message and nothing else. Copying the `.ftl` files in would
mean owning FreeMarker that Keycloak rewrites between releases, and a template
that stops matching its theme takes down the one page nobody can route around.
Two traps, both measured (`docs/07`): a child theme's `styles=` **replaces** the
inherited list, so the parent's `css/styles.css` has to be named again or the
whole PatternFly layer vanishes; and PatternFly's per-component variables cannot
be repainted from `:root`, because a custom property set on the element beats an
inherited one whatever the specificity.

**The mark is not kept here.** `frontend/src/logo.svg` is copied into the theme
by the `Dockerfile`, which is why the build context is the repository root. One
file, one product, one place to change it.

**The favicon is the one exception, and only because the template hardcodes it.**
`keycloak.v2` writes `<link rel="icon" href="${url.resourcesPath}/img/favicon.ico">`,
so without a file at that path the browser tab shows *Keycloak's* mark on our
login page. `themes/openberat/login/resources/img/favicon.ico` is therefore
committed — generated from the mark, never drawn:
`magick -background none frontend/src/logo.svg -define icon:auto-resize=16,32,48 keycloak/themes/openberat/login/resources/img/favicon.ico`.
Regenerate it whenever `logo.svg` changes; nothing checks that it matches.

**Brute-force protection is on in the export, because Keycloak's default is
off.** `bruteForceProtected` is absent from a stock realm, which means no
lockout at all — and the login form is reachable from the browser-facing proxy,
so without it a password is guessable at whatever rate the network allows. The
export sets it with `failureFactor: 5` and `permanentLockout: false`: the fifth
wrong password locks the account for 60 s, and from then on every failure locks
it again: for 60 s through the ninth, 120 s at the tenth and eleventh (measured,
`docs/07`), bounded by `maxFailureWaitSeconds`' 900 s, which the run did not
reach. Temporary, because a *permanent* one turns the same guessing campaign
into a way to lock a real user out of everything the portal fronts. It is the
per-user layer; the per-address one is `limit_req` on `login-actions` in
`nginx/conf.d/10-portal.conf.template`, and neither sees what the other sees —
one address spraying many accounts, or many addresses guessing one.

**Five and not ten, because AD counts too.** While the lock holds, **no bind
reaches AD** — not a wrong password and not the right one — so the burst a
guesser can land on the domain before Keycloak stops it is `failureFactor`
binds. A domain whose own lockout threshold is at or below that number locks
the account in AD, which is not this product's lockout: it locks the user out of
everything else that authenticates against the domain as well. The lock slows what reaches AD and does not cap it —
every failure *between* locks is a bind, and 11 of them reached AD in the
7½ minutes of the run — so a domain that locks accounts still does, only later.
A locked account answers `Invalid username or password` to the right password
too, so the page does not tell a guesser the lock is there.

**No password policy in the realm, on purpose.** Every account that signs in is
AD's, through a `READ_ONLY` federation, and a realm `passwordPolicy` is not
consulted when it does: measured, a policy of 64 characters with digits,
capitals, symbols and history let a 24-character password straight through
(`docs/07`). Length, complexity and history for those accounts are the domain's
password settings; a policy in the export would read as a control that governs
nobody. The one account the realm owns is the backend's service account, which
has a client secret and no password. An installation that adds local accounts
to the realm adds the policy with them.

**Not done by hand, written to the file.** If a setting is changed through the
Keycloak UI, the realm is exported again and committed here; otherwise the lab
cannot be rebuilt.

**No real secrets in the export.** The repository is public: a re-export is
scrubbed before committing — the OIDC client secret is a `${OPENBERAT_CLIENT_SECRET}`
placeholder, the backend service account's an `${OPENBERAT_BACKEND_SECRET}` one
and the LDAP bind password an `${AD_BIND_PASSWORD}` one. Real values arrive
through `.env` at deploy and the import resolves them from Keycloak's own
environment; **the syntax is plain `${VAR}`** — `$(env:VAR)` and `${env.VAR}`
are stored verbatim, which silently produces a client whose secret is the
literal placeholder text (measured, `docs/07`).

**Two clients, and the second one has no browser flow.** `openberat-proxy` is
what oauth2-proxy logs users in with; `openberat-backend` is a service account
whose only right is `manage-users`, which is the narrowest role Keycloak offers
for the kill switch's `logout-all` (ADR-0019). Keeping them apart is the point:
one secret sits in oauth2-proxy, and it is not the one that can manage users.
The role arrives through the `users` entry in the export — a service account is
a user, and a client on its own carries no role mapping.

**The file name must match the realm name.** `openberat-realm.json` holds realm
`openberat`; any other name and Keycloak refuses to start at all — the import
error is fatal, not skipped.

**Do not add a `clientScopes` array** unless you mean to replace Keycloak's
built-in set. Supplying one leaves the realm with only the scopes it names, so
`profile` and `email` cease to exist and every login fails with
`invalid_scope`. The `groups` claim therefore comes from a protocol mapper on
the client itself, which also makes it unconditional instead of something the
caller has to request (`docs/07`).

**Declare every LDAP mapper, not just the interesting one.** Adding the LDAP
provider through the admin console silently creates seven attribute mappers;
declaring the provider here with a `subComponents` block creates *only* what
that block names. Leave `username` out and every user arrives from LDAP with no
username at all — the import fails with `User returned from LDAP has null
username!` and the realm ends up with no federated users and no warning
(`docs/07`).

**`cachePolicy` is not a tuning knob.** It is `NO_CACHE` because ADR-0006 rests
on it: measured, at `DEFAULT` a group removed in AD survives a brand-new login
(`docs/07`).

What the settings mean: `docs/03-keycloak-ad.md`
