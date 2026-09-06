# keycloak

A stock image is used; there is no Dockerfile.

| File | Contents |
|---|---|
| `realm/openberat-realm.json` | Realm export — LDAP federation, group mapper, clients. So the lab is reproducible. |

**Not done by hand, written to the file.** If a setting is changed through the
Keycloak UI, the realm is exported again and committed here; otherwise the lab
cannot be rebuilt.

**No real secrets in the export.** The repository is public: a re-export is
scrubbed before committing — the OIDC client secret is a `${OPENBERAT_CLIENT_SECRET}`
placeholder and the LDAP bind password an `${AD_BIND_PASSWORD}` one. Real values arrive
through `.env` at deploy and the import resolves them from Keycloak's own
environment; **the syntax is plain `${VAR}`** — `$(env:VAR)` and `${env.VAR}`
are stored verbatim, which silently produces a client whose secret is the
literal placeholder text (measured, `docs/07`).

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
