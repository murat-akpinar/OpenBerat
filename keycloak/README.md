# keycloak

A stock image is used; there is no Dockerfile.

| File | Contents |
|---|---|
| `realm/openberat-realm.json` | Realm export — LDAP federation, group mapper, clients. So the lab is reproducible. |

**Not done by hand, written to the file.** If a setting is changed through the
Keycloak UI, the realm is exported again and committed here; otherwise the lab
cannot be rebuilt.

**No real secrets in the export.** The repository is public: a re-export is
scrubbed before committing — the OIDC client secret is a placeholder and the
LDAP bind password is not in the file. Real values arrive through `.env` at
deploy; whether the import can resolve them from the environment or needs a
post-import step is a Phase 1 item (`docs/07`, TODO).

What the settings mean: `docs/03-keycloak-ad.md`
