# keycloak

A stock image is used; there is no Dockerfile.

| File | Contents |
|---|---|
| `realm/openberat-realm.json` | Realm export — LDAP federation, group mapper, clients. So the lab is reproducible. |

**Not done by hand, written to the file.** If a setting is changed through the
Keycloak UI, the realm is exported again and committed here; otherwise the lab
cannot be rebuilt.

What the settings mean: `docs/03-keycloak-ad.md`
