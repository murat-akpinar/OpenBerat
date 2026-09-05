# oauth2-proxy

A stock image is used; there is no Dockerfile. All authentication happens here
(ADR-0003).

| File | Contents |
|---|---|
| `oauth2-proxy.cfg` | Keycloak OIDC client, Redis session store, cookie settings |

**The two critical settings** (`docs/04-provisioning.md`):
- `cookie_refresh` — without it, group information stays stale for up to 7 days
- `session_store_type = "redis"` — a session inside a cookie cannot be revoked by the kill switch
