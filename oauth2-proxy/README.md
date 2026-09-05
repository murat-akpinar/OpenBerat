# oauth2-proxy

A stock image is used; there is no Dockerfile. All authentication happens here
(ADR-0003).

| File | Contents |
|---|---|
| `oauth2-proxy.cfg` | Keycloak OIDC client, Redis session store, cookie settings |

**The three critical settings** (`docs/04-provisioning.md`) — all three default
to the wrong value for this project:
- `set_xauthrequest = true` — off by default, and without it no identity or group
  header reaches the backend at all
- `cookie_refresh = 5m` — without it, group information stays stale for up to 7 days
- `session_store_type = "redis"` — a session inside a cookie cannot be revoked by
  the kill switch, and it also carries the `sub → session` index (ADR-0019)
