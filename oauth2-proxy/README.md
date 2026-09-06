# oauth2-proxy

A stock image is used; there is no Dockerfile. All authentication happens here
(ADR-0003).

| File | Contents |
|---|---|
| `oauth2-proxy.cfg` | Keycloak OIDC client, Redis session store, cookie settings |

**The four critical settings** (`docs/04-provisioning.md`) — every one of them
defaults to the wrong value for this project:
- `set_xauthrequest = true` — off by default, and without it no identity or group
  header reaches the backend at all
- `cookie_refresh = 5m` — without it, group information stays stale for up to 7 days
- `session_store_type = "redis"` — a session inside a cookie cannot be revoked by
  the kill switch, and it also carries the `sub → session` index (ADR-0019)
- `backend_logout_url` — unset by default, and then `/oauth2/sign_out` clears the
  cookie while leaving the **IdP** session open: the next login is granted with no
  password prompt. Measured, both ways (`docs/07`). It is called with the
  session's own `id_token`, which is why the backend asks oauth2-proxy to sign out
  *before* deleting the session key rather than after (`docs/02`, "Logout")
