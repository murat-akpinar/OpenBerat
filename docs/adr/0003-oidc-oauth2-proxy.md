# 0003 — The OIDC login flow is delegated to oauth2-proxy

- **Status:** Accepted
- **Date:** 2026-09-05

## Context

After the forward auth decision (ADR-0002) two jobs remain: **authentication**
(the OIDC dance, the session cookie) and **authorisation** (may this user enter
this application). Do we write the first one ourselves?

The OIDC login flow is security-critical and subtle: `state`, `nonce`, PKCE,
JWKS key rotation, cookie security (`Secure`/`HttpOnly`/`SameSite`), token
refresh, open redirect protection. Roughly 300–400 lines, every one of which can
be got wrong.

## Options

| Option | Pro | Con |
|---|---|---|
| Delegate to oauth2-proxy | Zero OIDC code; mature code that has been under attack for years | One more component; the kill switch needs a Redis session store |
| Write it ourselves | A single binary, full control of session management | Maintaining security-critical code becomes ours |

## Decision

**Delegate to oauth2-proxy.** The chain:

```
nginx ──auth_request──► backend /decide
                          ├─► oauth2-proxy /oauth2/auth   (identity: OIDC + session)
                          └─► Postgres                    (authorisation: entitlement)
      ──────────────────► upstream application
```

oauth2-proxy becomes Keycloak's OIDC client and returns the verified identity in
the `X-Auth-Request-User` / `-Email` / `-Groups` headers.

Because nginx accepts only one `auth_request` per location (ADR-0002), the chain
is built inside the backend: the backend forwards the request's cookie to
oauth2-proxy, takes the identity, and then makes the authorisation decision.

This is the same logic as ADR-0002 continued: we do not rewrite a solved
problem. The code we write has shrunk to the only thing specific to this
project — **the authorisation decision**.

## Consequences

- Our security-critical code surface shrank dramatically; in exchange,
  oauth2-proxy's configuration is now a security boundary — particularly the
  cookie settings and the `--email-domain` / `--allowed-group` defaults, which
  must be reviewed.
- The **kill switch** (F-09) now acts in two places: terminate the Keycloak
  session **and** delete the oauth2-proxy session. This is why oauth2-proxy's
  session store must be Redis (a session inside a cookie cannot be revoked
  server-side). Redis is keyed by ticket rather than by user, so the second half
  needs an index the backend keeps —
  [ADR-0019](0019-kill-switch-session-index.md).
- **Stale group risk:** the `X-Auth-Request-Groups` oauth2-proxy returns comes
  from the ID token at login time and is not refreshed for days unless
  `--cookie-refresh` is set. That would undermine the product's core promise.
  Detail and the two ways out: `docs/04-provisioning.md`, "The stale group
  problem". **This is the most important consequence of this ADR.**
- The backend now depends on oauth2-proxy: if oauth2-proxy goes down nobody can
  authenticate and everything closes (fail-closed).
- The `groups` claim must be present in the token (see `docs/03-keycloak-ad.md`),
  otherwise our service cannot make a decision.
- Since we own no OIDC code, if we ever want to leave oauth2-proxy it gets
  written then; it is not today's need.
