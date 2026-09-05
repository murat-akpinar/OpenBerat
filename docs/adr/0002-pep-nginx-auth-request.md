# 0002 — PEP: nginx + `auth_request` (we are not writing our own proxy)

- **Status:** Accepted
- **Date:** 2026-09-05
- **Note:** The first version chose Caddy `forward_auth`; it was changed to nginx (see below).

## Context

Do we write the layer that intercepts traffic and enforces the authorisation
decision (the PEP) from scratch, or do we use an existing reverse proxy's auth
subrequest mechanism? And if the latter, which proxy?

## Options

**Our own proxy or an existing one:**

| Option | Pro | Con |
|---|---|---|
| Existing proxy + auth subrequest | TLS, HTTP/2, WebSocket, streaming and connection pooling for free | You live within the proxy's constraints |
| Our own proxy | Full control | TLS/WebSocket/streaming edge cases become your problem |

**Which proxy:**

| | nginx `auth_request` | Caddy `forward_auth` |
|---|---|---|
| oauth2-proxy integration | Officially documented example | You work it out yourself |
| Team knowledge / operations | Present | Absent |
| Configuration brevity | Long | Short |
| Automatic HTTPS | No | Yes (worthless with an internal CA) |
| Chaining multiple auth steps | **One `auth_request` per location** | Chains naturally |

## Decision

**nginx + `auth_request`.**

The hard part of proxying (TLS termination, HTTP/2, WebSocket upgrade,
streaming, timeout management) is a solved problem; rewriting it buys nothing.

nginx was chosen because oauth2-proxy's official integration example (ADR-0003)
is nginx `auth_request`; because the team and operations know nginx; and because
in a security product, being boring and auditable is a feature. Caddy's
advantages (short config, automatic HTTPS) are not decisive in this environment.

## Consequences

### The single-`auth_request` constraint changed the architecture

nginx accepts **only one** `auth_request` in a location context; a second one
does not chain, it overrides the first. The chain "ask oauth2-proxy first, then
the backend" therefore cannot be built in nginx.

The chain moved into the backend:

```
nginx: auth_request /decide  ──► backend
                                   1) forward the cookie to oauth2-proxy /oauth2/auth → identity
                                   2) if 401, return 401
                                   3) identity + memberOf → decision → 200/403
nginx: error_page 401 → oauth2-proxy /oauth2/start (redirect to login)
nginx: error_page 403 → portal "no access" page
```

Side effects:
- **Plus:** a single authorisation entry point; the chain lives in our code and is testable
- **Plus:** the nginx configuration got simpler
- **Minus:** one more internal HTTP call per decision (the cache was mandatory anyway)
- **Minus:** the backend now depends on oauth2-proxy — if it goes down, nobody can authenticate

### Other

- **Constraint:** every protected application must live under a common parent
  domain (`*.apps.example.local`), otherwise the session cookie cannot be
  shared. The DNS and wildcard certificate decisions depend on this. Carried as
  the most critical open question until
  [ADR-0015](0015-single-parent-domain.md) settled it: the parent domain is an
  installation prerequisite and the portal lives inside it.
- The backend never sees the traffic; it sees only request metadata (host, path,
  identity). Body inspection (WAF-style) is not possible.
- The proxy is replaceable: Caddy `forward_auth` and Traefik `forwardAuth` speak
  the same contract, and the backend code would not change.
