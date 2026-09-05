# 07 — Sources and Verified Findings

The sources the design decisions rest on. No technical claim written from memory
appears in this file — every line has a link.

## nginx `auth_request`

<https://nginx.org/en/docs/http/ngx_http_auth_request_module.html>

```
Syntax:  auth_request uri | off;
Default: auth_request off;
Context: http, server, location
```

- If the subrequest returns **2xx** access is allowed, **401/403** denies it, and
  any other code is treated as an **error**.
- The directive is **single-valued** (`uri | off`), not a list. A second one in
  the same context does not chain; it overrides the first. → **The chain is
  built inside the backend** (ADR-0002).
- `auth_request_set $var $upstream_http_...` lifts the subrequest's **response
  headers** into an nginx variable.

## oauth2-proxy

<https://oauth2-proxy.github.io/oauth2-proxy/configuration/overview> ·
<https://oauth2-proxy.github.io/oauth2-proxy/configuration/integrations/nginx/>

### Defaults — three of them are wrong for this project

| Setting | Default | Our value | Why |
|---|---|---|---|
| `set_xauthrequest` | `false` | `true` | Without it, `X-Auth-Request-User/-Groups/-Email` never arrive. The docs describe it as "useful in Nginx auth_request mode". |
| `cookie_refresh` | off (`0`) | `5m` | While off, the session lives as long as `cookie_expire`. **Keycloak is supported.** |
| `cookie_expire` | `168h0m0s` | per policy | 7 days |
| `session_store_type` | `cookie` | `redis` | Kill switch + large sessions |

### The official nginx integration pattern

```nginx
location = /oauth2/auth {
    proxy_pass http://127.0.0.1:4180;
    proxy_set_header Host             $host;
    proxy_set_header X-Real-IP        $remote_addr;
    proxy_set_header X-Forwarded-Uri  $request_uri;
    proxy_set_header Content-Length   "";
    proxy_pass_request_body off;
}

location / {
    auth_request /oauth2/auth;
    error_page 401 = @oauth2_signin;
    auth_request_set $user  $upstream_http_x_auth_request_user;
    auth_request_set $email $upstream_http_x_auth_request_email;
    proxy_set_header X-User  $user;
    proxy_set_header X-Email $email;
    proxy_pass http://backend/;
}

location @oauth2_signin {
    return 302 /oauth2/sign_in?rd=$scheme://$host$request_uri;
}
```

What this teaches:
- `proxy_pass_request_body off` + `Content-Length ""` — no body is sent to the subrequest.
- `error_page 401 = @named` — **the `=` is mandatory.** Without it the response
  code stays 401 and browsers do not follow a `Location` header on a 4xx.
- The documentation shows **no way to chain a second authorisation check.**

### The cookie size trap

- Some providers' cookies exceed the 4 KB limit; oauth2-proxy splits the cookie
  into chunks.
- nginx normally copies **only the first `Set-Cookie`** header — the official
  example handles this with `if` blocks and `$upstream_cookie_*`.
- The official recommendation: **use the Redis session store if large
  sessions/OIDC tokens are expected.** → AD users in many groups land exactly in
  that case here.

## Keycloak — LDAP group mapper

<https://www.keycloak.org/docs/latest/server_admin/index.html>

| Strategy | What it does |
|---|---|
| `LOAD_GROUPS_BY_MEMBER_ATTRIBUTE` | Scans groups looking for the user in the `member` attribute. Generic LDAP. |
| **`GET_GROUPS_FROM_USER_MEMBEROF_ATTRIBUTE`** | Reads the user's `memberOf` attribute directly. **Recommended for AD**, better performance. |
| `LOAD_GROUPS_BY_MEMBER_ATTRIBUTE_RECURSIVELY` | Resolves the nested group hierarchy. |

- Keycloak **queries LDAP** when listing group membership — it gets the current
  list. AD is consulted live at login time. → Keycloak is not the source of
  staleness (ADR-0006).
- `memberOf` gives only **direct** membership; with nested groups
  `..._RECURSIVELY` is required. To be tested in Phase 1.

## Unverified, to be tested

These claims have not been confirmed against a source; they will be tried in the
Phase 1 lab:

- [ ] Can an nginx subrequest (the `auth_request` target) itself trigger an
      `auth_request`? If it can, the chain could be built in nginx and the
      internal HTTP call in the backend would disappear. The architecture was not
      built on this because it is uncertain.
- [ ] Can Keycloak carry an AD group's `objectSid` into a token claim? If it can,
      ADR-0008 (name vs SID) becomes easy to resolve.
- [ ] The real deprovisioning delay as measured with `cookie_refresh`.
- [ ] Does oauth2-proxy return `Set-Cookie` when performing `cookie_refresh` on
      `/oauth2/auth`? In the official pattern the subrequest's upstream is
      oauth2-proxy; in ours it is the backend. **If it is not relayed the cookie
      is never refreshed and ADR-0006 silently collapses.**
- [ ] Does the `auth_request` subrequest inherit the main request's headers? If
      it does, a client-supplied `X-Original-URI` / `X-Forwarded-Host` could leak
      into the PDP (this is why `docs/02` fixes `X-App-Slug` in the nginx config).
- [ ] Does nginx OSS have active upstream health checks, or only passive ones
      (`max_fails`/`fail_timeout`)? The HA item in Phase 6 depends on this.
- [ ] The effect of the LDAP provider's **Cache Policy** on group freshness. Does
      the "Keycloak reads live" claim still hold at any value other than
      `NO_CACHE`? **ADR-0006 rests on this claim**, and the only source for it is
      the general Keycloak documentation.
- [ ] **Can the oauth2-proxy Redis session key be derived from the session
      cookie the backend already holds?** The cookie is understood to carry a
      ticket the store is keyed by, but that is oauth2-proxy internals and has
      not been read out of its source or documentation.
      **[ADR-0019](adr/0019-kill-switch-session-index.md) rests on this claim**,
      and through it the 5 s kill-switch target in ADR-0016. If it is false the
      fallback is option C of that ADR and N-03 is revised. And does the key
      survive `cookie_refresh`, or does a refresh mint a new ticket? A rotated
      key is caught by the next cache miss (new cookie → new hash → miss →
      index add), but the kill-switch test must be run **after** at least one
      refresh to prove the index still finds the live session.
- [ ] Which claim does oauth2-proxy put in `X-Auth-Request-User` for a Keycloak
      OIDC provider — `sub`, `preferred_username`, the email? `docs/05` assumes
      sAMAccountName, while `X-Auth-Subject` and the ADR-0019 index need the
      immutable `sub`; if no header carries the `sub`, the `docs/05` header
      contract is revised.
- [ ] Does the vendored Alpine.js run under a `default-src 'self'` CSP
      **without** `unsafe-eval`? The standard build evaluates expressions with
      `new Function()`; the CSP build restricts the expression syntax.
      ADR-0007's CSP consequence rests on this.

## Licences (to be verified)

The licence information in `docs/01-landscape.md` was written from memory and
**has not been confirmed**. Licences change often in this space. Each will be
verified on the tool's own page before it is chosen.
