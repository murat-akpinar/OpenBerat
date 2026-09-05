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

## Measured in the Phase 1 lab

Run on the lab host against the committed configuration (`docker-compose.yml`,
`oauth2-proxy.cfg`, `keycloak/realm/`), Keycloak 26.3 + oauth2-proxy v7.8.2,
2026-09-05. Each line below is an observation, not a reading of the docs.

### VERIFY (1) — `Set-Cookie` during `cookie_refresh`

**Answer: yes.** With `cookie_refresh = 5m`, a `GET /oauth2/auth` made after the
window has elapsed returns exactly **one** `Set-Cookie: _oauth2_proxy=…` header
alongside the identity headers. Inside the window it returns none. **ADR-0006's
mechanism holds at the oauth2-proxy end** — but only the *proxy* end: nothing
reaches the browser unless the subrequest's header is lifted out and re-emitted,
which is what `auth_request_set $auth_cookie $upstream_http_set_cookie` plus
`add_header Set-Cookie $auth_cookie always` in `10-portal.conf` are for.
`$upstream_http_set_cookie` captures only the first such header; one is all
there is here, because the Redis session store keeps the cookie small enough
never to be chunked.

**And the relay does not survive an internal redirect.** The first wiring of
the portal used `try_files $uri $uri/ /index.html`, and the refreshed cookie
never reached the browser even though oauth2-proxy was returning it. Measured,
same session age, one variable changed:

| Request | `auth_request` subrequests | `Set-Cookie` relayed |
|---|---|---|
| `GET /` with `try_files … /index.html` | **2** | 0 |
| `GET /index.html` (served directly) | 1 | 1 |
| `GET /` with `try_files $uri /index.html =404` | 1 | 1 |

An internal redirect — `try_files` falling through to a URI, an `index`
directive, a directory match — restarts nginx's access phase, so
`auth_request` runs **again**. The second subrequest arrives at oauth2-proxy
milliseconds after the first has already refreshed the session, correctly
returns no `Set-Cookie`, and `auth_request_set` overwrites `$auth_cookie` with
an empty string. Nothing errors. The user simply keeps their original groups
until `cookie_expire`, seven days later — **the exact silent collapse ADR-0006
was written to prevent, arriving through a door the ADR does not mention.**

Two consequences beyond the cookie:

- **Every such request costs two decisions, not one.** In Phase 3 that is two
  `/decide` calls, two cache lookups and two audit increments per request, on
  a path `docs/02` already describes as running 50 times for a single page.
- The fix is to keep authenticated locations free of internal redirects.
  `try_files … =404` as the final argument tries each preceding argument as a
  file and serves it in place; only a URI or named location as the last
  argument redirects. Protected applications `proxy_pass` and are unaffected;
  it is the static portal that has to be written carefully.

**`/oauth2/auth` answers `202`, not `200`.** Harmless — `auth_request` accepts
any 2xx — but a check written as `== 200` anywhere in the backend would fail
closed against a healthy session.

### VERIFY (3) — subrequests, the access phase, and inherited headers

Measured with a throwaway probe server on the lab nginx (1.29.8): a stand-in PDP
on loopback logging exactly what reached it, one location per question.

**Can an `auth_request` subrequest itself trigger `auth_request`? No.**

| Probe | Client sees | |
|---|---|---|
| `/q0` — the auth target returns 403 (control) | 403 | the harness denies correctly |
| `/q1` — the auth target itself carries `auth_request` → 403 | **204** | the inner target never ran |
| `/q6` — the auth target carries `deny all` | **204** | it never ran either |
| `/q1a`, `/q1b` requested directly | 404 | `internal;` holds |

And it is not `auth_request` that is special: `deny all` sits in the same nginx
phase and is skipped in the same position. **The access phase does not run for a
subrequest at all.** Two consequences:

- The chain cannot be built in nginx. It stays inside the backend, and
  [ADR-0002](adr/0002-pep-nginx-auth-request.md) is unchanged.
- `/decide`'s own protection still holds: in the same probe a direct request to
  an `internal` location returned 404, while `deny all` in that same location
  did nothing. So `internal;` is the directive that guards `/decide` — an
  `allow`/`deny` block beside it would test clean and constrain nothing.

**Does the subrequest inherit the main request's headers? Yes, verbatim.**
The client sent four headers it has no business sending:

| Sent by the client | At the PDP, nothing overridden (`/q4`) | At the PDP, with the `/decide` include (`/q3`) |
|---|---|---|
| `X-Original-URI: /admin/forged` | `/admin/forged` | `/q3?real=q3` — the config value wins |
| `X-App-Slug: finance` | `finance` | `probe-app` — the config value wins |
| `X-Auth-Request-Groups: OpenBerat-Admins` | `OpenBerat-Admins` | **`OpenBerat-Admins`** |
| `X-Probe: client-sent` | `client-sent` | **`client-sent`** |

A `proxy_set_header` of the same name replaces the inherited value; every header
the include does *not* name arrives at the PDP exactly as the client wrote it.
`docs/05`'s attack table covers the **upstream** direction — nginx stripping
`X-Auth-*` before proxying to the application — and says nothing about the
subrequest, which travels in the other direction and is not covered by that
include. **The `/decide` include has to clear the `X-Auth-*` family itself.**
`proxy_set_header X-Auth-Request-Groups "";` does it: at `/q5` the header is
absent at the PDP.

**`$request_uri` and `$request_method` inside the subrequest are the *main*
request's.** `POST /q3?real=post` arrives at the PDP as a `GET /decide` on the
wire, yet `proxy_set_header X-Original-Method $request_method` carried `POST`,
and `DELETE` came through as `DELETE`. `docs/02`'s header mapping is correct as
written and needs no workaround. (`$uri`, by contrast, is the subrequest's own
`/decide` — the two variables do not agree, and only one of them is the
original request.)

**A location that answers with `return` is not protected at all.** `return`
belongs to the rewrite module and runs in the **rewrite phase**, which comes
before the access phase where `auth_request` lives: the directive is present,
`nginx -t` is clean, and the subrequest never fires. The first cut of this probe
made exactly that mistake —
`location = /q0 { auth_request /q0deny; return 200 ...; }` with `/q0deny`
returning 403 answered **200**. The same config with `proxy_pass` in place of
`return` answers 403. Nothing in the repository does this today; ADR-0011's
generated application blocks are where it would arrive.

### Which claim lands in `X-Auth-Request-User`

The subrequest's response headers, verbatim:

```
x-auth-request-user:                 cae7c116-24a0-42b8-ac6e-9961b34f5d6b
x-auth-request-preferred-username:   labuser
x-auth-request-email:                labuser@example.local
x-auth-request-groups:               OpenBerat-Finance
```

`X-Auth-Request-User` carries the Keycloak **`sub`**, not the username —
`docs/05` assumed sAMAccountName and is corrected. The username arrives
separately in `X-Auth-Request-Preferred-Username`. This is the good outcome:
`X-Auth-Subject` and the ADR-0019 index need exactly this immutable value, and
it is there without a custom mapper. Groups arrive as flat names (`full.path`
off), which is what ADR-0008 matches on.

### The Redis session key survives a refresh

Across a `cookie_refresh` the cookie value **rotates** while the Redis key stays
byte-identical (`_oauth2_proxy-d8f9514ab7f2dec2ee20adbcd026765c` before and
after). The ADR-0019 index therefore does not go stale on refresh — the entry
written on the first cache miss still points at the live session. This is one
half of VERIFY (4); deleting the key to prove access actually stops is the other
half and is still open.

### Keycloak realm import

- **Environment substitution works, with one syntax only.** `${VAR}` is
  resolved from Keycloak's own environment. `$(env:VAR)` and `${env.VAR}` are
  stored **verbatim** — the import succeeds and the client ends up with a
  secret that is the literal placeholder text. Tested side by side in one
  import. This settles how the scrubbed export gets its real secret: `.env` →
  compose → Keycloak's environment → `${VAR}` in the export.
- **The file name must match the realm name.** `probe` in `zz-probe-realm.json`
  makes Keycloak exit at startup with `File name / realm name mismatch`. The
  failure is fatal, not a skipped file.
- **A `clientScopes` array replaces Keycloak's built-in set rather than adding
  to it.** An export that defines only `groups` leaves the realm without
  `profile` or `email`, and every login fails at the authorization endpoint
  with `invalid_scope`. The `groups` claim therefore comes from a protocol
  mapper on the client, which also makes it unconditional.
- **Keycloak issues no `aud` claim without an audience mapper**, and
  oauth2-proxy rejects the token: `audience claims [aud] do not exist in
  claims`. The client carries an `oidc-audience-mapper` naming itself.
- Keycloak advertises PKCE (`S256`) and oauth2-proxy leaves it off unless
  `code_challenge_method` is set. It is set.

### nginx resolves upstreams at startup

`proxy_pass http://oauth2-proxy:4180` makes nginx resolve the name **once, at
startup**, and refuse to start at all if it does not resolve — one stopped
container takes the entire PEP down, and ADR-0011 generates application blocks
whose upstreams may legitimately not exist yet. Fixed by `resolver 127.0.0.11`
plus a variable in `proxy_pass`, which moves resolution to request time; a
missing upstream then costs one 502 instead of the door.

Related, same class: oauth2-proxy performs OIDC discovery once at startup and
**exits** if Keycloak is not answering yet. `depends_on` waits for the
container, not for readiness, so first boot is a race it loses permanently.
Every service carries `restart: unless-stopped`.

## Unverified, to be tested

These claims have not been confirmed against a source; they will be tried in the
Phase 1 lab:

- [x] **Answered: no.** Can an nginx subrequest (the `auth_request` target)
      itself trigger an `auth_request`? The whole access phase is skipped for a
      subrequest — measured above. The chain stays in the backend and the
      internal HTTP call does not disappear.
- [ ] Can Keycloak carry an AD group's `objectSid` into a token claim? If it can,
      ADR-0008 (name vs SID) becomes easy to resolve.
- [ ] The real deprovisioning delay as measured with `cookie_refresh`.
- [x] Does oauth2-proxy return `Set-Cookie` when performing `cookie_refresh` on
      `/oauth2/auth`? **Yes** — measured above. In the official pattern the subrequest's upstream is
      oauth2-proxy; in ours it is the backend. **If it is not relayed the cookie
      is never refreshed and ADR-0006 silently collapses.**
- [x] **Answered: yes, verbatim.** Does the `auth_request` subrequest inherit
      the main request's headers? It does, so a client-supplied `X-Original-URI`
      / `X-Forwarded-Host` reaches the PDP unless the include overwrites that
      exact name (this is why `docs/02` fixes `X-App-Slug` in the nginx config —
      and why the same include now clears `X-Auth-*`). Measured above.
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
- [x] **Answered: the `sub`.** Which claim does oauth2-proxy put in
      `X-Auth-Request-User` for a Keycloak OIDC provider — `sub`, `preferred_username`, the email? `docs/05` assumes
      sAMAccountName, while `X-Auth-Subject` and the ADR-0019 index need the
      immutable `sub`; if no header carries the `sub`, the `docs/05` header
      contract is revised.
- [x] **Answered: yes, as `${VAR}`.** Can a committed Keycloak realm export
      reference environment variables for the OIDC client secret at import, or
      does the secret need a post-import step? The repository is public, so the export is committed scrubbed
      (`keycloak/README.md`) and the real value has to arrive some other way.
- [ ] Does the vendored Alpine.js run under a `default-src 'self'` CSP
      **without** `unsafe-eval`? The standard build evaluates expressions with
      `new Function()`; the CSP build restricts the expression syntax.
      ADR-0007's CSP consequence rests on this.

## Licences (to be verified)

The licence information in `docs/01-landscape.md` was written from memory and
**has not been confirmed**. Licences change often in this space. Each will be
verified on the tool's own page before it is chosen.
