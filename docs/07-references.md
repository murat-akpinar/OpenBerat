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
  that case here. **Measured below:** with the Redis store the cookie does not
  grow at all — but the 4 KB limit does not disappear, it moves to the response
  header block.

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

### VERIFY (4) — the Redis key is derivable from the cookie, and deleting it stops access

**Both halves answered. ADR-0019 holds, and with it ADR-0016's 5 s target.**

The key oauth2-proxy uses in Redis is recoverable from the raw session cookie the
backend already holds on every cache miss. The cookie is a signed, base64-wrapped
ticket:

    <base64( "v2." + base64url(handle) + "." + base64url(secret) )>|<ts>|<hmac>

Derivation: drop the `|ts|hmac` suffix, base64-decode, strip the `v2.` prefix,
and base64url-decode the handle up to the next `.`. The result is the Redis key
`_oauth2_proxy-<32 hex>`, and against a live login it matched an existing key
exactly. No oauth2-proxy secret is needed — the handle travels in the cookie in
the clear (the secret only decrypts the session payload, which the kill switch
never reads).

Deleting that key stops access on the **next** request. There is no backend yet,
so nginx `auth_request` targets oauth2-proxy's `/oauth2/auth` directly — this
measures the oauth2-proxy/Redis layer alone, which is what the kill switch acts
on:

| request | before `DEL` | after `DEL` |
|---|---|---|
| `/oauth2/auth` | 202 | 401 |
| `/` | 200 | 302 -> login |

**Across a `cookie_refresh` the key is stable.** The outer cookie value rotates
-- the signed timestamp changes -- but the handle inside is byte-identical
(`_oauth2_proxy-d8f9514ab7f2dec2ee20adbcd026765c` before and after), so the
ADR-0019 index written on the first cache miss still points at the live session.
The deletion test was repeated **after** forcing a refresh (>5 min, then one
request; the `Set-Cookie` on it confirms the refresh fired): the key derived from
the rotated cookie was live, and deleting it stopped access exactly as above.

Consequence: the kill switch deletes the session directly instead of degrading to
`cookie_refresh` latency (5 min). Option C is not needed and ADR-0016's 5 s
target stands. The one-shot test is `verify4.sh` on the lab host.

**The implementation was checked against the same lab, not only against itself.**
`session::session_key` was run over a cookie taken from a live `ob-login.sh`
session, and the key it produced —
`_oauth2_proxy-62a0f822376522d6626af2c9d8f9fe73` — was present in that Redis at
that moment. Worth doing because a round-trip test only proves the decoder
matches the encoder in the same file. Two details the recipe above does not
spell out and the real cookie does: oauth2-proxy writes the outer layer as
**padded standard** base64 (`…Mw==`) while the handle inside is URL-safe and
unpadded, so a decoder that assumes one alphabet fails on the other; and the
decoded handle *is* the Redis key as ASCII rather than bytes that need hex
encoding.

### A user in many groups — the cookie stays small, the header does not

**The cookie size problem is gone.** With `session_store_type = redis` the
session cookie is a fixed-length ticket: **192 bytes at 1 group and at 800**,
one cookie, never chunked. What grows is the Redis value and the identity
headers oauth2-proxy returns on `/oauth2/auth`. Ramped on labuser with
generated `OpenBerat-Load-NNNN` groups (18 characters each), a fresh login and
an empty Redis at every step:

| groups | session cookie | Redis session | `/oauth2/auth` | groups header | whole header block | `GET /` |
|---|---|---|---|---|---|---|
| 1 | 192 B | 3.3 KB | 202 | 42 B | 308 B | 200 |
| 100 | 192 B | 11 KB | 202 | 2022 B | 2288 B | 200 |
| 200 | 192 B | 19 KB | **502** | — | (4288 B) | **500** |
| 400 | 192 B | 35 KB | **502** | — | (8288 B) | **500** |

**The 4 KB limit did not disappear, it moved** — off the cookie, where
oauth2-proxy would have chunked it, and onto nginx reading oauth2-proxy's
*response header block*, where nothing chunks anything:

```
upstream sent too big header while reading response header from upstream,
request: "GET / HTTP/2.0", subrequest: "/oauth2/auth"
auth request unexpected status: 502
```

nginx reads a response header block into a **single** buffer of
`proxy_buffer_size` (one page, 4 KB here) and `auth_request` maps the resulting
502 onto **500 for the client**. That is a total lockout of exactly the accounts
an enterprise has most of — users in many AD groups — and it is not even a deny:
fail-closed, but indistinguishable from the backend being down. It appeared
between 100 and 200 groups, i.e. when the header block crossed 4096 bytes
(~185 groups at this name length), and nothing in `nginx -t` or in any startup
log says the configuration is one group list away from it.

Fixed in `10-portal.conf` with `proxy_buffer_size 32k` on the subrequest
location. **Raising that alone makes nginx refuse to start:**
`proxy_busy_buffers_size` defaults to twice `proxy_buffer_size` and must stay
below the `proxy_buffers` pool minus one buffer (`8 4k` by default), so
`proxy_buffers 4 32k` goes with it — and is never used, because a subrequest
response has no body. Re-measured after the fix, same ramp:

| groups | `/oauth2/auth` | groups header | header block | `GET /` | what `auth_request_set` captured |
|---|---|---|---|---|---|
| 100 | 202 | 2022 B | 2288 B | 200 | 1998 B |
| 200 | 202 | 4022 B | 4288 B | 200 | 3998 B |
| 400 | 202 | 8022 B | 8288 B | 200 | 7998 B |
| 800 | 202 | 16022 B | 16288 B | 200 | 15998 B |

Three more observations from the same run:

- **Groups arrive comma-joined in one header**, not one header per group — the
  count stayed 1 at every step. So
  `auth_request_set $g $upstream_http_x_auth_request_groups` carries the whole
  list byte for byte (1998 B of a 1998 B value at 100 groups) and does not
  silently keep only the first group.
- **The token grows with them:** at 800 groups Keycloak's token response was
  50 KB through nginx. That path is a response *body* and streams fine — the
  header buffer is the only place the size turns into an error.
- The same ceiling waits on two paths that do not exist yet: nginx reading
  **`/decide`**'s response, which carries the same joined list back as
  `X-Auth-Groups`, and the backend's own HTTP client reading oauth2-proxy's
  response — whose default header limit has not been checked and is a Phase 3
  item.

The one-shot test is `verify-groups.sh` on the lab host; it ends by recreating
keycloak and nginx to get the committed realm and configuration back.

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

### The login redirect — the `=` was inert and the `rd` was truncating

<https://nginx.org/en/docs/http/ngx_http_core_module.html#error_page> ·
<https://oauth2-proxy.github.io/oauth2-proxy/configuration/integrations/nginx/>

`error_page 401 = @signin` with the pattern both the oauth2-proxy documentation
and this repository carried — `return 302 …/oauth2/start?rd=$scheme://$host$request_uri`
— works: an anonymous request is answered `302`, the login completes, and the
user comes back to the page they asked for. Two things underneath it were not
what the configuration claimed.

**The client's query string was being handed to oauth2-proxy as parameters of
its own.** nginx has no way to percent-encode `$request_uri`, so it goes into
`rd=` raw and every `&` in it starts a new parameter of `/oauth2/start`.
Measured, one login each:

| Requested | Landed on after login |
|---|---|
| `/index.html?a=1&b=2` | `/index.html?a=1` |
| `/index.html?a=1&rd=https://evil.example.com/` | `/index.html?a=1` |

The first row is the everyday cost: a `200`, the right page, and everything
after the first `&` silently gone — a deep link into a protected application
comes back half-parameterised after any session expiry. The second is the same
mechanism aimed at the redirect itself: the injected `rd` became a *second* `rd`
parameter. oauth2-proxy took the first one and `whitelist_domains` would have
refused the host anyway, so it was not exploitable — but the client was writing
into the query string of a request it never made.

**Fixed by moving the return address out of the query string**: `@signin`
proxies to `/oauth2/start` and carries the target in `X-Auth-Request-Redirect`,
the header oauth2-proxy's own nginx page documents for exactly this
("or, if you are handling multiple domains"). Re-measured: `/index.html?a=1&b=2`
comes back whole, the injected `rd` arrives as inert query data on our host, and
the browser makes one round trip fewer — nginx now returns oauth2-proxy's
redirect to Keycloak directly instead of bouncing the browser through
`/oauth2/start`. The `rewrite ^ /oauth2/start? break;` needs its trailing `?`:
without it nginx appends the original query string and the injection is back.

**And the `=` this repository calls mandatory changed nothing — until the fix
made it load-bearing.** Measured side by side on one probe server, the same
location twice with only the `=` removed:

| Error handler | `error_page 401 = @signin` | `error_page 401 @signin` |
|---|---|---|
| `return 302 …` | 302 | **302** |
| `proxy_pass …/oauth2/start` | 302 | **401**, `Location` present |

nginx's documentation is precise about it and the rule as written was not: the
`=` means "answer with the code the handler returns", and it matters when *an
error response is processed by a proxied server*. `return` belongs to the
rewrite module and sets the status itself, so nothing was there to override.
The old configuration was correct by accident; the new one would have been a
401 with a `Location` nobody follows — the exact failure the rule describes,
reachable only now that the handler is a proxy.

### MEASURE — what the double hop costs

Five paths on one throwaway vhost, identical content phase (whoami over the
`edge` network), one variable changed: what the access phase has to do first.
A three-line fake `/decide` stood in for the backend — `return 200` for a cache
hit, `proxy_pass` to oauth2-proxy for a miss — in its own container on `core`,
so the hop crosses the same bridge the real backend will. Every subrequest leg
pooled (`keepalive`), HTTP/1.1, concurrency 1, 400 requests a round, 9 rounds,
first request of each round dropped because it paid for the TLS handshake.

| Path | What the access phase does | p50 |
|---|---|---|
| `direct` | nothing — no `auth_request` | **552 µs** |
| `local` | `auth_request` answered inside the same nginx | **558 µs** |
| `hit` | `auth_request` → fake `/decide`, answers alone | **626 µs** |
| `official` | `auth_request` → oauth2-proxy, the stock pattern | **997 µs** |
| `miss` | `auth_request` → fake `/decide` → oauth2-proxy | **1123 µs** |

Read as deltas:

- **The subrequest machinery is free**: +6 µs, inside the noise. What costs
  money is the hop, not `auth_request` itself.
- **N-01 draft — a cache hit costs +74 µs.** The decision adds well under a
  tenth of a millisecond to a request when the entry is warm.
- **N-02 draft — a cache miss costs +571 µs**, of which +497 µs is the
  oauth2-proxy call (cookie decrypt + Redis session load). The real miss adds
  the entitlement query and the `sub → session` index write on top; neither
  exists yet.
- **Our architecture costs +126 µs over the stock oauth2-proxy pattern.** That
  is the number ADR-0002 is spending: a second `auth_request` is impossible, so
  the chain runs inside the backend, and this is the bill for the extra hop.

Two things the harness does not measure. The fake `/decide` does no work —
no cache lookup, no path normalisation, no rule evaluation, no database — so
these are the topology's price, not the product's. And the bare-hop figure
(`hit` − `local`, +68 µs) understates a real hop: it answers with `return 200`
and never builds an upstream request, which is why the proxying hop on the miss
path costs nearly twice that.

**The environment moves more than the architecture does.** Two rounds out of
nine had every one of the five paths displaced by about +3 ms at once — a
2-core guest with background load, hypervisor steal at zero, so the contention
is inside the guest. The headline above is therefore the **median of the
per-round p50s**, not a pooled percentile: pooling lets one bad round move the
answer. Worth carrying into Phase 6, because under contention the deltas grew
rather than held — `miss` has the longest process chain (curl → nginx →
fake `/decide` → oauth2-proxy) and degraded first and furthest.

The measured user was in **one** AD group, so oauth2-proxy's identity header
block was ~186 bytes. A user in hundreds of groups returns a far larger block
on the same path — see the 4 KB buffer measurement above, which is the same
response travelling the same way.

Harness: `bench3.sh`, `99-bench.conf` and `bench-decide.conf` on the lab host;
the vhost and the container were removed afterwards and the stack is back on
the committed configuration.

### MEASURE — an active WebSocket outlives the authorisation that opened it

[ADR-0016](adr/0016-n03-revocation-targets.md) excludes an active WebSocket from
the revocation guarantee. This measures the exclusion instead of asserting it.

One echo connection through a protected vhost, carrying steady traffic — one
text frame a second, echo read back, never idle — and one HTTP poller on the
same cookie, the same vhost and the same `auth_request` target, so both paths
answer to exactly one authorisation. The group decision was made by a throwaway
oauth2-proxy started with `--allowed-group=OpenBerat-Finance`; the committed
proxy authenticates only, and would not have noticed the group at all. Control
first: with the group, `/oauth2/auth` returns **202** and
`X-Auth-Request-Groups: OpenBerat-Finance`; with an unheld group name, **401**.

| t | Event | HTTP path | WebSocket |
|---|---|---|---|
| 0 s | session minted, connection upgraded (`101`) | 200 | alive |
| +10 s | `labuser` removed from `OpenBerat-Finance` in Keycloak | 200 | alive |
| +300 s | `cookie_refresh` fires (`SessionAge: 5m1.9s`) | — | alive |
| +303 s | refreshed session no longer carries the group | **401** | alive |
| +427 s | Redis session gone since +303 s (see below) | 401 | alive |
| +457 s | `nginx -s reload` | 401 | alive |
| +498 s | nginx **container restarted** | 401 | **dead** |

**The HTTP path was cut 292 s after the group was removed**, at session age
5 m 1.9 s — the `cookie_refresh` boundary and nothing else, since this harness
has no decision cache in front of it. The last `202` is logged at +300 s and the
first `401` two seconds later. The 401 is the group check and not a lost
session: oauth2-proxy logs `Refreshing session` and then `[AuthFailure] Invalid
authorization via session (unauthorized): removing session` on the same request.

**The WebSocket never noticed.** It carried 500 exchanges over 499 s, 489 s of
them after the group was gone, and every one of them returned in ~0.2 ms. It
was authorised once, at the upgrade, and after that no request of any kind
crossed the access phase again — so there was nothing left for a policy to
answer.

Three consequences worth naming, because two of them are the levers an operator
would reach for and neither works:

- **The kill switch does not reach it.** oauth2-proxy deleted the session from
  Redis itself, at +303 s, when the refreshed group check failed — the same
  end state the kill switch produces ([ADR-0019](adr/0019-kill-switch-session-index.md)).
  The connection then ran for another **195 s with no session in Redis at all**.
  Revoking the session revokes the next *request*; there is no next request.
- **`proxy_read_timeout` does not reach it either**, as ADR-0016 says. It was
  set to 300 s and the connection lived through 499 s of it, because a frame a
  second resets it. It bounds idle connections only.
- **`nginx -s reload` does not reach it — and leaves a worker behind.** This is
  the path [ADR-0011](adr/0011-nginx-config-generation.md) takes on every
  application change. The old worker goes to `worker process is shutting down`
  and stays there, still serving the connection under the **old** configuration:
  measured across two reloads, the same PID was still shutting down 133 s later
  with the connection healthy. `worker_shutdown_timeout` is unset and nginx's
  default is no timeout, so one lingering worker accumulates per reload for as
  long as any long-lived connection is open. Whether to set it — and to what,
  given it also bounds ordinary reloads — is an open question in `docs/06`.

Only restarting nginx cut the connection, at +498 s: `SSLEOFError` on the client
one second later. That is not a revocation mechanism, it is an outage.

Harness: `verify-ws.sh` and `wsclient.py` (stdlib only — the lab host has no
`websocat`) with `99-ws.conf` on the lab host. The throwaway proxy and vhost
were removed afterwards, `labuser` was put back in `OpenBerat-Finance`, and the
stack is back on the committed configuration.

### Installing from a clean checkout — three steps that were wrong

`INSTALL.md` §1–§4 replayed on the lab host from a `git archive` of `HEAD`, as a
second compose project beside the running lab, following the document and
nothing else. Three failures, each of them something the lab host already had
and the document therefore never had to say:

- **`certs/` is not in the repository.** It is gitignored, so a fresh checkout
  has no such directory and §1's `openssl req` exits 1 with `Can't open
  "certs/wildcard.key" for writing, No such file or directory` — after printing
  a full screen of key-generation progress, which reads like success.
  `mkdir -p certs` is now part of the step.
- **The cookie secret the document told you to generate is refused.** `openssl
  rand -base64 32` is 44 characters, and oauth2-proxy v7.8.2 answers
  `cookie_secret must be 16, 24, or 32 bytes to create an AES cipher, but is 44
  bytes` and crash-loops. It measures the **string**, and decodes it first only
  if it is in the URL-safe alphabet — so the fix is one `tr`, not a shorter
  secret. Five recipes tested against v7.8.2:

  | Command | Length | Result |
  |---|---|---|
  | `openssl rand -base64 32` | 44 | **refused** |
  | `openssl rand -base64 32 \| tr -- '+/' '-_'` | 44 | accepted |
  | the same, `=` stripped | 43 | accepted |
  | `openssl rand -base64 24` | 32 | accepted, as 32 raw bytes |
  | `openssl rand -hex 16` | 32 | accepted, as 32 raw bytes |

  The check is strict **only because `cookie_refresh` is set**: the same 44
  character secret starts cleanly with `cookie_refresh` off, since without it
  no session is ever re-encrypted. ADR-0006 makes `cookie_refresh` mandatory,
  so this is not a knob — it is a permanent condition of the design, and the
  document's own reason ("must decode to 16, 24 or 32 bytes") was wrong twice
  over.
- **A base64 `POSTGRES_PASSWORD` breaks `DATABASE_URL`.** The document says to
  generate every password with `openssl rand -base64 24`; 394 of 1000 generated
  that way carry a `/`, which ends the URL's authority component. `psql
  "postgres://openberat:ab/cd+ef@127.0.0.1:5432/openberat"` fails with `invalid
  integer value "ab" for connection option "port"` — an error that names
  neither the password nor the character. Percent-encoding works and hex
  sidesteps it; §3 now says hex for that one variable. Nothing has hit this yet
  because the backend does not connect to Postgres until Phase 2.

Two more things the replay showed that are not errors but read like them: the
first `docker compose build` spends about five minutes in the backend's release
compile, and for the ~25 s Keycloak needs to boot and import the realm,
`docker compose ps` reports oauth2-proxy `restarting` — indistinguishable, from
`ps` alone, from the fatal secret above. Both are in §4 now.

After the three fixes the replay completed: anonymous request → 302 to Keycloak
with PKCE `S256`, credentials posted, session cookie minted, portal served 200.
The throwaway project and its checkout were removed and the lab put back on the
committed configuration.

### Samba AD DC does not provision in an unprivileged container

Two failures, one after the other, bringing `samba-ad` up for the first time.

**The DC's short name may not equal the domain's.** `hostname: ad` with
`AD_DOMAIN=ad.example.local` gives both the NetBIOS name `AD`, and Samba stops
at `guess_names: Domain 'AD' must not be equal to short host name 'AD'`. Fatal,
before anything is written. The pair is now `dc01` in `example.local` — the one
`docs/03` already documents, which also makes its example DNs (`DC=example,
DC=local`) literally correct.

**Provisioning then panics setting the sysvol ACLs.** `set_nt_acl` →
`try_chown` → `Security context active token stack underflow`, in the middle of
"Setting up self join". The cause is one layer below Docker: writing the
`security.NTACL` extended attribute returns `EPERM` **on the lab host, as root,
outside any container**. `systemd-detect-virt` reports `lxc` and
`/proc/sys/kernel` is owned by `nobody:nogroup` — the host is an unprivileged
Proxmox container, and a user namespace refuses writes to the `security.*`
namespace no matter which capabilities are held. `user.*` xattrs work; only
`security.*` are refused, and that is the namespace Samba's `acl_xattr` module
needs.

It is not the image or the configuration. The same wall with
`nowsci/samba-domain` (Samba 4.15) and with a Debian 13 image built for the
purpose (Samba 4.22), under `--privileged`, `seccomp=unconfined`,
`apparmor=unconfined`, `--cap-add SYS_ADMIN`, with `/var/lib/samba` on a named
volume rather than overlayfs, with `posix:eadb` pointing the xattrs at a tdb,
with `posix_eadb` named explicitly in `vfs objects`, and with `--targetdir`.
Samba 4.22 has also **removed** `--use-xattrs=no`, the flag the wiki still
names for filesystems without xattr support; `posix:eadb` is what is left of
it, and on its own it only gets as far as
`posix_eadb_fremovexattr() failed to get vfs_handle->data!` before the same
panic.

The database itself survives the panic — `samba-tool user list` returns
`Administrator`, `Guest`, `krbtgt` and the domain reports function level 2008
R2 — but the run aborts before the machine account reaches `secrets.ldb`, so
`samba` exits at startup with `Failed to obtain server credentials, perhaps a
standalone server?`. There is no usable half-state.

Consequence: the lab needs a host that is not a user namespace — bare metal, a
VM, or a privileged container. Recorded as a lab prerequisite in `INSTALL.md`
and in [ADR-0010](adr/0010-lab-ad-samba.md)'s consequences; it does not change
the decision, only the ground it needs. Every remaining Phase 1 box waits on
it.

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
- [x] **Answered: yes, and deleting it stops access.** Can the oauth2-proxy
      Redis session key be derived from the session cookie the backend already
      holds? Measured above: strip the signature, base64-decode, base64url-decode
      the handle -> the `_oauth2_proxy-<hex>` Redis key, which deleting cuts
      access on the next request. The key is byte-identical across a
      `cookie_refresh` (only the signed timestamp rotates the outer cookie), and
      the deletion test was repeated after a refresh had fired.
      **[ADR-0019](adr/0019-kill-switch-session-index.md) holds** and with it
      ADR-0016's 5 s target; option C is not needed.
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
