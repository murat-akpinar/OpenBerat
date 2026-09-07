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
| `cookie_expire` | `168h0m0s` | `10h` | The realm's own `ssoSessionMaxLifespan`: a cookie may not outlive the session it stands for (`docs/04`) |
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
  `..._RECURSIVELY` is required. Both halves measured in the lab below, plus one
  the docs do not mention: the recursion is not bounded by the group filter.

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

### The backend's own limit on that same group list

**~408 KB of response headers, about 16,000 group names — and it fails as an
outage, not as a size problem.** nginx's half of this is measured below; the
backend reads the same `X-Auth-Request-Groups` off oauth2-proxy's response with
a different HTTP client, so the number is different and had never been asked
for. Measured through `/decide` against a stand-in that generates the list:

| groups | header | result |
|---|---|---|
| 800 | 20 KB | 200 |
| 2 000 | 50 KB | 200 |
| 10 000 | 250 KB | 200 |
| 15 000 | 380 KB | 200 |
| 20 000 | 510 KB | **403 `auth_unavailable`** |

The ceiling is hyper's header buffer — 8 KB plus 4 KB per allowed header, about
408 KB — and **not** the 1 s oauth2-proxy budget: raising that to 20 s changed
nothing, which is the experiment that separates the two.

Two consequences. It is an order of magnitude above the 32 KB `proxy_buffer_size`
nginx needs for the same list (~1,300 groups), so **nginx is still the binding
constraint** and the one to raise first. And when it does bite, the request
denies with `auth_unavailable` — which reads as "oauth2-proxy is down" and sends
an operator to restart the wrong service. Anyone raising nginx's buffer past
~400 KB has to raise this at the same time.

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

### A comma in a group name is the management plane

The group list is joined with a comma into one header and split back apart on
the other side (measured two sections above: one header, never one per group).
Nothing in that round trip records where a name ended and the next began, so a
single group **named** `Payroll,OpenBerat-Admins` arrives as two — and the
second one is `ADMIN_GROUP`.

Measured end to end on the lab stack, with `labuser`, an ordinary portal user
in `OpenBerat-Finance` and nothing else:

| step | result |
|---|---|
| Create a Keycloak group named `Payroll,OpenBerat-Admins` | accepted, no complaint |
| Add `labuser` to it — one group, not two | accepted |
| Fresh login, `GET /api/me` | `groups: ["OpenBerat-Finance","Payroll","OpenBerat-Admins"]`, **`admin: true`** |
| `GET /api/admin/applications` | **200** |
| `POST /api/admin/entitlements`, a wildcard grant with no `application_id` | **201 Created** |

The last row is the whole product: a wildcard entitlement grants every
application, present and future (`docs/05` rule 4). Harness: `verify-comma.sh`
on the lab host, which restores the realm and the table afterwards.

**It cannot be fixed on our side of the header.** The claim leaves Keycloak as a
JSON array, oauth2-proxy flattens it to a string, and the request reaches the
backend with the boundary information already gone. Splitting more carefully
does not help: `["Payroll,OpenBerat-Admins"]` and `["Payroll",
"OpenBerat-Admins"]` produce the same bytes. Reading the array instead would
mean either decrypting oauth2-proxy's Redis session — reimplementing its session
format — or moving to oauth2-proxy's alpha configuration, and neither is a v1
change ([ADR-0006](adr/0006-group-membership-source.md) chose the header path).

**What does close it is upstream, and it is `OpenBerat-`.** The prefix in
[ADR-0008](adr/0008-group-identity-name.md) was introduced to keep the claim
small; it turns out to be the control that stops this, because the Keycloak LDAP
group filter matches the **whole** `cn` and `Payroll,OpenBerat-Admins` does not
match `OpenBerat-*`. A group that never enters Keycloak never reaches the
header. That makes the filter load-bearing rather than an optimisation, and
`docs/05` and ADR-0008 now say so. Verified against a real LDAP filter two
sections below, by taking the filter away.

Two things the backend *can* do, and now does:

- An `ad_group` entitlement whose `subject_id` contains a comma is **refused**
  at `POST /api/admin/entitlements`. It could never have matched anything — the
  list it is compared against was split on commas — so storing it would give an
  admin a rule that silently never fires.
- The whole management plane is tested against a portal user, route by route,
  in and out of process. Seven routes, a valid `Origin` and bodies that would
  really work: all 403, nothing written, each refusal logged with the actor.
  The same seven answer 200/204 for `labadmin`, which is what stops the seven
  403s from being seven typos.

### The lab AD, and the Cache Policy that decides whether Keycloak is live

The DC provisions on a host that is not a user namespace — the wall the section
above hit is the host, not Samba. On an Ubuntu 24.04 KVM guest, with no
`ima,evm` in the LSM list, `security.NTACL` writes succeed and
`nowsci/samba-domain` comes up as `dc01` in `example.local` at function level
2008 R2, costing 262 MiB and 0.04 % of one core at idle. The fixture that every
measurement below runs against is `samba-ad/fixture.sh`.

**A declared `subComponents` block suppresses Keycloak's default mappers.**
Adding the LDAP provider through the admin console creates seven mappers behind
your back — `username`, `first name`, `last name`, `email`, `creation date`,
`modify date`, `full name`. Declaring the provider in a realm export with a
`subComponents` block creates *only* what the block names, and nothing warns.
With just the group mapper declared, every user came back from LDAP carrying
`memberOf` and `pwdLastSet` and nothing else, and the import died on
`User returned from LDAP has null username! ... Mapped username LDAP attribute:
sAMAccountName`. The committed export therefore spells all eight out.

**The `userAccountControl` filter works, and it is the only thing that hides a
leaver.** `(&(objectCategory=person)(objectClass=user)(!(userAccountControl:
1.2.840.113556.1.4.803:=2)))` against the fixture returns `labuser`, `labadmin`
and `labnested` but not the disabled `labdisabled`, who is a member of
`OpenBerat-Finance` and would otherwise still be entitled.

#### VERIFY (2) — Cache Policy

**Answer: `NO_CACHE` is load-bearing, and the failure is silent.** The claim
under test is [ADR-0006](adr/0006-group-membership-source.md)'s — that Keycloak
reads group membership live and is therefore not a staleness layer. It is true
at exactly one setting.

Method: read `labuser`'s groups through Keycloak's own admin API (so the
oauth2-proxy session is not in the way), move the user in and out of
`OpenBerat-Finance` in AD, and compare against the directory.

| Cache Policy | Membership change in AD | Keycloak's answer |
|---|---|---|
| `NO_CACHE` | removed | gone on the next read |
| `DEFAULT` | removed | **still there** at t+0 and at t+180 s |
| `MAX_LIFESPAN` (60 s) | re-added | absent at t+0, present at t+70 s |

`DEFAULT` is the interesting one, and not because of the 180 seconds: a
**brand-new login** — a fresh browser flow, a new session, a new token — still
carried `OpenBerat-Finance` in `X-Auth-Request-Groups` after the group was
gone. So "Keycloak queries AD at login" is not a property of Keycloak; it is a
property of `NO_CACHE`. At `DEFAULT` nothing bounds the delay: not
`cookie_refresh`, not the decision cache TTL, not logging out and back in. Only
a component update, a realm cache clear or a restart flushes it, and the
deprovisioning target N-03 is unreachable by any amount of configuration
elsewhere.

`MAX_LIFESPAN` at least bounds it, and would be defensible if the number were
small. It is not what the design assumes, and the setting that matches the
design is `NO_CACHE`.

The failure mode is the same shape as the missing `cookie_refresh`: no error,
no warning, a working login, and entitlements that stopped tracking AD. It is
now a second mandatory line in ADR-0006's consequences.

#### Federation — an AD user logs in with no Keycloak-side account

**Answer: yes, and the credential never leaves AD.** The test refuses the
incidental evidence — `labuser` and `labadmin` log in, but both were in the
directory before the provider was declared, so their working login proves only
that *some* account works. The account under test was created in AD after the
realm was already running and deleted at the end: `labfed`, in `OU=Users`, in
no group at all.

| step | done in | result |
|---|---|---|
| `samba-tool user create labfed` | AD | Keycloak lists the user without anyone logging in |
| full OIDC login, first ever | browser flow | `/api/me` answers `labfed`, `sub` `0d4928bd…` |
| `samba-tool user setpassword` | AD | old password **refused** on the next login, new one accepted, same `sub` |
| `samba-tool user delete` | AD | login refused; the imported user disappears from Keycloak's list |

Two things follow that the happy path alone does not show. The password
rotation is the one that matters: with `editMode: READ_ONLY` the credential
Keycloak stores for a federated user carries a `federationLink` and no hash, so
the bind is delegated to the DC on **every** login — the old password stops
working the moment AD changes it, with no sync period, no cache flush and no
Keycloak restart. And `sub` survives the rotation, because it is derived from
`objectGUID` and not from anything a credential change touches, which is what
lets the ADR-0019 session index key on it.

The listing step is the counter-intuitive one: `labfed` appeared in Keycloak's
user list *before* the first login, because with `importEnabled: true` a user
search is itself an LDAP query and imports what it finds. Keycloak's user list
is therefore not a record of who has logged in; it is a cache of who was
looked up. Reading it as an audit of access would be wrong.

The harness is `ob-login-pw.sh` on the lab host — `ob-login.sh` with the
password as an argument, because rotating `labuser`'s would break every other
script. Its first version called the login successful whenever the jar held a
cookie matching `_oauth2_proxy`, which the **failed** flow also leaves behind
as `_oauth2_proxy_csrf`: a wrong password passed. The signal is `/api/me`
answering 200 with the expected username.

#### A disabled account — what the filter stops, and what stops it anyway

**Answer: it cannot log in, and the custom filter is not the reason.** The
account under test is `labuac`, created in AD after the realm was running and
deleted at the end, enabled first so that the same credential is known to work
and the disable bit is the only thing that changes between the two rows.

| Custom User LDAP Filter | Keycloak's user list | Login | Keycloak's reason |
|---|---|---|---|
| present (the committed config) | absent; a user already imported is **removed** | refused | `error="user_not_found"`, `userId="null"` |
| removed | present, and reported **`"enabled": true`** | refused | `error="invalid_user_credentials"`, with a real `userId` |

There are two independent barriers, and the one everybody names is the weaker.
AD refuses the LDAP simple bind for a disabled account, and `editMode:
READ_ONLY` delegates that bind on **every** login (measured above), so the
password is refused with the filter or without it.

What the filter alone does is keep the account out of Keycloak's *view*, and
that is not cosmetic. Without it Keycloak imports a leaver, gives them a `sub`,
resolves their groups, and displays them as **enabled** — Keycloak does not
read `userAccountControl`, so an operator reading the user list sees an account
AD has disabled shown as active. Every path that does not end in an AD bind
then reaches a live account: a locally set password, token exchange, a future
non-password authenticator. `docs/03` said "without this, staff who have left
keep logging in"; that is wrong as written and is corrected there. Without it
they keep *existing*, and it is AD, not our configuration, that refuses them.

**F-10 — how long a session already open survives.** `labuac` logged in while
enabled and was disabled in AD 12 s later; `/api/me` was polled every 10 s.
It answered 200 through `t+272 s` and 302 from `t+282 s` (10 s resolution). The
cut is at the `cookie_refresh` boundary — 299 s after the token was issued, not
after the disable — so the worst case is `cookie_refresh` (300 s) plus the
decision cache TTL (30 s) = **330 s**, inside N-03's 6 minutes with half a
minute to spare — added here, and measured directly further down, where a
cache entry minted just before the boundary carries access to t+328. Disabling shortens nothing: the session dies at the next
refresh, exactly as a group removal does.

The instruments lied twice before this was the answer, both times in the
reassuring direction. `kcadm get components/<id> --fields config` **omits**
`customUserSearchFilter`, so the projection prints a configuration the
component does not have. And `kcadm update components/<id> -f file.json`
**merges**: deleting a key from the file leaves it on the component. The first
control run therefore removed nothing and produced a confident wrong answer — a
disabled user still invisible "without" a filter that was still there. Removing
a key needs `-s 'config.<key>=[""]'`; any `-f` body needs `providerType` and
`parentId` or the server answers `Invalid provider type 'null'`. Read the state
back from the full `get components/<id>`, or from the LDAP configuration
Keycloak prints itself when it rebuilds the store. Harness: `verify-uac.sh`
and its log on the lab host.

### The `groups` claim, and what else can put a name in it

Every earlier group observation on this stack read `X-Auth-Request-Groups` —
oauth2-proxy's rendering of the claim, not the claim. This one drives the
authorization-code flow itself and stops at the callback, so the code is still
unspent, then exchanges it at the token endpoint with its own PKCE verifier and
decodes what Keycloak signed.

**`GET_GROUPS_FROM_USER_MEMBEROF_ATTRIBUTE` delivers, and it is live.** Both the
ID token and the access token carry `groups`, as flat names (`full.path` off),
which is what ADR-0008 matches on. A group created in AD and a membership added
to it reached the **next login's token** with no sync run, no Keycloak restart
and no cache to wait out — `fullSyncPeriod: -1`, so nothing had synced, and
`cachePolicy: NO_CACHE`, without which the section above shows it would not have.
Removing the membership in AD took the name back out of the next token.

| AD state for `labuser` | `groups` in the token |
|---|---|
| baseline | `["OpenBerat-Finance"]` |
| `OpenBerat-Claimtest` created, member added | `["OpenBerat-Claimtest","OpenBerat-Finance"]` |
| member removed | `["OpenBerat-Finance"]` |
| group deleted in AD | `["OpenBerat-Finance"]` |
| **group re-assigned in Keycloak, absent from AD entirely** | `["OpenBerat-Finance","OpenBerat-Claimtest"]` |

**The last row is the finding: the claim is a union, not a projection of
`memberOf`.** The imported group object survives its deletion in AD — nothing
syncs, and `drop.non.existing.groups.during.sync` is `false` — and assigning the
user to that orphan *in Keycloak* put the name back in the token with no
`memberOf` entry anywhere in AD to support it. `editMode: READ_ONLY` and the
mapper's own `mode: READ_ONLY` govern writes **towards LDAP**; neither prevents a
local group membership inside Keycloak. Nor does the LDAP filter
`(cn=OpenBerat-*)`, which selects which AD groups are imported and constrains
nothing on this path.

It is not an escalation — whoever can assign a group in Keycloak can equally
sign a token containing any group at all — but it bounds what "AD is the single
source of truth" can be read to promise, and `docs/02` and `docs/03` are
corrected. `ADMIN_GROUP` is matched on this claim by name, so **reading AD does
not tell you who holds OpenBerat admin**; the reconciliation question that
raises is in `docs/06`. It also explains why the comma escalation two sections
up reproduced against a hand-made *Keycloak* group: that path never needed AD.

Incidental, and not the answer to its own box: `labuser`'s `memberOf` carried
`CN=Payroll\,OpenBerat-Admins` throughout and the claim never did. That agrees
with what the filter is supposed to do, but the control case — the same login
with the filter genuinely removed — has not been run, and the box stays open.

Harness: `verify-groupclaim.sh` + `claims.py` on the lab host. It only reads;
the AD and Keycloak mutations in the table were made by hand and reverted, and
both sides are back on `samba-ad/fixture.sh` state.


### Nested groups — `memberOf` misses them, and the recursive strategy crosses the filter

Fixture (`samba-ad/fixture.sh`): `labnested` is a member of `Finance-All`, and
`Finance-All` is a member of `OpenBerat-Finance`. AD's `memberOf` on `labnested`
names `Finance-All` and nothing else, which is direct membership behaving as
documented.

| Group mapper strategy | `groups` for `labnested` (transitive) | `groups` for `labuser` (direct) |
|---|---|---|
| `GET_GROUPS_FROM_USER_MEMBEROF_ATTRIBUTE` | **absent** | `["OpenBerat-Finance"]` |
| `LOAD_GROUPS_BY_MEMBER_ATTRIBUTE_RECURSIVELY` | `["OpenBerat-Finance"]` | `["OpenBerat-Finance"]` |

The first row is the expected half, with one detail worth having: the claim is
**absent**, not an empty list. A nested-group deployment left on the default
strategy therefore does not misgrant, it denies — every such user reaches the
backend with no groups and default-deny gives them nothing, which is the failure
mode to prefer but also the one nobody reports as a bug against AD.

The second row was not predicted. `Finance-All` does not match the mapper's
`groups.ldap.filter` `(cn=OpenBerat-*)`, so Keycloak does not import it — and
the recursive strategy resolved straight through it anyway. The filter still
bounds what the claim can **name**: `Finance-All` never appears in it. It does
not bound what may be **traversed** to get there. A client-side walk over the
filtered group set could not have reached `OpenBerat-Finance` from a user whose
only `memberOf` is invisible to that set, so the chain is being resolved on the
directory side of the query. Under this strategy the users who can hold
`ADMIN_GROUP` include everyone nested below `OpenBerat-Admins` through groups
with any name at all — [ADR-0008](adr/0008-group-identity-name.md)'s prefix is a
naming rule for the claim, never a containment boundary.

Switching is one field on the group mapper and needs no restart: the next login
carried the new answer in both directions. The performance cost `docs/03` warns
about was not measured — a four-group fixture cannot show it, and that number
has to come from the target directory.

Harness: `verify-nested.sh` on the lab host. It flips the strategy, runs
`verify-groupclaim.sh` at each setting and restores the mapper; the realm is
back on `GET_GROUPS_FROM_USER_MEMBEROF_ATTRIBUTE`. Writing the mapper back needs
the two `kcadm` habits the `userAccountControl` section describes — read the
whole component, not `--fields config`, and read it back after every write.

### The group filter is what stops the comma — measured by taking it away

`Payroll,OpenBerat-Admins` is a real group in the lab AD (`samba-ad/fixture.sh`,
created as LDIF because `samba-tool` cannot build the DN) and it is in
`labuser`'s `memberOf` next to `OpenBerat-Finance`. The escalation measured
above used a Keycloak-local group; this is the same name arriving the way a
customer's would, through LDAP — and the row that settles
[ADR-0008](adr/0008-group-identity-name.md) mitigation 1 is the second one, the
same login with `groups.ldap.filter` emptied.

| `groups.ldap.filter` | `groups` claim for `labuser` | `/api/me` | `GET /api/admin/applications` |
|---|---|---|---|
| `(cn=OpenBerat-*)` | `["OpenBerat-Finance"]` | `admin: false` | 403 |
| *(empty)* | `["Payroll,OpenBerat-Admins", "OpenBerat-Finance"]` | `groups: ["Payroll", "OpenBerat-Admins", …]`, **`admin: true`** | **200** |

One name in the claim, two in the backend, and the second is `ADMIN_GROUP`. The
filter is the control, and it is the only one: an installation that widens it
has an escalation path open to anyone who can create a group in AD, not merely a
large token.

A negative result is worth what the proof that the filter was really off is
worth, so `labnested` rides along as a positive control — its only group is
`Finance-All`, a name the filter excludes for an ordinary reason. Claim
**absent** with the filter on, `["Finance-All"]` with it off. The edit took
effect, so the quiet `labuser` row above is the filter working rather than the
write failing silently, which is exactly how the `userAccountControl` control
case nearly went.

Two things that were not predicted:

- **Removing the filter imports the excluded groups into Keycloak's own
  database, and restoring it does not remove them.** After the control the realm
  held `Finance-All` and a group literally named `Payroll,OpenBerat-Admins`. The
  claim goes clean on the very next login — under
  `GET_GROUPS_FROM_USER_MEMBEROF_ATTRIBUTE` membership is re-resolved through the
  filter every time — so the leftover object grants nothing by itself. It is one
  Keycloak-side assignment away from granting everything, and that assignment is
  the one the section above measured as invisible to AD. Ten minutes of a widened
  filter therefore leaves cleanup behind that nothing prompts for.
- **The filter is consulted per login, not only at sync time.** That is what
  makes it usable as a control rather than a sync-time hygiene setting:
  tightening it takes effect on the next token, with no restart and no sync.

Harness: `verify-commafilter.sh` on the lab host — baseline, control, restore,
cleanup, then a fifth pass that proves the restoration from the outside rather
than from the setting. It carries one shell trap worth naming, because it left a
group behind on the first run: `docker compose exec -T` reads stdin, so a
`while read` delete loop fed by a pipe loses every line after the first
deletion. The cleanup list goes through a file.

### `ADMIN_GROUP` outside the group filter — the management plane locks everyone out

The comma experiment above measured one direction: a group name the filter lets
through *is* the management plane. The other direction is the mistake an
installation actually makes, and it was written into `INSTALL.md` §4 before it
had been tried, so it was tried. `ADMIN_GROUP` arrives from the shell
(`ADMIN_GROUP=… docker compose up -d --force-recreate backend`), so the lab's
`.env` is never edited; harness `verify-admingroup.sh` on vaultscan.

`GET /api/admin/applications` through the real proxy, with fresh logins:

| `ADMIN_GROUP` | `labadmin` | `labuser` |
|---|---|---|
| `OpenBerat-Admins` (committed) | **200** | 403 |
| `Payroll-Admins` — excluded by `(cn=OpenBerat-*)` | **403** | 403 |
| `OpenBerat-Admins` again | **200** | 403 |

So the failure is total rather than partial: the account that is in the real
admin group is refused alongside everyone else, and because `ADMIN_GROUP` is
checked against the claim there is no database row and no locally created
Keycloak account that can grant it back — the group has to exist *in AD* and
pass the filter. In a fail-closed system the first admin cannot come from the
database, and this is what that costs when the variable is wrong.

**The symptom points at the wrong thing.** `/api/me` still lists
`OpenBerat-Admins` in `groups` and reports `"admin": false` in the same
response, so from the portal it looks like a group-membership problem while it
is a one-variable problem. The only place the two are named together is the
backend log:

```
WARN openberat::admin: admin refused: not in ADMIN_GROUP actor=labadmin path=/api/admin/applications
```

That line, with an `actor` that is visibly in the group the installation thinks
it configured, is the signature. `docker compose logs backend | grep 'admin
refused'` is the first thing to read when nobody can reach `/api/admin/*`.

### MEASURE — a group removed in AD, and the 330 seconds it can take

The claim under test is [ADR-0016](adr/0016-n03-revocation-targets.md)'s six
minutes for the ordinary deprovisioning path, and the arithmetic
[ADR-0006](adr/0006-group-membership-source.md) puts behind it: staleness lives
in `cookie_refresh` plus the decision cache TTL and nowhere else. The
`userAccountControl` measurement above reached 330 s by adding the two; this one
removes a group and watches the whole committed chain do it.

One application `wiki` on `sample-app` and one entitlement allowing
`OpenBerat-Finance`, both created through `/api/admin/*` so the vhost under test
is the generated one ([ADR-0011](adr/0011-nginx-config-generation.md)). Controls
first: `labuser` 200, anonymous 302 into the login flow. The cut, when it comes,
is `deny="no_matching_grant"` in the nginx log and a 302 to the portal's
`/denied` — the deny page is on the portal host, so a refusal is a redirect and
not a 403 on the wire.

**Run 1 — a client that never stops asking.** Poll every 2 s from login; the
group goes out of AD 19.5 s in.

| t | event | answer |
|---|---|---|
| +0 s | session minted, first request | 200 |
| +19.5 s | `samba-tool group removemembers` | — |
| +19.5 s | Keycloak asked for the user's groups | **already empty** |
| +300.7 s | last request on the old membership | 200 |
| +302.7 s | `Refreshing session … SessionAge: 5m2.057s` | **302** |

**283.2 s after the AD change**, at the `cookie_refresh` boundary and nothing
else. The directory contributed **zero** — at `NO_CACHE` the group was gone from
Keycloak's answer in the same second (VERIFY (2) above), so every one of those
283 seconds is ours.

The structural half of the run is the more useful one. 150 polls produced
**10** consultations of `/oauth2/auth`, exactly 30 s apart. A cache hit never
reaches oauth2-proxy, so on a hit nothing looks at the session's age at all: the
decision cache does not add its TTL *after* the refresh, it decides **when the
refresh is attempted**. The two terms are not sequential delays, and treating
them as a sum is right for the ceiling and wrong for the mechanism.

**Run 2 — the ceiling, on purpose.** Same setup, but one request at t+296 and
silence before it. That request misses the cache at session age 4 m 56 s, so
oauth2-proxy answers from the unrefreshed session and the entry is minted with
the *old* groups, 4 s before the boundary — and it is a hit for one whole TTL.

| t | request | answer |
|---|---|---|
| +0 s | control | 200 |
| +13.8 s | group removed in AD | — |
| +296 s | cache miss, session age 4 m 56 s | 200 |
| +298 … +326 s | **16 hits, every one of them past the refresh boundary** | 200 |
| +328 s | cache miss, `SessionAge: 5m27.187s` | **302** |

**314.2 s after the AD change**, and 28 s after the session should have been
re-checked. Three consultations for the whole run. A fill at t+299.9 gives
t+329.9, so the ceiling is exactly `cookie_refresh + TTL` = **330 s**, and it is
reached rather than approached — the worst case is not a tail, it is one
ordinary request landing a few seconds before the boundary.

Against N-03's 360 s that leaves **30 s of margin**, and the margin is the whole
of it: there is no term left to absorb a slower Keycloak or a longer poll gap.

Which lever to reach for if 330 ever has to come down follows from the same
consultation grid, and it is not the one ADR-0016 names. Shaving `cookie_refresh`
buys time at the price of a token refresh against Keycloak per user per period;
shaving the cache TTL buys the same seconds at the price of a subrequest and an
entitlement query, both local. Neither is free, but only one of them is paid to
the IdP.

Harness: `verify-n03.sh` on the lab host, driven from the workstation — the DC
is on the other host, so no single script sees both ends. `labuser` was put back
in `OpenBerat-Finance` and the application and entitlement were deleted
afterwards; the generated `apps.conf` is back to its header.


### `/api/admin/explain` — checked against the PEP rather than against itself

An explain screen is only worth having if it answers the same way as the thing
it explains, and the cheap way to test one — assert that it reports the rules
the fixture just created — proves nothing, because a second decision
implementation would pass it too. So the harness makes both answers for the
same request: `labuser` fetches the path through nginx while an admin explains
it, and the two are compared.

Twelve paths, one application, `OpenBerat-Finance` holding `allow ""` and
`deny /admin/*`. The PEP and the explanation agreed on all twelve, including
the normalisation cases the deny rule exists to survive: `/x/../admin/users`,
`/%61dmin/`, `/x\..\admin/` and `/admin/users?next=/public` were denied by
both, `/adminx` and `/public?next=/admin/` allowed by both, and `/%2561dmin/`
denied by both — the PEP through `error_page 403`, the explanation as
`malformed_uri`.

Three things the run corrected or pinned down:

- **A deny reaches the browser as a 302, not a 403.** `protected.inc` maps
  `error_page 403 = @denied`, so the status a client sees for a refusal is a
  redirect to `/denied`. The harness therefore checks the redirect *target* as
  well as the code: a 302 to the login is a 401, a different answer entirely,
  and reading it as a deny would let a broken session pass the matrix while
  proving nothing.
- **`/admin%00` never reaches the PEP.** nginx answers it 400 itself, before
  `auth_request` runs, so it cannot corroborate anything and was dropped from
  the matrix. `policy.rs` covers it as a unit test.
- **The two can legitimately disagree for up to one cache TTL.** The PEP
  answers from a decision-cache entry (30 s, `cache::TTL`); explain reads the
  entitlement table directly. Immediately after a rule change the explanation
  is right and the PEP is stale, which is the intended direction — but an admin
  who deletes a deny, explains, and then tries the URL will see the old answer
  for up to half a minute. Documented rather than fixed: making explain read
  the cache would make it explain a decision that is about to stop being true.

Also confirmed on the lab: a portal user gets 403 (and still 403 while sending
`X-Auth-Groups: OpenBerat-Admins`, which the shared strip clears), a missing
`groups` is a 400 rather than a guess, a mistyped parameter name is a 400,
an unknown hostname is a 404, and three explains in a row wrote no `audit_event`
row — asking why cannot change the answer.

Harness: `verify-explain.sh` on the lab host. It clears the application and
entitlement tables before building its fixture and deletes both afterwards;
both were empty before the run and are empty after it.

### MEASURE — the kill switch, and the session it could not see

ADR-0016 promises **≤ 5 s** for the kill switch, and ADR-0019 is the four steps
that make it possible. Measured from the admin's `POST /api/admin/kill/{sub}`
to the first request the protected application refuses:

| | |
|---|---|
| `POST /api/admin/kill/{sub}` returns | **0.064 s** |
| Access gone (first non-200 from the application) | **0.085 s** |
| N-03 target | 5 s |

Two orders of magnitude of headroom, and it is not surprising: the four steps
are one Keycloak call, two Redis commands and an in-memory map deletion, and
none of them waits on a TTL. The number that would matter is the one this
replaces — without the index the same kill takes `cookie_refresh`, 300 s.

Each step was checked for the mark it should leave rather than inferred from
the end state, because three of the four are invisible from outside and a kill
switch that silently skips one still looks like it worked:

- **Keycloak `logout-all`:** following the portal to the end afterwards reaches
  a login **form**. Without this step the browser is redirected to a Keycloak
  that still holds the SSO session and signs the user straight back in with no
  password — the kill switch would look instantaneous and cut nothing.
- **The session keys:** `EXISTS` on the indexed `_oauth2_proxy-<hex>` key
  returns 0 afterwards.
- **The cache entries:** the next request is a 302 to `/denied`, on the first
  probe, rather than after the 30 s cache TTL.
- **The index entry:** gone, so nothing is left pointing at a session that no
  longer exists.

Refusals, on the same run: a `sub` that is not a UUID is a 400 before anything
is called (it is interpolated into an Admin API path), a portal user is 403, an
admin with no `Origin` is 403, and a `sub` no user has is a **404** — not a
503, which would send an operator mid-incident to look at a Keycloak that is
working.

**What the measurement found.** The first run killed a session that had opened
an application, and it worked. The second — a user who had signed in and stayed
on the portal — reported `{"sessions":0}` and cut nothing: `/api/me` still
answered 200 afterwards, and the applications would have opened for the next
five minutes, until `cookie_refresh` noticed the revoked refresh token. The
index was only ever written on a `/decide` miss, and **the portal does not go
through `/decide`** — its `auth_request` goes to `/oauth2/auth`, authentication
without a policy decision. Every user is in that state for the seconds between
signing in and clicking the first application, which is exactly when an admin
under incident response reaches for the kill switch.

Two changes closed it, and the second is why it was not simply a backend fix:

1. Every authenticated `/api` call records the session now, not only a
   `/decide` miss, and one whose session key cannot be derived is refused —
   the same answer `/decide` gives, for the same reason (ADR-0019: a session
   the kill switch cannot find must not carry access).
2. The portal's `/api/` location stops stripping the session cookie. Rule 16 in
   `nginx/conf.d/README.md` removes `_oauth2_proxy` from the `Cookie` header
   before proxying anywhere, and the session key is derived *from* that cookie,
   so with it gone the backend answered 503 rather than indexing anything. The
   exception is narrow and written out where it is made: this upstream is the
   PDP itself, and `/decide` already hands it the same cookie.

Re-measured after both: the portal-only session is indexed, the kill reports
one session, and `/api/me` answers 302 to the login afterwards.

Harness: `verify-kill.sh` and `verify-kill-gap.sh` on the lab host. Both create
their own application and entitlement through `/api/admin/*` and delete them
afterwards.

### TEST — the idle WebSocket that `proxy_read_timeout` does cut

The other half of the claim measured above.
[ADR-0016](adr/0016-n03-revocation-targets.md) keeps `proxy_read_timeout 300s`
because "it cuts idle connections, which is worth having and costs nothing" —
and only the half it does **not** cut had ever been run. Both halves run here at
once, on one vhost with one timeout and one cookie, so the contrast is the
result rather than two runs compared across two configurations.

Through the **committed** configuration, unlike the measurement above: the vhost
is generated from the `application` table
([ADR-0011](adr/0011-nginx-config-generation.md)) and its `location` includes
`protected.inc`, so the 300 s under test is the shipped value and not a
throwaway vhost repeating it. The upstream is the compose file's `sample-ws`
(`jmalloc/echo-server`). Both connections upgrade one second apart, `101` each.

| Connection | Sends | Outcome | nginx's own line |
|---|---|---|---|
| **idle** | nothing after the handshake | **dead at t+300.002 s** | `101 32b rt=300.002s urt=300.001` |
| **active** | one echo a second | **alive at t+420 s**, 420 exchanges | `101 3704b rt=420.052s urt=420.051` |

Three things the run makes concrete:

- **The clock starts at the last read from the upstream, not at the upgrade.**
  `echo-server` greets a new connection with one frame (`Request served by …`),
  the only unprompted thing it says, and the close landed 300.000 s after that
  frame — to the millisecond, which is why the number is this clean.
- **The access log is where an operator sees it afterwards.** nginx writes the
  line when the connection closes, so `rt=` is the connection's lifetime: 300 s
  for the silent one and 420 s for the talking one, on the same directive.
- **Being cut is not being denied.** The close is a TCP close; the client may
  reconnect at once, and the reconnect is an ordinary HTTP request that goes
  through `auth_request` and the decision path again. That is the whole value of
  the directive — for an idle connection it turns "authorised once, forever"
  into "re-authorised every 300 s at the latest".

**It bounds an idle connection; it does not bring it inside N-03.** The two
clocks run side by side rather than in series, so the ceiling is the sum:
a connection last read just before a group is removed is cut 300 s later, and
the reconnect at that moment is authorised against a session that can still be
330 s stale (the measurement above) — a second connection, cut 300 s after that
one. Arithmetic rather than a measurement, but it puts the worst case near
**630 s**, past the six minutes. ADR-0016 already excludes every upgraded
connection from the guarantee, idle ones included; this is why that exclusion is
not only about busy connections.

Harness: `verify-ws-idle.sh` and `wsclient.py` (which grew an interval argument;
`0` is the idle mode) on the lab host. It creates its own application and
entitlement through `/api/admin/*` and deletes them afterwards.

### TEST — logout, and the step that cannot be taken second

`docs/02` lists three logout steps and warns that skipping step 2 hands the next
login back without a password prompt. Two of the three are invisible from
outside, so each was checked for the mark it should leave rather than inferred
from the end state.

**Measured, on the committed configuration:**

| | |
|---|---|
| `POST /api/logout` returns | **0.066 s** (204) |
| Access gone (first non-200 from the application) | **0.084 s** |
| N-03 target for a user-initiated logout (ADR-0016) | 5 s |

- **The oauth2-proxy session:** `EXISTS` on the indexed `_oauth2_proxy-<hex>`
  key returns 0 afterwards.
- **The cache entries:** the next request to the application is a 302 to the
  portal on the *first* probe, not after the 30 s cache TTL.
- **The index:** only this browser's key is gone. The same user's second browser
  is still signed in **and still indexed** — a live session in no index is one
  the kill switch cannot find, which is what `SREM` rather than `DEL` buys.
- **The IdP session:** following the portal to the end afterwards reaches a
  login **form**.

**Two control runs, and they are the point of the section.** The design as first
written had the backend delete the oauth2-proxy session key and the browser walk
`/oauth2/sign_out` afterwards. Run in that order, the last check above came back
the other way — *no* login form, the user signed straight back in with no
password. The IdP session had survived its own logout.

The cause is an ordering the design did not see. Keycloak refuses to end a
session silently without an `id_token_hint`; without one it stops on a
confirmation page, which is a logout unfinished until a second click and
unfinished altogether if the tab is closed. The hint has to come from
oauth2-proxy, whose `backend_logout_url` calls `end_session_endpoint`
back-channel with the session's own `id_token` — and **that token lives inside
the session the backend had just deleted**. Deleting the key first leaves
oauth2-proxy nothing to log out with, and it says nothing about it.

So the sign-out became a call the backend makes, first, before its own DEL. The
second control is the one that shows the `backend_logout_url` line is load
bearing at all: with it removed, `/oauth2/sign_out` on a live session still
answered 302 and cleared the cookie, and the very next request to the portal
came back **signed in, with no password prompt** — `docs/02`'s "I logged out"
illusion, reproduced exactly.

The link's `href` is still `/oauth2/sign_out`, so a browser that never ran
`portal.js` loses only step 3: measured on its own, the link alone also reaches
a login form.

Refusals, on the same run: a missing `Origin` and a foreign one are both 403,
and neither reached oauth2-proxy — the session was still alive after both.

Harness: `verify-logout.sh` on the lab host. It creates its own application and
entitlement through `/api/admin/*` and deletes them afterwards, and signs
`labuser` in three times over: one session to lose, one to prove the other
browser survives, and one for the no-JavaScript fallback.

### MEASURE — deprovisioning re-measured, and the number that was the experiment's

[ADR-0016](adr/0016-n03-revocation-targets.md) makes Phase 6 repeat the Phase 1
measurement as an exit criterion, and the question it asks is narrow: did
anything Phases 2-5 added put a term into the revocation path? The candidate is
real. The kill switch ([ADR-0019](adr/0019-kill-switch-session-index.md)) writes
a `sub → session` index on every cache miss, and a miss is exactly the request
that reaches oauth2-proxy and triggers the refresh. Both runs of the Phase 1
harness were repeated against the current chain, on the same lab, with the same
`labuser` and the same generated `wiki` vhost.

**Ordinary case.** Session minted 19:03:12.40, the group out of AD at
19:03:42.86 — 30.4 s later, against Phase 1's 19.5 s.

| t (from the session) | event | answer |
|---|---|---|
| +0 s | session minted, `expires` 19:08:12.40 | 200 |
| +30.4 s | `samba-tool group removemembers` | — |
| +53 s | Keycloak asked for the user's groups | **empty** |
| +301.0 s | last request on the old membership | 200 |
| +303.0 s | `Refreshing session … SessionAge: 5m2.595s` | **302**, `deny="no_matching_grant"` |

150 answers of 200 then 120 of 302, and **10 consultations of `/oauth2/auth`
after the login flow's three, still exactly 30 s apart** — the cache TTL still
decides when the refresh is attempted, and the index write added nothing to the
grid.

**Ceiling.** Session minted 19:18:01.35, the group out of AD 11.3 s later; one
request at t+296 and silence before it.

| t | request | answer |
|---|---|---|
| +296 s | cache miss at session age 4 m 56 s, no refresh | 200 |
| +298 … +326 s | **16 hits, every one past the 19:23:01 boundary** | 200 |
| +328 s | cache miss, `Refreshing session … SessionAge: 5m27.653s` | **302** |

Phase 1 read `5m2.057s` and `5m27.187s` at the same two points, and cut at
t+302.7 and t+328.0. The repeat reads `5m2.595s` and `5m27.653s`, and cuts at
t+303.0 and t+328.0. **N-03 holds and nothing was added:** the ceiling is still
`cookie_refresh` + cache TTL = **330 s** against the target's 360 s, and it is
still reached rather than approached.

The repeat did settle one thing a single measurement could not. **283 s was
never a property of the system.** The cut lands at a fixed *session age*; how
long that takes to arrive after the AD change is that age minus however long the
change happened to fall after the session was minted. Phase 1 removed the group
at t+19.5 and measured 283.2 s; this run removed it at t+30.4 and measured
**272.6 s**, and the ceiling run removed it at t+11.3 and measured **316.7 s**
where Phase 1 measured 314.2 s. Four numbers spanning 44 s, describing identical
behaviour. The quantity to publish is the ceiling, which does not move: a change
landing in the same second as the mint waits the whole `cookie_refresh` + TTL,
and nothing waits longer.

Harness: `verify-n03.sh` on the lab host, unchanged, driven from the workstation
in both directions — the DC is on the other host. `labuser` was put back into
`OpenBerat-Finance` and the application and entitlement deleted afterwards; the
generated `apps.conf` is back to its header.

One thing the repeat needed that Phase 1 did not: **the Keycloak component ids
written down anywhere are stale by construction.** The realm is re-imported on
every `docker compose build keycloak` and H2 has no volume, so the LDAP provider
gets a fresh id each time — look it up by `type` rather than by a recorded id.
Its `cachePolicy` was still `NO_CACHE`, which is what keeps the directory's own
contribution zero.

### One real application — Jenkins behind the proxy, and the port that makes it optional

The lab's `sample-app` is `traefik/whoami`: it proves the `X-Auth-*` headers
arrive, not that anything consumes them, and the product's whole promise is the
step after arrival. So a real one was put behind the proxy — **Jenkins
2.555.1-lts, on its own host**, reached across the LAN rather than from the
compose network, which is the awkward case and therefore the honest one.

On the OpenBerat side the integration is **one `application` row** (slug
`jenkins`, `upstream_url` `http://<host>:8080`, hostname
`jenkins.apps.example.local` — `validate_upstream` accepts a plain private IP)
and **one `entitlement`** (`OpenBerat-Finance`, allow). No code, no migration,
no configuration file. On the Jenkins side, `reverse-proxy-auth-plugin`, a
security realm that reads `X-Auth-Username` and `X-Auth-Groups` (delimiter `,`),
and full-control-once-logged-in with anonymous read denied — the recipe is in
`INSTALL.md` §8.

| Request | Result |
|---|---|
| `labuser` logs in **once** at the portal, then `GET https://jenkins.apps.example.local/` with that session cookie and nothing else | **200**, and `j_username` appears **0** times in the body — no login form, no second password |
| the same session against `/whoAmI/api/json` | `name: labuser`, `authenticated: true`, authorities include `OpenBerat-Finance` |
| no cookie at all | **302** to `auth.apps.example.local/realms/openberat/protocol/openid-connect/auth` |
| **`X-Auth-Username: labadmin` + `X-Auth-Groups: OpenBerat-Admins`, sent straight to the published port from an unrelated host on the LAN** | **200**, `name: labadmin`, `authorities: [… OpenBerat-Admins]` |

Then the rule from `INSTALL.md` §7 went on the application host — one line in
`DOCKER-USER`, allowing the PEP's address and dropping the rest — and the same
four requests were repeated:

| Request, after the rule | Result |
|---|---|
| the forged header from an unrelated LAN host | **no answer**: the packet is dropped, `curl` times out at 8 s |
| the forged header **from the PEP host**, the one address allowed | 200 — the rule is a source filter, not a fix to the application |
| `labuser` through the proxy | **200**, `whoAmI` = `labuser`, unchanged |
| the Jenkins build agent, which reaches the controller container-to-container | still connected — the rule matches on the LAN interface, so traffic on the Docker bridge never meets it |

The second row is the point: nothing about the application changed, and nothing
could. The mechanism's security is the source filter, which is why
[ADR-0021](adr/0021-application-identity-trusted-headers.md) makes it a
requirement and `INSTALL.md` hands the operator the forged request to test it
with.

**The first table's last row is what the mechanism costs.** No cookie, no session, no contact
with the proxy — a header and a reachable port are the whole authentication.
`denyAnonymousReadAccess` does not close it, because the forged request is not
anonymous: it authenticates. This is why
[ADR-0021](adr/0021-application-identity-trusted-headers.md) makes isolating the
upstream a requirement rather than a deployment default, and why `docs/06`'s
"can upstreams be reached bypassing nginx?" no longer has three answers to pick
from.

#### Two users, one browser — the application's session does not win

The open question this settles attributed shared-browser identity confusion to
the *other* mechanism, the application running its own OIDC. The test asks
whether trusted headers have it too: user A visits and the application mints its
own cookie; user B then logs in on the same browser and the request carries B's
OpenBerat session together with **A's** `JSESSIONID`.

| Request | Served as |
|---|---|
| A's session, first visit | `labuser` |
| B's session, own visit | `labadmin` |
| **B's session + A's application cookie** | **`labadmin`** |
| A's application cookie alone, no OpenBerat session | **302** to login |

The header is read per request and wins over the application's own session, and
the application's cookie is worth nothing without ours because every request
passes the gate first. Both users were genuinely entitled for the duration —
`labadmin` was given a second `entitlement` on the same application and it was
deleted afterwards, which is also why the third row's authorities legitimately
list both groups.

#### What arrives is not the AD group list

Measured on the way past: `labuser`'s token carries `groups:
["OpenBerat-Finance"]`, and what leaves oauth2-proxy — into `/api/me`, into the
backend's matching, and into the application — is seven names:

```
OpenBerat-Finance, role:default-roles-openberat, role:offline_access,
role:uma_authorization, role:account:manage-account,
role:account:manage-account-links, role:account:view-profile
```

The `keycloak-oidc` provider appends Keycloak realm and client roles with a
`role:` prefix. It grants nothing here — `ADMIN_GROUP` is matched by exact name
and no `role:…` string can equal it — but an application mapping
`X-Auth-Groups` onto its own permissions is being handed six names its AD
administrator never granted.

#### Three traps worth writing down

- In 2.555.1 the deny-anonymous setter is `setAllowAnonymousRead(false)`, **not**
  `setDenyAnonymousReadAccess(true)`, and there is no matching getter. The wrong
  name throws `MissingMethodException` mid-script — and because
  `setSecurityRealm` saves on its own, the realm survives while the
  authorization half silently does not.
- `init.groovy.d` mounted at `/usr/share/jenkins/ref/` is **seed-once**: the copy
  into `$JENKINS_HOME` is skipped when the target exists, so an edit to the
  mounted file changes nothing. Edit the runtime copy.
- The container's `docker logs` was frozen weeks in the past on a stale
  json-file, so the script logs to a file under `$JENKINS_HOME` instead. A boot
  script that reports nothing is indistinguishable from one that did not run.

Harness: `verify-appidentity.sh` on the lab host (the two-users test, including
the grant and its cleanup). The application and entitlement rows are left in
place — this one is meant to keep running.

### Security headers and the TLS floor — what the stack served before, and after

Two of the three parts of this box were already right and one was wrong in a way
no configuration review would have caught.

**The TLS floor.** Probed against a bare `nginx:1.29-alpine` with nothing but a
certificate configured, because the question is about the base image and not
about this product. A client forced down to an old version, and then one cipher
at a time:

| offered | stock image | with `tls.inc` |
|---|---|---|
| TLS 1.0, TLS 1.1 | refused (`alert protocol version`) | refused |
| TLS 1.2, TLS 1.3 | negotiated | negotiated |
| `AES128-SHA` — RSA key exchange, **no forward secrecy** | **accepted** | refused |
| `ECDHE-RSA-AES128-SHA` — CBC/SHA1 | **accepted** | refused |
| `ECDHE-RSA-AES256-GCM-SHA384` | accepted | accepted |

So `ssl_protocols TLSv1.2 TLSv1.3` changes nothing today — the first probe of
this pair was misread as "TLS 1.0 accepted" until the detector was corrected to
look at the negotiated cipher rather than at the `Protocol:` line, which
`s_client` prints for a handshake that failed too. It is written anyway, because
the floor should belong to this configuration rather than to whatever the base
image's OpenSSL defaults to next year. `ssl_ciphers EECDH+AESGCM:EECDH+CHACHA20`
is the line that does something: without it a recorded session is decryptable by
anyone who later obtains the private key, and what travels on it is a cookie
valid for every host on `.apps.<domain>` (ADR-0015).

**The headers, per kind of response.** Read off the running lab, one request per
row, `nosniff` and `Strict-Transport-Security` omitted because every row has
them:

| response | CSP | `X-Frame-Options` | `Referrer-Policy` |
|---|---|---|---|
| portal `/`, authenticated 200 | ours | `DENY` | ours |
| portal `/denied` | ours | `DENY` | ours |
| portal `/api/me` | — | — | — |
| portal `/`, no cookie → 302 to login | — | — | — |
| Jenkins, authenticated 200 | **Jenkins's own**, report-only | `sameorigin` (its own) | `same-origin` (its own) |
| Jenkins, no cookie → 302 | — | — | — |
| Keycloak `/realms/…` | — | `SAMEORIGIN` (its own) | `no-referrer` (its own) |
| unknown host → default server 404 | — | — | — |

**The one that was wrong.** The first version of `security.inc` set
`Referrer-Policy` at http level, and the lab immediately showed why that is a
mistake: Keycloak sends `no-referrer`, Jenkins sends `same-origin`, and nginx
*appends* rather than replaces. A duplicated `X-Content-Type-Options` is
harmless — the browser splits the joined value and reads the first token, which
is `nosniff` either way — but a duplicated `Referrer-Policy` is not: the last
valid value wins, so the proxy's `strict-origin-when-cross-origin` would have
**relaxed** the login host and every application that had already made a
stricter choice. It is set on the portal's own HTML only, where nothing upstream
has an opinion; everywhere else the browsers' own default is that same value
already. `nginx/conf.d/README.md` rules 19 and 20 are this paragraph.

The CSP measured earlier in this document was delivered as a `<meta>` tag, since
the question then was whether Alpine survives one. It is a real header now, and
it sits on `location /` rather than on the portal `server`: `/oauth2/` is
oauth2-proxy's own pages and a protected application is somebody else's, and
`default-src 'self'` would break both.

The generated application block (ADR-0011) no longer carries a copy of the
certificate — one wildcard serves every host, so it is set once at http level in
`tls.inc`. Verified by deleting the two lines from the block installed on the
lab, reloading, and fetching Jenkins over TLS: 200, 129838 bytes.

### MEASURE — renewing the wildcard certificate under a running stack

The certificate is mounted, never baked (`nginx/Dockerfile`), so the question is
what an operator has to do beyond replacing two files. Measured by generating a
second self-signed wildcard with the same subject and SAN and swapping it in.
Every verdict below is `GET /api/me` with a freshly minted session, for a reason
given at the end.

| step | result |
|---|---|
| new files written, no reload | nginx still serves the **old** serial |
| `nginx -s reload` | serves the new serial |
| 400 requests spanning the reload | **400 × 200, no failure** |
| login, oauth2-proxy untouched | **broken** — `/api/me` → 302 |
| `docker compose restart oauth2-proxy` | `/api/me` → 200 |
| an **existing** session across that restart | 200, on the portal and on Jenkins |

The failure in the fourth row is the whole finding, and it is specific to a
self-signed deployment: `docker-compose.yml` mounts `certs/wildcard.crt` into
oauth2-proxy as `provider_ca_files`, because the issuer is reached over HTTPS
and the lab's leaf is its own trust anchor. oauth2-proxy reads that file once, at
startup, so after the swap it is validating a new leaf against the old one:

```
Error redeeming code during OAuth2 callback: token exchange failed:
  Post "https://auth.apps.example.local/realms/openberat/protocol/openid-connect/token":
  tls: failed to verify certificate: x509: certificate signed by unknown authority
```

Nothing else in the chain cares. Sessions are in Redis, so the restart costs
under a second and no signed-in user notices; only a login in flight fails.

One trap ruled out rather than inherited: it does not matter whether the new
file is written **over** the old one or **replaces** it. `certs/` is a directory
mount for nginx, and oauth2-proxy's single-file mount is re-resolved when the
container starts — measured both ways, `cp` and `mv`, and a plain
`docker compose restart` was enough for both. No `--force-recreate` is needed.

**Why every verdict here is `/api/me` and not the harness's exit code.** The
first run of this experiment reported that login still worked after the swap. It
did not. `ob-login.sh` walks the browser flow with curl and exits 0 as long as
each request answers, and the OAuth callback answered — with a 500. A harness
that reports success on a failed login would have put the wrong procedure into
`INSTALL.md`; the failure only surfaced when the session it produced was asked
to do something.

### MEASURE — backup and restore, and the `--clean` that cannot restore in place

The state worth backing up is one Postgres database; everything else on the host
is either derived or in the repository (`INSTALL.md` §9). So the procedure is a
`pg_dump` and a `psql`, and the only question was whether it actually brings a
system back. Rehearsed three ways on the lab, against Jenkins as the protected
application.

| run | what was destroyed | restore | application answering again |
|---|---|---|---|
| in place, first attempt | nothing; the stack kept running | **failed** | — |
| in place | nothing; the stack kept running | **1.0 s** including `stop`/`start backend` | immediately, 200 |
| bare host | both containers **and** both volumes | 3.4 s, postgres started from an empty volume | **59 s**, 200 |

The dump is 0.3 s and 32 KB for one application, one entitlement and 86 audit
rows.

**The failed run is the finding, and it is the run against a database that
already had the schema.** The first procedure written down took the dump with
`pg_dump --clean --if-exists`, on the reasoning that one command would then
restore onto an empty database *and* over a live one. It does the first and not
the second:

```
ERROR:  cannot drop inherited constraint "audit_event_default_pkey"
        of relation "audit_event_default"
```

`audit_event` is partitioned by month and `audit_event_default` inherits its
primary key (`0001_init.sql`), so the `DROP CONSTRAINT` a `--clean` dump emits
is one Postgres refuses on a partition. It stops before loading a row —
`ON_ERROR_STOP=1` is what makes that a stopped restore instead of a half-loaded
database, which is the failure that would have been discovered a year later
with a wrong answer to "who could reach what". The procedure now empties the
schema itself (`drop schema public cascade`) and dumps without `--clean`, which
is one command more and works on both a running database and an empty one.

**The 59 s is not the restore.** The restore is 3.4 s of it; the rest is
Keycloak importing its realm and oauth2-proxy retrying discovery until it
answers (`INSTALL.md` §5). Nothing in that path is ours, and it is the same 25-60 s
any `docker compose up` on this stack costs.

**What made the restore complete without an admin.** Before this box the
generated nginx blocks were written only by a mutation handler, so a database
restored into an empty `apps_conf` volume gave every application a hostname
nginx had never heard of. The backend now renders the file at startup as well
(ADR-0011) — measured separately by deleting `apps.conf`, restarting nginx and
watching the request fail at the TLS handshake with no `server` block to match
it (`curl` exit 35), then restarting the backend: the file was back and the
application answered 200 **2.9 s later, restart included**. It is the same
2 s poll the reloader already ran (`nginx/docker-entrypoint.d/40-generated-reload.sh`).

**Keeping the audit rows aside needs a `*`.** The rollback procedure dumps
`audit_event` before overwriting it, and `pg_dump -a -t audit_event` produces a
file with **none** of the rows in it: the table is partitioned, every row is in
`audit_event_default`, and `-t` on the parent does not follow partitions. It
exits 0 and says nothing. `-t 'audit_event*'` gets them all.

**Rolling back is restoring, because the old binary will not start.** Asserted
in `backend/tests/integration.rs` rather than assumed: with a version in
`_sqlx_migrations` that the running build does not carry, `store::connect`
returns `migration 2 was previously applied but is missing in the resolved
migrations` and the process exits. There is no down migration to reach for —
the way back to the previous version is the dump taken before the upgrade.

### TEST — audit retention, and the month that could not be partitioned

[ADR-0022](adr/0022-audit-retention.md) answers N-04 as a mechanism rather than
a number: the operator sets `AUDIT_RETENTION_MONTHS`, the backend creates the
current and next month's partitions on a daily tick, and an expired month leaves
as a `drop table`. Run against the lab stack, with the default 12 months, after
planting an expired month **with** a partition of its own and an expired row
**without** one:

| | Before | After one startup tick |
|---|---|---|
| Partitions | `audit_event_2020_01`, `audit_event_default` | `audit_event_2026_10`, `audit_event_default` |
| Probe rows | 2 (one in the old partition, one in the default) | **0** |
| Live rows in the default partition | 91 | **91**, untouched |

```
INFO openberat::store: audit retention: everything before 2025-09-01 removed
                       partitions=["audit_event_2020_01"] stray_rows=1
```

**The month that is missing from that table is the result.** `audit_event_2026_09`
was not created, and the reason is the one the ADR is built around:

```
WARN openberat::store: cannot create the audit partition month=2026-09-01
  error=updated partition constraint for default partition "audit_event_default"
        would be violated by some row
```

Every row this lab has ever written is in the default partition, so Postgres
cannot carve September out from under them. Treating that as an error to return
would have skipped the expiry — the half with data to delete — so it is logged
and the run continues. October, which has no rows yet, is created normally, and
from next month on every row is partitioned. The same is true of any
installation upgrading into this: one month stays in the default partition and
expires there on the same cutoff as everyone else.

`AUDIT_RETENTION_MONTHS=0` stops the backend at startup —
*"must be a whole number of months, 1 or more"* — rather than being read as
"keep nothing". It is the only background task in the product that deletes, so
it is the one variable where a typo is fatal rather than defaulted.

### TEST — one page load, two login flows, one CSRF cookie

Reported from the lab as a 403 on the OAuth callback: *"Unable to find a valid
CSRF token"*, where going back and signing in again worked. oauth2-proxy's own
dump of the failing request shows the browser sent **no `Cookie` header at
all**, and the flow that succeeded a second later was a different one — its
`state` carried `.../favicon.ico` as the return address, not `/`.

The cause is that **a single page load starts more than one login flow**.
Anything that 401s goes to `@signin` -> `/oauth2/start`, and each start mints a
CSRF cookie holding that flow's PKCE verifier. With one cookie name for all of
them the second start overwrites the first, and one browser cannot finish two
flows. Reproduced with curl in one cookie jar — the document and the favicon
beside it, then the password typed on the document's flow:

| `cookie_csrf_per_request` | CSRF cookies in the jar after two starts | The document's login | `/api/me` |
|---|---|---|---|
| `false` (the default) | **1** | **500** | 302, still anonymous |
| `true` | **2** | **200** | **200** |

Both of the user-visible failures come from the same overwrite, and which one
appears is a race:

- the callback finds the **other flow's** cookie, so the code is redeemed with
  the wrong PKCE verifier and Keycloak answers `invalid_grant "Code not valid"`
  -> **500**. This is what the reproduction above hits every time.
- the other flow's callback wins first and **clears** the shared cookie, so the
  loser arrives with nothing -> **403**, the message the report started from.

The setting exists in oauth2-proxy 7.8.2 (`--cookie-csrf-per-request`) and names
the cookie `_oauth2_proxy_<nonce>_csrf`, one per flow. There is no
`cookie_csrf_per_request_limit` in this version, so the bound on how many such
cookies a browser accumulates is their 15 minute `cookie_csrf_expire` alone.

Our own pages are not what triggers it — `index.html`, `denied.html` and
`unavailable.html` all declare `<link rel="icon" href="/logo.svg">`, so the
second flow comes from a page that is not ours: oauth2-proxy's own error page
and Keycloak's login page have no icon link. Serving `/favicon.ico` anonymously
would remove that one instance; it does not remove the class, which is why the
fix is the cookie name and not the favicon.

**The same message has a second, entirely benign cause: a pasted authorize
URL.** Reported again on 2026-09-07, and reproduced from both sides. The user
had pasted
`https://auth.apps.example.local/realms/openberat/protocol/openid-connect/auth?...&state=...`
into the address bar — oauth2-proxy's own dump names it: `Sec-Fetch-Site: none`,
which is what a typed or pasted URL looks like, and
`approval_prompt=force`, which oauth2-proxy adds at `/oauth2/start`, so the URL
was copied out of an earlier flow's redirect. Keycloak had a live SSO session,
redirected straight to the callback with a fresh code, and oauth2-proxy answered:

```
AuthFailure Invalid authentication via OAuth2: unable to obtain CSRF cookie:
  CSRF cookie with name '_oauth2_proxy_-IqX6rDd_csrf' was not found
```

That is `cookie_csrf_per_request = true` behaving exactly as the section above
asks it to: the cookie is named after the `state`, and a `state` the browser
never received from `/oauth2/start` has no cookie to match. Skipping
`/oauth2/start` skips the step that sets it, so the callback is a login attempt
for a flow this browser never began — refused, fail-closed. **The entry point is
`https://portal.apps.example.local/`, never the authorize URL.** Reproduced with
curl against a jar holding a valid session and no CSRF cookie: 403, same
message, `csrf cookies in jar = 0`, while `ob-login.sh` starting at the portal in
the same minute reached `api/me` 200.

Worth keeping apart, because the two causes look identical from the browser and
only one is a bug: **no `Cookie` header at all** is the concurrent-flow race
above; **cookies present but none matching the state** is either a pasted URL or
a `state` older than the CSRF cookie's expiry.

### MEASURE — `/metrics`, and what a decision actually costs on the finished chain

The Phase 6 monitoring box, run against the lab stack with `verify-metrics.sh`
(on the lab host). Five requests through the whole chain — nginx `auth_request`
-> `/decide` -> oauth2-proxy -> Postgres — then four more spaced 31 s apart, one
second past the 30 s decision cache TTL, so each of those is a miss. The
exposition is scraped from inside the `core` network before and after, and every
number below is a delta.

**The counters move by exactly what the traffic did**, which is the assertion —
a counter that is merely present tells you nothing:

| Series | Traffic | Delta |
|---|---|---|
| `decision_total{decision="allow"}` | three requests to an entitled application | 3 |
| `decision_total{decision="deny",reason="malformed_uri"}` | one `/%2561dmin/` | 1 |
| `decision_total{decision="unauthenticated"}` | one request with no cookie | 1 |
| `decision_cache_total{result="hit"}` | the second and third, plus the refusal | 3 |
| `decision_cache_total{result="miss"}` | the first | 1 |
| `decision_duration_seconds_count` | all five | 5 |
| `audit_dropped_total` | — | 0 |

The latency, read off the histogram buckets rather than averaged, against
N-01 (2 ms on a cache hit) and N-02 (10 ms on a miss):

| What the request was | n | Where it landed |
|---|---|---|
| Cache hit | 3 | **≤ 0.25 ms**, all three |
| Cache miss, warm | 5 | 4 at **≤ 2 ms**, one at ≤ 5 ms |
| No session at all — 401, then the login redirect | 1 | ≤ 1 ms |
| Cache miss, **first request after a restart** | 1 | ≤ 10 ms |

That last row is the one worth keeping. It is the same code as the row above it;
what it pays for is the first Postgres connection and the first HTTP connection
to oauth2-proxy, and it is the only measurement in this set that comes near
N-02. A load test that opens with a cold pool will read the whole product as
slower than it is — and one that discards its first sample will miss the only
moment a real deployment is slow. Neither figure is a load result: this is one
user, one application, no concurrency. N-01 and N-02 are fixed under load in the
box after this one.

Three things the run got wrong before it got them right, all three in the
harness rather than in the product, and all three the same mistake — reading a
status code where the answer is somewhere else:

- **A denial is a 302, not a 403.** `error_page 403` sends the browser to the
  portal's `/denied` page, which lives on another host, so nginx cannot serve it
  internally (`errors.inc`, README rule 7). The counter had already recorded
  `malformed_uri` while the harness was calling it a failure. What distinguishes
  a denial from a login redirect at the client is the `Location`, not the status.
- **`/metrics` on the portal answers 200.** The portal's `location /` falls back
  to `index.html` for anything it has no file for, so the interesting question is
  not the status but the body — and the body is the portal page. Nothing proxies
  `/metrics` to the backend: the only path to it is the `core` network.
- **The first read of `audit_dropped_total` returned `Postgres.`** — the word at
  the end of its own `# HELP` line. Grepping an exposition for a series name
  matches the comments too.

The exposition names nobody. Checked for the username, the application slug, the
hostname and both address ranges the lab uses: none appear, because the only
labels in it are `decision`, `reason`, `result` and `le`.

### TEST — installing the release bundle on a host with no images

ADR-0023 makes the release one tarball: `git archive` of the tag plus
`docker save` of every image the release compose references. `release.sh`
produced **420 MB** compressed for 0.1.0, and `verify-airgap.sh` (on the lab
host) installed it the way an air-gapped site would — after deleting every image
the bundle claims to carry, so nothing on the host could stand in for a missing
one.

| Step | Result |
|---|---|
| `docker compose config --images` | six: our three built images and `postgres:17-alpine`, `redis:7-alpine`, `oauth2-proxy:v7.8.2`. The lab directory and the sample applications are behind `--profile lab` and do not appear |
| Secrets in the bundle | none — no `.env`, no private key. It carries what `git archive` carries |
| `docker compose create --pull never`, images deleted | refuses: `No such image: redis:7-alpine` |
| `docker load -i images.tar` | all six |
| `docker compose up -d --pull never` | the six containers start |
| Backend answering `/readyz` | **33 s** after `docker load` began |
| Portal redirecting to the IdP | **88 s** |
| A real login, then the protected application | `/api/me` 200, Jenkins 200 |
| `openberat_build_info` | `version="0.1.0"`, and the same string in the backend's first log line |

**The gap between 33 s and 88 s is the finding.** `/readyz` reports Postgres
and Redis and deliberately says nothing about oauth2-proxy (`docs/02`), which
performs OIDC discovery once at startup and exits until Keycloak answers. So for
most of a minute the backend is ready, every container is *up*, and the portal
answers **500**. The first run of this test called that a failure — it waited on
`/readyz`, logged in immediately and got a 500 — which is the same shape as the
certificate-renewal run that reported success on a login that had 500'd. On a
first install the signal that the stack is usable is the portal answering 302,
not any container being up.

Nothing here proves the *host* had no network; `--pull never` is what proves the
bundle was complete, because with the images deleted it is an error naming the
missing image rather than a download that succeeds quietly. That distinction is
why the flag is in `INSTALL.md` §11 rather than a bare `up -d`.

Two things the bundle deliberately does not solve. It freezes the third-party
images **by content** while their tags stay mutable, so two bundles built a
month apart can differ — inside one bundle nothing drifts, which is the property
the offline site needs. And the certificate, `.env` and any lab override are the
operator's: the test copies them in from the existing installation, which is
exactly the manual step §11 describes.

### TEST — a licence header, and the migration that would not take one

ADR-0013 asks for a notice in every file and for Alpine.js's MIT notice to be
preserved. Both were done in one sweep — 41 files, two lines each — and the
sweep passed `cargo fmt`, `clippy`, the whole test suite and the nginx and
frontend CI checks. Deployed to the lab, **the backend would not start**:

```
ERROR openberat: cannot connect or apply migrations, refusing to start:
                 migration 1 was previously applied but has been modified
```

`sqlx::migrate!` stores a **checksum of every migration file** in
`_sqlx_migrations` and compares it on each start. Two comment lines at the top
of `0001_init.sql` change that checksum, so the file is a different migration as
far as the migrator is concerned — and the correct response to "the schema is
not the one I was built against" is to refuse, which is what happened. A comment
is not a comment in that directory; it is a schema change nobody wrote.

**The local test suite could not have caught it**, and that is the point worth
keeping. `decide_section` and the schema test both begin with
`drop schema public cascade`, so every local run applies migration 1 to an empty
database and records the new checksum as if it had always been that one. Only an
installation that had *already* applied the old file can see the difference,
which is exactly what the lab is. The same shape will hold for any future change
to an applied migration.

| | Before | After |
|---|---|---|
| `cargo test`, locally | 34 unit + 1 integration, all passing | the same, all passing |
| The lab backend | up | `Restarting (1)` in a loop, `/decide` unreachable |
| A protected application | 200 | 500 — nginx has no `auth_request` to ask |

Fixed by leaving `backend/migrations/` out of the sweep, and the CI job now
fails a migration that *gains* a header rather than one that lacks it. The rule
is in `CONTRIBUTING.md`: an applied migration is immutable byte for byte, and
new schema goes in a new file.

With that reverted, the rest holds on the live stack: `nginx -t` accepts every
`.conf` and `.inc` with its new header, the login theme still pulls
`css/openberat.css` (a comment in `theme.properties` would have failed silently
by falling back to the stock sheet), and both notices arrive at a browser — the
portal page carries its own, and `/vendor/alpine.js` opens with the MIT banner.
That last one is why the banner is in the file rather than only in the vendor
README: the file is distributed to every visitor, and a notice in a README is
not attached to the copy they receive.

Two runs of the verification failed on a stopwatch rather than on the change.
Rebuilding restarts three clocks the login needs — the backend re-applies
migrations, Keycloak re-imports the realm and drops every session, and
oauth2-proxy exits and restarts until discovery answers — and waiting on the
portal alone reports a broken login that is only an early one.

### TEST — `INSTALL.md` §6, run as written

The section told an operator that applications are defined "through the admin
API" and then never showed a call, so an installation could be finished and
still have nothing behind it. The calls are in the document now, and
`verify-install6.sh` (on the lab host) runs the section literally — the cookie
copied out of a jar the way the text says to copy it out of the browser, and a
throwaway application removed at the end.

| What the section claims | Result |
|---|---|
| A state-changing call without `Origin` is refused | **403**, nothing created |
| `upstream_url` naming infrastructure is a 400 with a reason | `{"error":"upstream_url names an infrastructure port"}` for `http://postgres:5432` |
| The create answers 201 with `"nginx":"staged"` | yes, and the block reaches nginx |
| No rule means deny | the new host answers **302 to `/denied`** before any entitlement — a refusal is a redirect, not a 403 (`errors.inc`) |
| One `ad_group` entitlement makes it reachable | 200 |
| `explain` agrees with the PEP, and needs `groups` | `"decision":"allow"`; without `groups`, **400** rather than a guess |
| `DELETE` cleans up | **200** with the same `nginx` field, and a second one is 404 |

Two corrections came out of running it rather than reading it. `DELETE` answers
**200 with a body**, not 204 — the body carries the nginx publish status, which
is the thing an admin needs after removing an application, and the first draft
of this harness asserted 204. And the guard that answers 403 without an `Origin`
is worth stating in the install document rather than only in `docs/02`: a
curl-driven admin session hits it immediately, and the failure looks like a
permissions problem.

**Re-run on 2026-09-07 for [ADR-0024](adr/0024-no-admin-ui-in-v1.md), which
rests on this section being an interface and not a promise.** Every row above
still holds, `ALL OK`, against the same lab. That matters more now than when it
was first written: with no admin screens, §6 is not documentation *of* the
management interface, it *is* the management interface, so a regression in any
of these rows breaks administering the product rather than one page of a guide.

### MEASURE — the decision under load, and the thing that runs out first

The Phase 6 load test (`verify-load.sh` and `verify-load2.sh`, on the lab host).
The load goes at a throwaway application in front of the `whoami` container on
the compose network rather than at Jenkins across the LAN — with a slow upstream
the run measures the upstream. Each worker is one `curl` process holding one
HTTP/1.1 connection, so *c* processes are *c* concurrent decisions; HTTP/2 would
multiplex and that would stop being true. Every latency below is the backend's
own histogram read before and after the run, so it is the decision and not the
TLS handshake in front of it.

**The host is the caveat and it is a large one.** Two vCPU and 2 GB, with
Postgres, Redis, Keycloak, oauth2-proxy, nginx, the backend, the sample
application *and* the load generator all on it. Nothing here is a capacity
figure for a real deployment.

**N-01, the cache hit, holds — and not narrowly.** The decision is tens of
microseconds at every concurrency the host could produce:

| Concurrent connections | 1 | 4 | 8 | 16 | 32 | 64 |
|---|---|---|---|---|---|---|
| Mean decision | 11 µs | 14 µs | 18 µs | 19 µs | 21 µs | 29 µs |
| Under N-01's 2 ms | 100% | 100% | 100% | 100% | 100% | 99.8% |

Sustained, the same shape: 19 200 requests at 32 connections, **750 r/s, every
one a 200**, 16 540 decisions at a 25 µs mean and 99.9% under 2 ms.

**N-02, the cache miss, holds too.** A cache key is `(cookie, slug)`, so sixteen
sessions on one application are sixteen misses; the entry lives 30 s, so the same
sessions are a fresh set every 32 s:

| Concurrent first visits | 1 | 2 | 4 | 8 | 16 |
|---|---|---|---|---|---|
| Mean | 2.66 ms | 4.33 ms | 4.67 ms | 3.73 ms | 3.08 ms |
| Under N-02's 10 ms | 1/1 | 2/2 | 4/4 | 8/8 | 16/16 |

**Thirty-one out of thirty-one.** The mean does not climb with concurrency
because what a miss waits on — the oauth2-proxy round trip, the Redis index
write, the entitlement query — is not CPU the decision is competing for.

**What runs out is nginx, not the decision.** At 32 connections, sampled mid-run:

| Container | CPU | Memory |
|---|---|---|
| nginx | **138%** | 14 MB |
| sample-app (the upstream) | 17% | 12 MB |
| **backend** | **11%** | **2 MB** |
| oauth2-proxy, Postgres, Redis | ≈0% | 19 / 32 / 5 MB |
| Keycloak | 0.13% | **563 MB** |

Of two cores, TLS and proxying take one and a third and the authorisation
decision takes a tenth of one. The right conclusion is not "the backend is
fast"; it is that **on this shape of host the decision is roughly one per cent
of what serving the request costs**, so tuning it further buys nothing and the
first instance to add under load is nginx, not the backend.

**The first ceiling a real user meets is neither.** Run against the stack as it
ships, from one address, 400 requests at 4 connections produced **32 answers and
368 × 429**: `00-auth.conf` allows 50 r/s per address with a burst of 100, and
nginx refuses the rest before `/decide` is ever consulted — the backend recorded
32 decisions for 400 requests. The limiter does its job perfectly. Whether 50 is
the right number is N-07's question and is still open (`docs/06`); the case that
decides it is a site behind NAT, where one address is an entire office and fifty
people at one request a second are already at the limit.

Two measurements had to be thrown away, both for the same reason — **the load
generator and the instrumentation are on the two cores under test**. A 50 s run
sampled with `docker stats` reported 383 r/s and 2 660 responses that were
neither 200 nor 429; repeated without the sampler it was 750 r/s and 19 200 ×
200. And the miss path first read a 17.6 ms mean, measured immediately after
that saturation run: repeated on a quiet host it is 2.7–4.7 ms, and the load
average falling from 2.47 to 0.59 across the sweep is visible in the means.
Neither figure was a property of the product.

### TEST — port 80, which four documents said redirected and nothing published

`nginx/conf.d/openberat.conf` carries a `listen 80` server that answers
`301 https://$host$request_uri`, and its own comment says the port "is not
published on the host". Four places said otherwise: both README mermaid
diagrams and the README port table (`443 (80 redirects to it)`) and the
`docs/02` deployment diagram (`:80 redirects to :443`). `docker compose config`
renders one published port, `443`.

Both halves run against the `openberat-nginx` image rather than reasoned about:

| Case | Result |
|---|---|
| The image run with `-p 18080:80` | `HTTP/1.1 301 Moved Permanently` |
| Nothing bound to the port | `curl: (7) Failed to connect ... Could not connect to server` |

So the redirect works and is unreachable — the block is correct and the
publication is missing, which is why nobody noticed. **What an operator meets
is a refused connection**, not a redirect, the first time a user types a
hostname and the browser tries HTTP. The documents now say that, and
`INSTALL.md` §2 names the one-line change (`"80:80"` in the nginx `ports:`) for
an operator who wants the redirect. Publishing it by default was not decided
here: it widens the only published surface the design currently claims, which
is the operator's call and not a documentation fix.

### TEST — the deny rule that was accepted and could never fire

`policy::normalise` percent-decodes the request path and folds `\` into `/`.
`matches` does neither to the stored `path_pattern` — it resolves `.`/`..` and
lower-cases, and that is all. The two sides were therefore not normalised the
same way, and `create_entitlement` checked only that the pattern was empty or
began with `/`.

Proven twice, and the chain test below is the one that matters.

**What the rule does, asked of the whole chain** (`verify-deadrule.sh`, on the
lab). The row goes in under the API, straight into Postgres, so this measures
the rule rather than the guard in front of it — one application (`jenkins`),
one `allow` for `OpenBerat-Finance`, and `GET /admin/` as `labuser` after each
change plus a cache TTL:

| Deny rule in the table | `/admin/` answers |
|---|---|
| none | **404** — the PEP allowed it, Jenkins answered |
| `/%61dmin/*` | **404** — identical. The rule never fired |
| `/admin/*` | **302** to `/denied?app=jenkins.apps.example.local` |

A deny rule the matcher cannot meet is not weaker than a working one, it is
**indistinguishable from having written no rule at all**.

**And that the guard now refuses it** (`verify-pattern.sh`, same host, as
`labadmin`): `/%61dmin/*`, `/x\admin/*`, `/ADMIN/*`, `/x/../admin/*`, `/a//b`
and `/adm*n/*` all come back **400**, each naming the form it wanted
(`path_pattern must be written the way it is matched: /admin/`), while
`/admin/*` still answers 201 and deletes cleanly.

The same shape at the unit level, by taking the guard out and running the
integration test against Postgres:

| Pattern, `effect: deny` | Without the guard | With it |
|---|---|---|
| `/%61dmin/*` | **201 Created** | 400 |
| `/x\admin/*` | 201 | 400 |
| `/ADMIN/*` | 201 | 400 |
| `/x/../admin/*` | 201 | 400 |
| `/admin/*` | 201 | 201 |

The 201 is the whole finding. Nothing downstream would ever have caught it:
the rule is stored, the admin reads it back exactly as typed, `/api/admin/explain`
walks the same matcher and also reports no match, and the request reaches the
upstream under whatever allow rule covers it. **A deny rule that never fires
looks identical to one that was never needed.**

The guard is `validate_path_pattern`, and it asks one question — does the
pattern survive `normalise` unchanged — because that is the property `matches`
actually depends on, so a sixth normalisation step later cannot open the gap
again. It is the judgement the comma guard already makes about group names,
applied to the other half of the same row.

Not fixed in `matches`: decoding the pattern there has a failure mode (a
pattern that will not decode) whose only fail-closed answer is to match
everything, which is an outage. The boundary has no such problem — it can
refuse. Nothing is released yet, so there are no stored rows to migrate.

### MEASURE — `worker_shutdown_timeout`, and the reload it does not reach

The open question `docs/06` carried since Phase 1 — should it be set, and to
what ([ADR-0025](adr/0025-worker-shutdown-timeout.md)). Measured on the lab with
a throwaway vhost carrying no `auth_request` (`verify-shutdown.sh`,
`99-wsq.conf`), because the claim is about how long a retired worker keeps
serving an upgraded connection and that does not depend on who authorised it.
Three connections, one per configuration, each trading a frame a second.

| Configuration the worker started under | Retired by a reload at | Worker gone | Connection died |
|---|---|---|---|
| unset (the committed configuration) | 05:08:53 | **never** — still shutting down at 05:16, 7 min later | still alive |
| `worker_shutdown_timeout 20s` | 05:10:12 | 05:10:32, **+20 s** | +22 s |
| `worker_shutdown_timeout 300s` | 05:11:08 | 05:16:10, **+302 s** | +302 s |

**The finding is the middle row of the first column.** Setting the directive and
reloading does not reach a worker that is *already* shutting down: at 05:09:26
the value was set to 20 s and nginx reloaded, and worker 8207 — retired at
05:08:53 under the unset configuration — was still there at 05:10:35, **102 s
later**, with its connection alive at 107 exchanges. Meanwhile worker 8285,
started under the 20 s value, was killed 20 s after the reload that retired it.
The timer is read from the configuration the worker was *started* with, not the
one live when it is retired. So the first reload after this change still leaves
one unbounded worker behind, and existing ones survive it: `docker compose up -d
nginx` clears them, a reload does not.

**What it costs an ordinary reload: nothing measurable.** 120 requests to the
portal spanning two reloads with the value set — 120 × 302, no failures, no
dropped connections. The first attempt at that measurement read 50 × 302 and
**350 × 429**: unpaced, it was not measuring the reload at all but the 5 r/s
login-flow zone in `00-auth.conf`, the same limit the load test found
(`docs/06`, N-07). Paced under it, the reload is invisible.

The value is `proxy_read_timeout` on protected locations, deliberately
(ADR-0025): one duration, so a reloaded connection and an idle one are cut at
the same age. Verified afterwards on the rebuilt image rather than on a
`docker cp`'d file — `nginx -t` passes on both `nginx.conf` and
`breakglass.conf`, and a real login answers `api/me` 200 and Jenkins 200.

### TEST — what a login leaves behind: the logs, the stores, and the logout

Two questions asked in one pass on the lab (`verify-logleak.sh`,
`verify-codeleak.sh`): does a logout destroy the credential or only stop showing
it, and does anything a person types or is issued — password, session cookie,
authorization code, JWT — survive in a place somebody without the session can
read. The hunt is for the **exact byte string**, taken from `.env` and from the
live cookie jar, across `docker compose logs` for all six services and across
the host's `/var/lib/docker/containers/*/*-json.log`, which is where they persist
after the container is gone.

**Nothing that is a secret is in a log.** Session cookie, the Redis session key,
`labuser`'s password, a deliberately wrong password submitted as a canary, the
OIDC client secret, and the Postgres, Keycloak-admin and AD-bind passwords: all
eight clean, in every service and on disk. The backend, Keycloak, Redis and
Postgres logs carry no JWT, no `Bearer`, no `password=` and no `Cookie` header —
including on the error paths, which is where secrets usually get printed: a
forged `_oauth2_proxy` cookie and a failed password were both fed in first.

**The one thing that was:** nginx logs `"$request"`, and the query string comes
with it. Every login therefore wrote the OAuth **authorization code** into the
access log at `/oauth2/callback`, and Keycloak's **`session_code`** at
`/login-actions/authenticate`. oauth2-proxy logged the callback a second time in
its own request log.

```
"GET /oauth2/callback?state=…&session_state=…&iss=…&code=0307490a-8b54-4b58-a397-739c14d96dac.8fe8…"
```

**How much that code is worth to whoever reads the log — measured, not assumed.**
The flow is driven to the callback and stopped there so the code is unspent, then
redeemed at the token endpoint the way a log reader would: with the client secret,
which is a server-side configuration value, but without the PKCE verifier, which never
leaves oauth2-proxy.

| Redeeming the logged code with | Keycloak answers |
|---|---|
| no `code_verifier` | `invalid_grant` / **PKCE code verifier not specified** |
| a wrong `code_verifier` | `invalid_grant` / **PKCE verification failed: Code mismatch** |
| the correct `code_verifier` (positive control) | **accepted** — `access_token` issued |
| the same code again | `invalid_grant` / **Code not valid** |

`accessCodeLifespan` is 60 s on top of that. So `code_challenge_method = "S256"`
in `oauth2-proxy.cfg` is the control that matters, and it holds; the log entry is
a defence-in-depth failure, not an exploitable one. Fixed anyway, in
`conf.d/logredact.inc` (README rule 21): two `map`s replace the two values and
the log formats write `$safe_request`. The rest of the query string is kept on
purpose — `state`, `rd` and `error_description` are what a failed login is read
from. Re-measured after the rebuild: `code=REDACTED`, `session_code=REDACTED`,
zero live values in either service, and a login still answers `api/me` 200.
oauth2-proxy has no redaction of its own and nginx already logs every request it
sees, so its duplicate went with `request_logging = false` — `auth_logging` keeps
`[AuthSuccess]` and the startup errors `INSTALL.md` §"oauth2-proxy" sends people
to are untouched. What is left that *looks* like a token is `client_data=eyJ…` on
the Keycloak login-action URL: base64 JSON holding `redirect_uri`,
`response_type` and `state`, no credential.

**The stores hold no more than the logs.** The oauth2-proxy session in Redis is
ciphertext — no readable JWT in the stored value. `audit_event` is
sub / name / application / decision / reason / path / IP / request-id, with no
column that could hold a token, and the frontend uses no `localStorage`,
`sessionStorage` or `document.cookie`, so `/api/me`'s five fields
(`admin`, `email`, `groups`, `sub`, `username`) are all the browser ever holds
besides the cookie.

**Logout destroys the credential rather than hiding it**, which the logout test
above establishes step by step; this run adds the replay. The pre-logout cookie
was copied to a jar the logout never touched and used afterwards: `/api/me`
**302** and the Jenkins vhost **302**, the Redis key `exists=1 → 0`, the session
index 4 → 3 with the user's other sessions deliberately untouched.

**Where the browser's copy of the cookie is cleared is worth knowing.**
`POST /api/logout` does **not** clear it: the backend calls oauth2-proxy's
`/oauth2/sign_out` server-to-server, so the `Set-Cookie` that clears it is
addressed to the backend and the 204 carries none. The navigation `portal.js`
performs next — `location.href = /oauth2/sign_out?rd=%2F` — is what clears it,
`_oauth2_proxy=; Max-Age=0; HttpOnly; Secure; SameSite=Lax`. Measured on the jar:
1 cookie after login, still 1 after the POST, **0** after the navigation. Nothing
is exposed by the gap — the session is already destroyed server-side and the
value is dead — but a client that only POSTs and never navigates keeps a dead
cookie for `cookie_expire` (168 h when this was measured, 10 h now — `docs/04`).

**No session fixation on the way in.** An attacker-chosen
`_oauth2_proxy=ATTACKER-PLANTED` planted in the jar before the login was replaced
by a server-minted value, and a second login in the same jar minted a fresh one
again.

## Measured in the browser

The lab stack is not the system under test here: a Content-Security-Policy is
enforced by the browser, so this one was run against Firefox 153 (headless,
screenshotted) over a plain HTTP origin, with the policy delivered as
`<meta http-equiv="Content-Security-Policy" content="default-src 'self'">`.

### Alpine.js under `default-src 'self'`

Three pages, identical but for which build they load and how `x-data` is
written. Each one reports whether an external script ran at all, whether the
`Alpine` object exists, what `document`'s `securitypolicyviolation` events said,
and whether a binding actually evaluated — the fallback text stays in place if
it did not.

| page | build | `x-data` | binding | violations |
|---|---|---|---|---|
| `std-inline` | `alpinejs@3.17.1` | `{ n: 41 }` inline | **did not evaluate** | `script-src blocked eval`, twice |
| `csp-inline` | `@alpinejs/csp@3.17.1` | `{ n: 41 }` inline | `42` | none |
| `csp-data` | `@alpinejs/csp@3.17.1` | `Alpine.data('probe', …)` | `42` | none |

The first row is the claim [ADR-0007](adr/0007-frontend-buildless-static.md)
rested on, and it holds: the standard build **loads** under the policy — the
script itself is same-origin, `window.Alpine` is present — and then evaluates
nothing, because it compiles every expression with `new Function()`. The
failure is silent in exactly the way that matters: no error on the page, no
missing file, just attributes that never do anything.

The second row was the surprise. The CSP build of 3.17.1 does not merely accept
bare property names, as the ADR assumed when it said the build "restricts the
expression syntax" — it ships a parser, and inline object literals and
arithmetic go through it untouched. So the entry cost of dropping `unsafe-eval`
is much lower than the ADR feared. What the parser refuses, tried one expression
per element on one page, all under the same policy:

| expression | result |
|---|---|
| `app.name`, `app.enabled ? 'on' : 'off'`, `app.enabled && app.name` | works |
| `label()`, `upper(app.name)` — member calls, with arguments | works |
| `clicks = clicks + 1` in `x-on:click` and in `x-init` | works |
| `x-for="a in apps"` | works |
| `$el.tagName` — the magics | works |
| `apps.filter(a => a.id > 1).length` — arrow function | **fails** |
| `` `n=${app.id}` `` — template literal | **fails** |

Neither refusal costs anything: both belong in the `Alpine.data()` object, which
is ordinary JavaScript in an ordinary `.js` file and is not parsed by Alpine at
all.

`@alpinejs/csp@3.17.1` is therefore vendored at `frontend/src/vendor/alpine.js`
(provenance and npm integrity hash in the README beside it). Packaging checked
on the lab stack afterwards, since a new subdirectory of `frontend/src/` had
never been through ADR-0020's copy before: rebuilt nginx image, and
`https://portal.apps.example.local/vendor/alpine.js` answers 200,
`application/javascript`, 71087 bytes, sha256 identical to the committed file —
and 302 to Keycloak without a session, so the vendor path is authenticated like
the rest of the portal rather than quietly anonymous. ADR-0007's open
consequence is closed: the CSP the portal is written for needs neither
`unsafe-inline` nor `unsafe-eval`. The `frontend` job in CI now fails if any
file under `vendor/` regains `eval(` or `new Function`, because swapping in the
standard build looks like nothing but a larger file and would cost `unsafe-eval`
on the one host every user opens.

**Re-measured on 2026-09-07, when [ADR-0024](adr/0024-no-admin-ui-in-v1.md)
decided there would be no admin screens.** The file is still served and is now
referenced by nothing: `/vendor/alpine.js` answers **200, 71 453 bytes** to a
`labuser` session and **302** without one, and `grep -rl alpine` inside the
running nginx image's document root matches only the vendored file itself and
the README beside it — no page loads it. The size differs from the 71 087 above
because the MIT banner was prepended afterwards (ADR-0013); the bytes under the
banner are unchanged. This is what corrected the reason given in three documents
and a CI comment for putting that banner in the file rather than only in a
README — it said the build "is served to every browser that opens the portal",
which stopped being true the moment no page loaded it. The notice still belongs
there, because the file ships inside the nginx image and is reachable at that
path, which is a distributed copy either way.

**The file is gone as of 2026-09-07**
([ADR-0027](adr/0027-frontend-no-framework.md)). The screen it was kept for was
built ([ADR-0026](adr/0026-audit-explain-screen-in-v1.md)) in plain DOM calls,
so `frontend/src/vendor/` is deleted and `/vendor/alpine.js` is no longer a URL
the nginx image serves. **The measurement above stands** — it is a fact about
Alpine under a `default-src 'self'` policy, not about this repository, and it is
what the next person reaching for a framework here has to read before vendoring
the standard build. The two CI checks it produced (`eval(`/`new Function` under
`vendor/`, and the MIT banner) are gone with their subject; the text-only rule
they sat beside now runs over every file under `frontend/src/` with no exception
carved out.

### The login theme — where PatternFly can and cannot be repainted from `:root`

The theme is a child of `keycloak.v2` that overrides no template, only the
palette (`keycloak/themes/openberat/login/`). Same method as above: the rendered
login page and its four stylesheets were pulled off the lab, served locally and
screenshotted in Firefox headless twice, once with `ui.systemUsesDarkTheme=0`
and once with `1`.

Three things the first screenshot corrected, none of them guessable from the
CSS by reading:

| Attempt | What happened |
|---|---|
| `:root { --pf-v5-global--primary-color--dark-100 }` | **Nothing.** PatternFly writes the `--100` names as literals in its own `:root` and only *some* of them alias the `--dark-100` pair, so the button stayed PatternFly blue |
| `:root { --pf-v5-global--primary-color--100 }` | Repaints the button **in light mode only** |
| `.pf-v5-c-button.pf-m-primary { --pf-v5-c-button--m-primary--* }` | Repaints it in both |

The middle row is the interesting one. PatternFly's dark palette lives under
`:where(.pf-v5-theme-dark)`, which has **zero specificity** — so a plain `:root`
override wins over it every time, and every variable the theme sets does apply
in dark mode. But `:where(.pf-v5-theme-dark) .pf-v5-c-button` sets the button's
own `--pf-v5-c-button--m-primary--BackgroundColor` **on the button element**,
and a custom property set on the element beats an inherited one no matter how
specific the rule that inherits it. Specificity is not the mechanism here;
*which element carries the declaration* is. Anything PatternFly assigns per
component has to be answered per component.

Painting the button through its own three variables also removes the light/dark
branch: the text colour is `var(--card)`, the ground the button sits on, which
is white on `--gold-ink` in light (5.31:1) and near-black on it in dark
(8.62:1). Both clear WCAG AA, which `frontend/src/portal.css` treats as a rule.

Two smaller findings from the same run. `${msg("loginTitleHtml")}` passes
through `kcSanitize`, and a `<span class="…">` **survives** it — so the
two-tone wordmark the portal header uses is reproducible on the login page from
a theme message, without touching a template or putting presentation HTML in
the realm export. And a child theme's `styles=` **replaces** the inherited list
rather than extending it: the parent's `css/styles.css` has to be named again
or the whole PatternFly layer disappears. Resource lookup still walks the theme
chain, so naming it is enough — the file itself need not be copied.

Deployment, on the lab: `keycloak/` needed the `Dockerfile` it never had, since
a theme is read at runtime and mounting it would be the configuration drift the
rules forbid. The mark is not duplicated — the build context is the repository
root and `frontend/src/logo.svg` is copied into the theme, the same trick
ADR-0020 uses for the frontend. Verified after `docker compose build keycloak`:
the login page links `/resources/<v>/login/openberat/css/openberat.css` (200),
the mark comes back `image/svg+xml`, and `ob-login.sh` still completes a real
`labuser` login through the retheme — the check that matters, since the harness
scrapes the form action out of the page and a broken template would fail there
rather than merely look wrong.


### The dark restyle — a palette that has to survive its own background

The four screens were repainted from the paper/ink light theme to a near-black
ground lit by two corner glows, with the panels as translucent glass over it
(`frontend/README.md` "Design"). The interesting part is not the look, it is that
an aurora makes the ground **variable**: a contrast ratio computed against
`--ground` is a ratio against the darkest pixel on the page, and the text does
not necessarily sit there.

So the ratios are computed against the worst ground any text can reach — both
glows at full strength, overlapping, which the two corner positions make
impossible in practice, with a panel's scrim over them:

| On | --ink | --muted | --gold-ink | --refuse |
|---|---|---|---|---|
| a card (`--panel`, 0.70 scrim) | 10.24 | **4.81** | 6.46 | 5.15 |
| the header bar (0.78 scrim) | 11.39 | 5.36 | 7.20 | 4.99 |
| the scrimmed middle of the page, no panel | 10.38 | 4.88 | 6.55 | 4.55 |
| the raw lit ground | 4.19 | 3.67 | 4.93 | 3.42 |

The last row is why a panel is **a dark scrim first and a sheen second** rather
than the plain white alpha glassmorphism is usually written with: on the lit
patch a white-alpha panel *adds* to the glow and `--muted` lands at 3.67:1. The
only thing that touches the raw lit ground is the `h1`, at 4.19:1 — it is
28-44 px, where AA asks 3:1. Two colours moved to make the table hold:
`--muted` `#9a9384` → `#a8a08e`, and `--refuse` `#e0605c` → `#ef8a84`, which at
the original value read 3.42:1 on that ground.

**The login theme in both OS modes, which is the measurement that mattered.**
Same method as the section above — the rendered page and its stylesheets pulled
off the lab, served locally, screenshotted in Firefox headless with
`ui.systemUsesDarkTheme` 0 and 1. keycloak.v2 puts PatternFly's dark palette
behind a `.pf-v5-theme-dark` class it sets from `prefers-color-scheme`, so a
dark-only child theme on a light-set machine is the case that breaks, and it is
invisible to whoever writes the CSS on a dark machine. **The two screenshots are
identical**, after one fix.

The fix is a follow-on to the per-component finding above, and a sharper version
of it: **`--pf-v5-c-form-control--BorderColor` is not a variable that exists.**
In PatternFly v5 a form control's border is drawn on its `::before` and `::after`
pseudo-elements, so the names are `--pf-v5-c-form-control--before--BorderTopColor`
and friends; setting the plausible-looking `--BorderColor` does nothing at all,
silently, and the input keeps a white border on a dark card in light-set OSes.
The same is true of the eye toggle beside the password field
(`.pf-v5-c-button.pf-m-control`). The names were read out of the shipped
`patternfly.min.css` rather than guessed — grepping
`--pf-v5-c-form-control--[A-Za-z-]*Border[A-Za-z-]*` is faster than a screenshot
round trip and does not produce a plausible wrong answer.

**The favicon is a template string, so it is the one asset a palette cannot
reach.** keycloak.v2 renders
`<link rel="icon" href="${url.resourcesPath}/img/favicon.ico">`; resource lookup
walks the theme chain, so with no file at that path the browser tab of our login
page carried *Keycloak's* mark. Dropping a real `.ico` at
`themes/openberat/login/resources/img/favicon.ico` overrides it without touching
the template — verified on the lab, the rendered page links
`/resources/<v>/login/openberat/img/favicon.ico` and it comes back 200 at
15 086 bytes, byte-identical to the committed file. It is generated from
`frontend/src/logo.svg` with ImageMagick (`icon:auto-resize=16,32,48`) and is the
only derived asset in the repository; the regeneration command is in both
`frontend/README.md` and `keycloak/README.md` because nothing checks that it
still matches the mark.

**The portal's application buttons open in a new tab** (`target="_blank"`), with
`rel="noopener"` — not decoration: without it the application it opens gets
`window.opener` on the portal, which is the one host carrying a cookie valid for
every application on `.apps.<domain>` (ADR-0015). The tab change is announced,
not only drawn: the card shows a `↗` from CSS and `portal.js` appends a
visually-hidden "(opens in a new tab)", since a screen reader is told nothing by
the arrow.

Verified after the rebuild rather than on the local copies: `nginx -t` passes,
`ob-login.sh` completes a real `labuser` login through the retheme — the check
that matters, since the harness scrapes the form action out of the page and a
broken template would fail there rather than merely look wrong — and `api/me`,
the portal, `portal.css` and the Jenkins vhost all answer 200.

## Unverified, to be tested

**One open, and every other claim here has been tried.** The list is kept as a
record of what was assumed and what the lab said, because four of the answers
were the opposite of the assumption and one of those (`Set-Cookie` on
`/oauth2/auth`) is load-bearing for ADR-0006. A new claim goes in unticked and
leaves ticked.

- [x] **Answered: both, and they were the same mistake.** How long is a session
      in the *shipped* configuration, and does `GET /api/admin/sessions` count
      sessions that would still authenticate? ADR-0028 read `cookie_expire` and
      stopped there; the realm ends a session at **30 minutes idle or 10 hours
      absolute**, and the third of the three possible outcomes is what happens:
      the key exists and the cookie is refused, so the screen over-reports. Run
      below, and the four numbers now live in one table in `docs/04`.

- [x] **Answered: no.** Can an nginx subrequest (the `auth_request` target)
      itself trigger an `auth_request`? The whole access phase is skipped for a
      subrequest — measured above. The chain stays in the backend and the
      internal HTTP call does not disappear.
- [x] **Answered: no, twice over.** Can Keycloak carry an AD group's `objectSid`
      into a token claim? Tried on the lab against Keycloak 26.3.5
      (`verify-sid.sh`, `verify-sid2.sh`), and it fails at both steps:

      1. **The import destroys the value.** Setting
         `mapped.group.attributes=["objectSid"]` on the group mapper and running
         a `fedToKeycloak` sync does put an `objectSid` on the Keycloak group —
         and what it puts there is the binary SID read as text. A domain group's
         SID is **28 raw bytes**; what is stored is a 13-character string whose
         UTF-8 encoding is **21 bytes and contains four U+FFFD replacement
         characters**. Every byte that was not valid UTF-8 became the same
         character, so the value cannot be turned back into `S-1-5-21-…` and two
         different SIDs can collapse onto the same string. It is not an
         identifier; it is a hash with unknown collisions.
      2. **No stock mapper would carry it anyway.** The build offers exactly one
         OIDC group mapper, `oidc-group-membership-mapper` — *"Map user group
         membership"*, whose only options are the claim name and whether to use
         the full path. `oidc-usermodel-attribute-mapper` reads **user**
         attributes. Nothing in the list emits a *group* attribute, so even a
         correctly imported SID would need a custom or script mapper deployed
         into Keycloak.

      **[ADR-0008](adr/0008-group-identity-name.md) stands, and now for a
      measured reason** rather than "B and C are not available without
      reopening ADR-0006". They are not available at all on this path: it is not
      that reading the SID costs an LDAP connection, it is that the SID does not
      survive the trip. The mapper config was rolled back by re-importing the
      realm, which is what a Keycloak rebuild does anyway.
- [x] **Answered: 330 s, and that is the only figure worth publishing.** The
      real deprovisioning delay as measured with `cookie_refresh`. Measured
      above, through the committed chain and with the directory contributing
      nothing, then re-measured in Phase 6 and unchanged. The delay counted from
      the AD change ranged over 272.6-316.7 s across four runs of identical
      behaviour, because the cut lands at a fixed session age; the ceiling is
      what does not move.
- [x] Does oauth2-proxy return `Set-Cookie` when performing `cookie_refresh` on
      `/oauth2/auth`? **Yes** — measured above. In the official pattern the subrequest's upstream is
      oauth2-proxy; in ours it is the backend. **If it is not relayed the cookie
      is never refreshed and ADR-0006 silently collapses.**
- [x] **Answered: yes, verbatim.** Does the `auth_request` subrequest inherit
      the main request's headers? It does, so a client-supplied `X-Original-URI`
      / `X-Forwarded-Host` reaches the PDP unless the include overwrites that
      exact name (this is why `docs/02` fixes `X-App-Slug` in the nginx config —
      and why the same include now clears `X-Auth-*`). Measured above.
- [x] **Answered: only passive.** Does nginx OSS have active upstream health
      checks? Asked of the binary rather than of the documentation, because a
      directive nginx does not have is a configuration that will not load —
      `nginx -t -c` on a throwaway config, nginx 1.29.8, the image this project
      ships (`verify-healthcheck.sh` on the lab host):

      | Directive | |
      |---|---|
      | `server … max_fails=3 fail_timeout=10s` | accepted |
      | `server … backup` | accepted |
      | `upstream { zone probe 64k; }` | accepted — shared memory is OSS, it is the *checking* that is not |
      | `health_check` | **`[emerg] unknown directive "health_check"`** |

      So **nothing in nginx OSS polls `/readyz`.** Passive checking ejects an
      instance only after real requests have already failed against it, which
      for this product means users seeing errors first — and `auth_request`
      turns an unreachable backend into a 500, not a denial. The HA item
      therefore has three roads and none of them is the one `docs/02` assumed:
      NGINX Plus, a patched build with `nginx_upstream_check_module`, or
      something outside nginx that polls `/readyz` and rewrites the upstream
      list — which is the shape ADR-0011 already uses for application blocks.
      `/readyz` is not wasted either way: it is what an operator, a container
      orchestrator and the break-glass runbook ask.
- [x] **Answered: no, only at `NO_CACHE`.** The effect of the LDAP provider's
      **Cache Policy** on group freshness. Measured above: at `DEFAULT` a group
      removed in AD survives a brand-new login, so the "Keycloak reads live"
      claim is a property of the setting, not of Keycloak.
      **[ADR-0006](adr/0006-group-membership-source.md) holds only with `NO_CACHE`**,
      which is now mandatory alongside `cookie_refresh`.
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
- [x] **Answered: yes, and it is the only thing that does.** Does the Keycloak
      **LDAP group filter** exclude a group whose `cn`
      contains a comma — `Payroll,OpenBerat-Admins` against `(cn=OpenBerat-*)`?
      Measured above: such a group reaching the claim is a management-plane
      escalation, and this filter is the only thing that stops it
      ([ADR-0008](adr/0008-group-identity-name.md) mitigation 1). The control
      case — the same login with the filter emptied — reaches
      `/api/admin/applications` with a 200.

## Licences — checked 2026-09-07

`docs/01-landscape.md`'s licence column was written from memory. Every cell has
now been read from the project's own `LICENSE` file, through GitHub's licence
endpoint, which reports what that file says rather than what a README claims.
Twelve of fourteen were right.

| Project | Written from memory | What the `LICENSE` file says |
|---|---|---|
| Keycloak | Apache-2.0 | `Apache-2.0` |
| Pomerium | Apache-2.0 (some features Enterprise) | `Apache-2.0` — the Enterprise console is a separate product, not a directory in the repository |
| **Authentik** | **MIT** | **`NOASSERTION` / "Other".** MIT is the default, but the file carves out `authentik/enterprise/` under a separate enterprise licence and `website/` under CC BY-SA 4.0 |
| Authelia | Apache-2.0 | `Apache-2.0` |
| oauth2-proxy | MIT | `MIT` |
| Teleport | AGPL-3.0 community + commercial | `AGPL-3.0` |
| **HashiCorp Boundary** | **BUSL (no longer open source)** | **`NOASSERTION` / "Other".** Business Source License **1.1**, licensor **International Business Machines Corporation** — not HashiCorp — Change Date four years after each version is published, Change License **MPL-2.0** |
| Apache Guacamole | Apache-2.0 | `Apache-2.0` |
| Warpgate | Apache-2.0 | `Apache-2.0` |
| OpenZiti | Apache-2.0 | `Apache-2.0` |
| OPA | Apache-2.0 | `Apache-2.0` |
| Cedar | Apache-2.0 | `Apache-2.0` |
| Casbin | Apache-2.0 | `Apache-2.0` |

The two corrections both go the same way — **a single SPDX identifier was
hiding a carve-out.** Authentik is not simply MIT: it has a paid directory
inside the same repository, which makes ADR-0014's "no feature behind a licence"
a difference from Authentik and not only from Pomerium. And Boundary's BUSL is
not a permanent state: every version becomes MPL-2.0 four years after it ships,
under a licensor that is now IBM. Neither changes a decision here; both change
what this document can be quoted for.


## The audit and `explain` screen

Run on the lab host on 2026-09-07 with `verify-auditscreen.sh`, against the
committed configuration and a rebuilt nginx image. `ALL OK`.

The screen ([ADR-0026](adr/0026-audit-explain-screen-in-v1.md)) draws two
endpoints that already existed, so what needed checking was not the endpoints —
they were measured when they were written — but that the page reaches a browser
under the same policy as the rest of the portal, and that the two answers it
prints carry every field it prints.

| Check | Result |
|---|---|
| `/audit` and `/audit.js` to a session | **200** |
| the same with no session | **302** to Keycloak — the screen is behind `location /` like the portal, not a new anonymous path |
| CSP on `/audit` | `default-src 'self'` unchanged, **no `unsafe-*`** |
| the served page | no inline `<script>` body, no inline event handler, loads `/audit.js` |
| `labuser` on `/api/admin/audit` and `/api/admin/explain` | **403** — the branch the page draws as a refusal rather than an outage |
| `labadmin` on `/api/admin/audit` | **200** |
| a mistyped filter (`?decsion=deny`) | **400**, not a wider list |
| half a keyset cursor (`before_ts` with no `before_id`) | **400** |
| `since` = `until` | `[]` — an empty window, not the whole table |

`explain` was asked the same request three ways, because the field the screen
prints as "matched against" is the one an admin reads when the answer surprises
them:

| `path` as it reaches the handler | `normalised_path` | verdict |
|---|---|---|
| `/x` | `/x` | `allow` — the rule is the whole application |
| `/%61dmin` (single-encoded) | `/admin` | `allow` |
| `/%2561dmin` (double-encoded) | **`null`** | `deny` / `malformed_uri` |

The last row is the one the screen has a sentence for rather than an empty
cell: the URI never became a path, so no rule was consulted, and printing `""`
there would read as the site root. Reaching the handler with a literal
`/%2561dmin` takes one more layer in the query string (`path=/%252561dmin`),
because the query is decoded once before `explain` sees it — the first attempt
at this measurement asked the wrong question and got `/admin`.

**A row is written 35 s after the requests it summarises**, which is `cache::TTL`
(30 s) plus the sweep interval (5 s), and it carried `count: 4` and
`distinct_path: 4` for four requests to four paths — the summary columns the
table has to draw, or a row that stands for fifty thousand requests reads as
one. The row is found by `?app=<slug>&since=<start of the run>`: audit rows
**outlive the application they name**, so a slug filter alone matches every
earlier run of the harness, and the first version of this measurement reported
5 s for a row written three minutes earlier.

`/vendor/alpine.js` no longer serves JavaScript
([ADR-0027](adr/0027-frontend-no-framework.md)); it answers `text/html`, because
`location /` ends its `try_files` with `/index.html` and every unknown path
under the portal host falls through to the portal page. That is pre-existing
behaviour and not a 404 — worth writing down, because "is it gone" cannot be
asked of this host with a status code.

### Who is signed in

Added to the same harness when the screen grew a **Live** tab
([ADR-0028](adr/0028-live-sessions-endpoint.md)). `GET /api/admin/sessions`
answers **403** to `labuser` and **200** to `labadmin`, and the caller is in its
own list.

The one property the endpoint exists for is that it counts session keys that
still **exist** rather than the index set's cardinality — a session that merely
expired leaves its key in the set until the set's own TTL, and cardinality would
report it as somebody signed in. The lab could not produce that case on its own:
every key in `labadmin`'s set was still live, because a lab session's key lasts
`cookie_expire` (168 h then, 10 h now) and no harness run had been going long
enough to strand one. So it is forced, by adding a key that names no session rather than deleting
one that does — deleting a real key would sign a live browser out:

| Step | Set (`SCARD`) | Endpoint |
|---|---|---|
| before | 6 | 6 |
| `SADD _oauth2_proxy-neverexisted` | **7** | **6** |
| after reading it | 7 | — the read did not prune |
| `SREM` | 6 | 6 |

The third row is the second half of the decision: a read endpoint that pruned
would be a write endpoint, so dead members are reported away and left alone.

The tab bar itself is checked as six ids in the served HTML (`view-live`,
`view-history`, `view-explain` and their tabs), because the fragment routing is
the only thing standing between three views and one page that shows all of them
at once.

### What the Live tab found on its first day

Opened against the lab, it showed **60 sessions across 8 subjects** for a
directory with two users. Every one of them was real — the keys existed and each
would still have authenticated — and the pile is what the tab is for. Two
separate causes, and only one of them is a lab artifact:

- **42 of the 60 named subjects Keycloak no longer had.** Its H2 database
  deliberately gets no volume (`docker-compose.yml`), so every
  `docker compose build keycloak` re-creates the federated users with fresh ids,
  while Redis keeps the sessions minted under the old ones. `kcadm get users`
  knew 3 ids; the index held 8. This does not happen to an installation that
  follows `INSTALL.md`, which gives Keycloak a real database — but it is worth
  recording that **an oauth2-proxy session outlives the IdP forgetting the user
  it names**, and keeps authenticating until the next `cookie_refresh` finds out
  — five minutes, measured since (`docs/04`).
- **The rest are sessions nobody signed out of.** Every harness run in this
  document logged in and deleted its cookie jar. That leaves a key behind, which
  is what a closed laptop, a cleared browser and a finished CI job also leave —
  and it is counted here until somebody presents the cookie, though it stops
  *working* 30 minutes later (`docs/04`). `verify-auditscreen.sh` now signs out at the end.

Pruning the 6 subjects Keycloak did not have took the lab to **3 subjects and 22
sessions** — one of them a `labnested` session with no audit row at all, drawn
as "not seen at an application yet", which is the portal-only case ADR-0019
exists for, on screen.

### Logout removes the key and the index entry — and two ways to measure it wrong

Chasing the count above produced a phantom bug worth writing down, because both
mistakes are easy to repeat.

**`POST /api/logout` answers 403 without an `Origin` header** (docs/02). A curl
that omits it gets a refusal the session survives, which reads exactly like a
logout that ran and did nothing. The backend says so — `logout refused: wrong or
missing Origin` — and that line is the only thing that separates the two.

**A count cannot see this working.** `ob-login.sh` never calls `/api`, so a
freshly minted session is **not in the index** until its first request there —
that is the `indexed` middleware doing what it was written for. On the logout
call itself the middleware adds the key one instruction before the handler
removes it, so the set's cardinality does not move while exactly the right thing
happens. Measured on the key instead, with the derivation from VERIFY (4)
(`ob-session-key.sh`):

| | `EXISTS key` | `SISMEMBER index key` | `GET /api/me` |
|---|---|---|---|
| signed in, one `/api` call | 1 | 1 | 200 |
| `POST /api/logout`, no `Origin` | 1 | 1 | 200 — **403, nothing happened** |
| `POST /api/logout` with `Origin` | **0** | **0** | **302** |

Neither Redis `DEL` nor `SREM` errors on a key that is not there, so the
handler's `204` is not evidence either. Only the key is.

**Not measured: what the page looks like.** Every assertion above is a status
code, a header or a JSON field. The layout reuses the panel, table and contrast
tokens `portal.css` already carries, and no ratio in that file's table changed —
`allow` takes `--gold-ink` and `deny` takes `--refuse`, both already computed —
but nobody has opened it in a browser.

## A security read of the finished configuration

Nothing below came from a failing test. Each one is a rule the repository
already writes down, applied to a file that did not follow it. Measured by
building the nginx image from the commit before the fix and from the commit
after, running each on `:8443`/`:8444` with only the certificate mounted — no
upstreams — and reading the status code. **`502` means the location matched and
proxied**, `404` means it did not exist.

| Request | Before | After |
|---|---|---|
| `auth.…/realms/master/protocol/openid-connect/token` | **502** — proxied | 404 |
| `auth.…/realms/master/` | **502** — proxied | 404 |
| `auth.…/realms/openberat/.well-known/openid-configuration` | 502 | 502 — still served |
| `auth.…/realms/openberat/login-actions/authenticate` | 502 | 502 — still served, now rate-limited |
| `auth.…/realms/openberat-other/foo` | — | 404 — the alternation does not leak |
| `auth.…/resources/x/login/openberat/css/openberat.css` | 502 | 502 — still served |
| `auth.…/admin/master/console/` | 404 | 404 |
| `portal.…/oauth2/auth` | **502** — proxied | 404 |
| `portal.…/portal.css` | 200 | 200 — the anonymous files still are |

The first two are the one that matters. `location ~ ^/(realms|resources)/` reads
as "the login flow and its assets", and Keycloak's `master` realm is neither: its
`admin-cli` client is public with direct access grants enabled by default, so
that URL takes `grant_type=password&client_id=admin-cli&username=…&password=…`
and answers a token or an error — an online guessing oracle for
`KC_BOOTSTRAP_ADMIN_PASSWORD`, on the one hostname every browser in the
deployment is redirected to. There was nothing in front of it: the `login` zone
was on `@signin` and `/oauth2/`, and `bruteForceProtected` is **absent** from a
stock realm export, which in Keycloak means off.

`/oauth2/auth` is the smaller sibling of the same omission. `/decide` carries
`internal;` and the README explains at length why an IP ACL would not do the
job; the portal's other subrequest target had nothing, so it answered directly —
`401` without a cookie, `202` with one, and on the `202` the session's own
`X-Auth-Request-User/-Email/-Groups`. Neither number is a leak to somebody who
does not already hold the cookie, and that is the whole of its defence.

### The generated block, and the field nobody checked

`render_apps_conf` describes itself as the last point before a value becomes
nginx configuration. It validated the upstream URL and the hostname's *name* —
whether it shadows `portal.` or `auth.` — and never the shape of either the
hostname or the slug, which becomes a bare directive argument:

```
set $app_slug {slug};
```

Only the schema's `CHECK` stood between a `;` and a second directive, and
because the admin API did not check it either, a bad slug came back from
Postgres through the generic error path as a **503** — an operator reading an
outage where the answer was "that is not a slug". Three tests, each seen red
first by removing the guard: with it gone, `render_apps_conf` renders a row
whose slug is `evil; return 200` exactly as written.

### `/api/*` and the zone it did not have

`00-auth.conf` says why rate limiting was pulled forward: everything funnels
through one backend, so a flood does not degrade one application, it exhausts
authorisation for all of them, and fail-closed turns that into a total outage.
`protected.inc` carries the `decisions` zone, so every application was covered.
`/api/*` was not — and it is the one authenticated path the decision cache never
sees, because the portal does not go through `/decide`. Each call is an
oauth2-proxy hop, a Redis write (the ADR-0019 index) and, on `/api/apps`, an
uncached join across `application` and `entitlement`.

### The two questions the read left, and what answering them measured

**A `path_pattern` with no trailing `*`.** `matches` strips the star before
comparing, so `/reports` and `/reports/*` are one rule — and the starless
spelling reads as a single page. The correction could only run at write time:
narrowing it in `matches` would shrink every starless **deny** row already
stored, and no reading of a row recovers its author's intent
([ADR-0029](adr/0029-path-pattern-is-a-subtree.md)). Nothing in `policy.rs`
moved, so nothing already decided decides differently; the test pins the
sentence the admin now reads, because the sentence is the fix:

```
path_pattern is a subtree and has no exact-path form: write /reports/*,
which matches /reports and everything below it
```

**Break-glass, measured on the real stack rather than asserted.** The first
rehearsal (`docs/08`, 2026-09-06) curled `sample.apps.example.local` — which was
in the hand-written `breakglass/apps.conf` either way, so a procedure that would
have answered 404 for every real application passed it. The second one adds and
removes a row instead. Postgres, Redis, the backend, nginx and one sample
upstream, brought up from the committed compose file:

| Step | Result |
|---|---|
| `insert into application … 'sample'`, restart backend | `apps.conf`, `apps.status`, `breakglass.apps`, `breakglass.status` in the volume; both status files `ok` |
| `sample.apps.example.local` through the running proxy | **302** into the login flow, no break-glass header |
| stop nginx, start `nginx-breakglass` | **200**, `x-openberat-breakglass: active` |
| a hostname not in the table | **404** from the default server |
| `insert … 'wiki'`, restart backend, swap again | **200** — a row became a break-glass host with nobody editing a file |
| `delete from application where slug='wiki'`, restart, swap | **404** — it left with the row; `sample` still 200 |
| back to nginx | **302**, no break-glass header |

And the property the file extension exists for, checked directly rather than
reasoned about:

```
$ docker compose exec nginx nginx -T | grep -c "breakglass/upstream.inc"
0
$ docker compose logs nginx | grep -ci "conflicting server name"
0
```

`nginx.conf` globs `conf.d/generated/*.conf` and the generated break-glass file
is `breakglass.apps`, so none of it reaches the running configuration. Had it,
every application would have had a second `server` block with no `auth_request`
in it, and `nginx -t` would have said the configuration was fine.

### Every fix from the two security commits, run rather than read

The first commit was verified by probing a rebuilt nginx image for status codes,
which covers what a *location* answers and nothing about what a *limit* or a
*handler* does. This is the rest of it, on running containers.

**The rate limits fire, and only where they should.** nginx alone, no upstreams;
a `429` is answered from the preaccess phase without the limiter ever looking
for a backend, so the absent upstreams do not affect the count.

| Location | Requests | Result |
|---|---|---|
| `auth.…/realms/openberat/login-actions/authenticate` | 60, concurrent | **39 × 429**, 21 through — `burst=20` plus one refill, exactly the zone |
| `auth.…/resources/…` on the same host | 60, concurrent | **0 × 429** — deliberately unlimited, so a login page's dozen assets never meet the limiter |
| `portal.…/api/me` | 300, concurrent | **232 × 429**, 68 through |

The `/api/*` figure took two attempts and the first one is the lesson: at 30
concurrent requests each waiting 3 s on an absent backend, the offered load is
about 10 r/s — under the zone's 50 r/s, so nothing was limited and the run
looked like a missing directive. The limiter is a rate, so the test has to be
one. `nginx -T` on the running container was the tie-breaker: the directive was
there all along.

**Keycloak's own database carries the brute-force settings**, not just the file.
The export imported cleanly (`Realm 'openberat' imported`) and `kcadm.sh get
realms/openberat` reads back:

```
"bruteForceProtected" : true,   "permanentLockout" : false,
"failureFactor" : 10,           "waitIncrementSeconds" : 60,
"maxFailureWaitSeconds" : 900,  "minimumQuickLoginWaitSeconds" : 60
```

`kcadm.sh get realms` on the same instance answers
`[{"realm":"openberat"},{"realm":"master"}]` — the realm nginx used to publish is
a real realm on every install, not a hypothetical one.

**The admin API answers a sentence where it used to answer an outage.** Called
on the `core` network the way nginx leaves a request — the `X-Auth-*` family
rewritten from the verified identity, plus the session cookie `/api/*` forwards
(ADR-0019) — against a running backend, Postgres and Redis:

| Call | Before | Now |
|---|---|---|
| `slug: "evil; return 200"` | 503 | **400** `slug must be lower-case letters and digits, separated by single hyphens` |
| `external_hostname: "bad host.example"` | 503 | **400** `external_hostname must be lower-case letters and digits, separated by single dots or hyphens` |
| `path_pattern: "/reports"` | **201 — stored, granting the subtree** | **400** `path_pattern is a subtree and has no exact-path form: write /reports/*, which matches /reports and everything below it` |
| `path_pattern: "/reports/*"` | 201 | **201** — the form that reads correctly is still accepted |
| the same calls with `X-Auth-Groups: OpenBerat-Users` | 403 | **403** |
| the same calls with no `Origin` | 403 | **403** |

One thing this run found that was not being looked for: the first attempt sent
no `Cookie` header and **every** call answered `503`, including the two that
should have been `403`. That is the `indexed` middleware (`api.rs`) refusing an
authenticated request whose session key it cannot derive — before any admin
handler runs. Fail-closed, and it means the management plane cannot be reached
by a caller holding identity headers but no session at all, which is a stronger
statement than the `403`s above.

## A second security read, and what it measured

Same method as the read above and the same kind of finding: a rule the
repository already writes down, applied to a file that did not follow it. The
first two are one omission read twice — `protected.inc` pinned four headers, and
nginx forwards every header no directive overwrites.

### The `X-Forwarded-*` family the proxy did not write

Measured against the **break-glass** configuration, which needs no identity
chain: a generated block pointing at `traefik/whoami`, which echoes the request
headers back. nginx images built from the commit before the fix and from the
commit after, one request each, carrying six forged headers.

| Header sent by the client | Before | After |
|---|---|---|
| `X-Forwarded-Host: evil.attacker.tld` | **`evil.attacker.tld`** | `app.apps.example.local` |
| `X-Forwarded-Port: 1337` | **`1337`** | `443` |
| `X-Forwarded-For: 203.0.113.9` | **`203.0.113.9, 172.19.0.1`** | `172.19.0.1` |
| `X-Forwarded-Prefix: /pwn` | **`/pwn`** | absent |
| `X-Original-URL: /admin` | **`/admin`** | absent |
| `X-Rewrite-URL: /admin` | **`/admin`** | absent |

The `X-Forwarded-For` row is the whole argument against
`$proxy_add_x_forwarded_for`: it did not replace the client's value, it appended
the real address *after* it, so the leftmost entry — the one every reader and
every framework takes as the client — was the forged one. Keycloak reads exactly
that entry (`KC_PROXY_HEADERS=xforwarded`), which is why `keycloak.inc` carried
the same line and every login event the realm recorded named an address the
client chose. `limit_req` was never affected: it keys on `$binary_remote_addr`.

The other three rows are absent rather than corrected, and that is the
difference between the two halves of the fix: `X-Forwarded-Host` and `-Port`
are values this proxy owes the upstream, and `X-Forwarded-Prefix`,
`X-Original-URL` and `X-Rewrite-URL` are values it has nothing to say about — a
framework that honours one re-routes off a client header, which is the PEP
deciding one path and the upstream serving another.

Both configurations still pass `nginx -t`, and the CI check that found them is
mutation-tested: dropping one `proxy_set_header` line back out turns it red.

### `$portal_origin` renders what the literal did

`nginx -t` proves the syntax of `return 302 $portal_origin/denied?app=$host;`
and nothing about the value, so the map and the return were run together on a
throwaway configuration and the answer read off the wire:

```
Location: https://portal.apps.example.local/denied?app=wiki.apps.example.local
```

Byte-identical to what the hardcoded form produced. The point of the change is
not the value but where it is written: `errors.inc` is included by every block
`render_apps_conf` generates, so a hostname in it is the deployment's hostname
inside the one file that is meant to be identical everywhere.

### The build context was 2.5 GB

Read off the nginx build, which uses the repository root as its context:

| | Context sent to the daemon |
|---|---|
| Before | **2.526 GB** |
| After | **171.6 kB** |

`backend/.dockerignore` lists `target/`, and it applies only to the backend's
own build, whose context is `./backend`. The nginx and keycloak builds start a
level up, where nothing excluded it. `certs/` was in the same position: no
`COPY` reaches it, so the private key was in no layer — it was simply handed to
the daemon on every build.

**The `**/` is load-bearing and was measured wrong once.** A Docker ignore
pattern is matched against the whole path, not segment by segment, so a bare
`target/` matches a top-level directory and misses `backend/target/`. The first
attempt used it and the context did not move.

### The group filter closed the spelling it was tested with

ADR-0008 mitigation 1 was measured on the lab and the measurement was real: with
`(cn=OpenBerat-*)` on the group mapper, a user in an AD group named
`Payroll,OpenBerat-Admins` gets a claim without it, and emptying the filter puts
the name in the next token and `admin: true` in `/api/me`. The name it used
carries no prefix, and the filter's prefix clause is what rejects it.

Put the prefix in front and the same attack passes the same filter. Measured
against OpenLDAP holding all three names, `ldapsearch` on `ou=Groups`:

| Filter | Groups returned |
|---|---|
| `(cn=OpenBerat-*)` — as shipped | `OpenBerat-Finance`, **`OpenBerat-Payroll,OpenBerat-Admins`** |
| `(&(cn=OpenBerat-*)(!(cn=*,*)))` | `OpenBerat-Finance` |

`Payroll,OpenBerat-Admins` is excluded by both, which is the row the original
measurement covered. The comma is not special in an LDAP filter string — RFC
4515 escapes only `\`, `*`, `(`, `)` and NUL — so `(!(cn=*,*))` is a plain
substring test for "contains a comma", and it is the clause that speaks to the
injection. The prefix is a naming convention and says nothing about it.

Keycloak accepts the two-clause filter: the realm export imports clean
(`Import finished successfully`) and `kcadm get components` reads it back
verbatim as `['(&(cn=OpenBerat-*)(!(cn=*,*)))']` with `mode: READ_ONLY`
unchanged.

**Run end to end on the lab** (2026-09-07, `verify-commafilter2.sh`). AD holds
`cn=OpenBerat-Payroll,OpenBerat-Admins` (`sAMAccountName` `payroll-escalation2`,
which is how it goes in at all — samba-tool builds the DN by concatenation and
the comma ends the RDN) with **`labnested`** in it. Not `labuser`: it is in
`OpenBerat-Admins` for real now, so it could not tell an escalation from its own
membership.

| Group mapper filter | `groups` claim | `/api/me` | `/api/admin/applications` |
|---|---|---|---|
| `(&(cn=OpenBerat-*)(!(cn=*,*)))` — shipped | `null` | `admin: false` | **403** |
| `(cn=OpenBerat-*)` — the old one | `["OpenBerat-Payroll,OpenBerat-Admins"]` | `groups: [… "OpenBerat-Payroll", "OpenBerat-Admins" …]`, `admin: true` | **200** |

The middle column is the whole mechanism in one line: one group in the claim,
**two** in `/api/me`, and the second is `ADMIN_GROUP`. Nothing between AD and the
backend attacked anything — oauth2-proxy joins the array with commas and the
backend splits it back, and a name carrying a comma comes apart at a boundary
the directory never had.

Restoring the filter is not the end of it, which the run also shows: Keycloak
**imports** the group while the filter is wide and narrowing it again leaves the
group behind (`OpenBerat-Payroll,OpenBerat-Admins` still listed in step 3). The
harness deletes it and re-reads the chain — claim `null`, `admin: false`, 403 —
because a restoration asserted rather than proved is how a lab keeps a hole
nobody meant to leave. The fixture ships both spellings now: one that the prefix
clause refuses and one that only the comma clause does.

## What a second backend instance would cost the decision cache

Measured for [ADR-0031](adr/0031-decision-cache-multi-instance.md), which had to
choose between moving the cache into Redis and broadcasting its invalidations.
Both runs are from a throwaway `redis:7-alpine` on the compose `core` network —
the same hop a second backend instance would make — against the lab's running
`redis` (`verify-ha-cache.sh`, `verify-ha-pubsub.sh` on the lab host).

**A round trip, which is what a shared cache would add to every decision.**
`redis-benchmark -t get -d 600`, a 600-byte value standing in for an entry
carrying the identity and a few rules:

| Connections | p50 | Throughput |
|---|---|---|
| 1 | **0.039 ms** | 20 555 r/s |
| 16 | **0.167 ms** | 51 867 r/s |

`redis-cli --latency` over 489 `PING` samples on one connection reads
min 0 ms, avg 0.18 ms, max 2 ms.

The figure that decides the ADR is not the 2 ms of N-01 — 0.039 ms fits inside
it easily. It is that **the whole decision measures 11–29 µs** end to end today,
so a round trip is 1.5–6× the cost of the thing it would be added to, and a page
of 50 assets makes 50 of them.

**Publish to delivery, which is what broadcast invalidation would add to the
kill switch.** A subscriber and a publisher each holding an open connection, the
subscriber's RESP frames read with shell builtins so nothing but the round trip
is inside the window:

| Cycles | Wall clock | Per publish→delivery |
|---|---|---|
| 5 000 | 1.38 s | 276 µs |
| 20 000 | 5.77 s | 288 µs |
| 20 000 | 5.63 s | 281 µs |

This is an **upper bound**: the loop also pays for the shell's own `printf` and
thirteen `read` builtins per cycle. Against ADR-0016's 5 s kill-switch target,
of which the measured switch spends 0.085 s, the margin is four orders of
magnitude.

Two harness notes, because both produced a wrong number first. `redis-cli`
buffers its stdout when it is not a terminal, so a subscriber writing to a file
delivers nothing until it exits — the subscriber here is busybox `nc`, which
does not. And busybox `date` silently drops `%N`: `date +%s%N` returns whole
seconds, so the first run reported every delivery as 0 µs. The clock above is
`/proc/uptime` read with the shell builtin, at 10 ms, amortised over thousands
of cycles.

**Not measured:** anything about two backend instances actually running. Nothing
has been deployed twice; these are the two transport costs the decision turns
on, and the ADR is explicit that its subscription-liveness rule is a design
commitment rather than a measurement.

## `DATABASE_URL` as an override, and what the default hides

Three checks behind INSTALL.md §3, "Pointing at a Postgres you already run".
Two were run on this host; the third was read out of the dependency's source,
which is said here rather than implied.

**The interpolation, both ways.** `docker compose config` against an `.env`
built from `.env.example` renders
`postgres://openberat:…@postgres:5432/openberat`; with `DATABASE_URL` set to an
external server it renders exactly that string, query parameters included. The
form is `${DATABASE_URL:-postgres://openberat:${POSTGRES_PASSWORD}@postgres:5432/openberat}`
— nested substitution inside a default, which compose v5.5.1 resolves. `:-` and
not `-` is what makes an **empty** `DATABASE_URL=` in `.env` take the bundled
service: `.env.example` ships the variable empty, and `-` would hand sqlx an
empty string instead.

**`POSTGRES_PASSWORD` stays required even when nothing connects to the bundled
service.** `docker run … -e POSTGRES_PASSWORD= postgres:17-alpine` exits with
`Database is uninitialized and superuser password is not specified`, so an
operator who moves the database out and clears the password gets a
restart-looping container rather than an idle one.

**sqlx defaults to `sslmode=prefer`, which falls back to plaintext without
saying so.** Read, not run: `sqlx-postgres` 0.9.0 marks `PgSslMode::Prefer`
`#[default]` and documents it as "First try an SSL connection; if that fails,
try a non-SSL connection". Its URL parser accepts `sslmode`, `sslrootcert`,
`sslcert` and `sslkey`, so `verify-full` is available and is what INSTALL
recommends — over a socket to a container next door the default costs nothing,
over a network it is the decision chain in the clear. And the root store it
verifies against is not the container's: `backend/Cargo.toml` asks for
`tls-rustls-ring`, which sqlx 0.9 resolves to `tls-rustls-ring-webpki` →
`webpki-roots`, the public CA list compiled into the binary (`Cargo.lock` has
`webpki-roots` and no `rustls-native-certs`). An internal CA therefore has to
arrive as `sslrootcert=`; adding it to `/etc/ssl/certs` in the image does
nothing.

**Not measured:** an installation actually pointed at an external Postgres.
Nothing here connects to one; what is checked is what compose renders, what the
bundled image refuses, and what the client does when the URL says nothing about
TLS.

## The retention job's first pass, and the order the comment promised

`main.rs` said a fresh install has its partitions "before the first decision is
written". The pass was `tokio::spawn`ed, so that was a race the code usually won
and never imposed. Run on this host against a throwaway `postgres:17-alpine`,
with the month's partition dropped and another session holding
`lock table audit_event in access exclusive mode` — which is what a running
`pg_dump` (INSTALL.md §9) does to a restart:

| Binary | Lock held | Listener bound after | Month's partition at that moment |
|---|---|---|---|
| spawned (before) | 6 s | **0.06 s** | no |
| awaited (after) | 6 s | **5.57 s** | **yes** |
| awaited (after) | 20 s | **10.09 s** | no, and it says so |

The first row is the bug: the process was serving `/decide` — and writing audit
rows into `audit_event_default` — while the partition those rows belong in did
not exist. The second is the promise kept: startup waits for the lock, then
binds. The third is why the await is bounded by `RETENTION_FIRST_PASS`: past
10 s it logs *the first audit retention pass did not finish in time; serving
anyway, the daily run will retry* and serves, because a backup that outlasts the
timeout must not turn a restart into an outage.

`/readyz` answers 200 immediately after that timed-out pass and again once the
lock is released, so cancelling the query does not leave the pool damaged.

**Not measured:** the daily tick itself. `interval_at` starts one interval out
rather than firing immediately, which is what stops the awaited pass being run
twice, and nothing here waits 24 h to watch the second one.

## MFA for the management plane, and the bridge it needed

[ADR-0032](adr/0032-admin-mfa.md) had one thing to establish on the lab: the
shape of the condition. Keycloak's conditional step keys on a **role** and
`ADMIN_GROUP` arrives as a **group**, so the bridge is a realm role
(`openberat-mfa`) mapped onto the group — inherited by every member, so nothing
is assigned to a user. Built with `kcadm` first, then written into the realm
export and rebuilt from it.

`verify-adminmfa.sh`, four stages, each a real portal login driven with curl:

| Stage | After the password | `/api/me` | `/api/admin/applications` |
|---|---|---|---|
| `labuser`, not in the group | no form — logged in | 200 | 403 |
| `labadmin`, no OTP credential yet | **OTP enrolment** (QR + secret) | 200 after enrolling | 200 |
| `labadmin`, credential exists | **OTP challenge**, correct code | 200 | 200 |
| `labadmin`, wrong code | OTP challenge, still the challenge | **302** | **302** |

The last row is the control: a refused code leaves no session at all, not a
session with fewer rights.

**Four things the run cost, none of them the design.**

- **The condition's config key is `condUserRole`, not `condition-user-role`.**
  Written with the wrong name the condition is accepted, stored and silently
  never true — the first run logged an admin straight in with no OTP page, which
  looks exactly like a flow that was never bound. `kcadm get
  authentication/config-description/conditional-user-role` is what settles it.
- **`kcadm update authentication/flows/<flow>/executions` needs `-n`.** Without
  it kcadm reads the resource first to merge, gets an array back, and fails with
  a Jackson deserialisation error; the requirement stays `DISABLED` and the
  sub-flow is dead.
- **A sub-flow created by `create …/executions/flow` lands first, not last.** It
  sat above `Username Password Form`, where the role condition is evaluated
  before there is a user to have a role — always false, so the admin is never
  asked. `authentication/executions/<id>/lower-priority` moves it.
- **A refused OTP is a failed login, and the realm is `bruteForceProtected`.**
  The stage that tests a wrong code locks the account, and every stage after it
  reads "password form" instead of what it is measuring. The harness clears
  `attack-detection/brute-force/users/<id>` between stages, and deletes any
  existing OTP credential first so that "first login" is really the first.

Two smaller ones. Keycloak's enrolment page carries the raw secret in
`name="totpSecret"` — the base32 in the QR is that string encoded, so a harness
computing a code uses the string's bytes as the HMAC key, not a base32 decode.
And a code already spent on enrolment is refused on the next login, so two
stages seconds apart have to wait for the next 30 s window: TOTP replay
protection, not a wrong code.

## How long a session actually lasts, and what the Live tab counts

Two runs on the lab, because the question had two halves and only one of them
needed 33 minutes of waiting.

**The idle half** (`verify-sessionlife.sh`). Two sessions for the same user, A
abandoned and B touched every 5 minutes — B is the control, because if B died
too then something other than the idle timeout did it. Redis is read *before*
the dead cookie is presented, since presenting it is what makes oauth2-proxy
notice:

| | at t0 | after 33 min |
|---|---|---|
| A (abandoned) | `/api/me` 200, key TTL 604 799 s | key still there, TTL 602 698 s, **`/api/me` 302** |
| B (touched every 5 min) | `/api/me` 200 | `/api/me` **200** |

So `ssoSessionIdleTimeout` is real and `cookie_refresh` is what keeps B alive.
The abandoned key kept **six days** of TTL after the credential stopped working,
and only the probe removed it: `exists=0` immediately after the 302.

**The counting half** (`verify-sessioncount.sh`), which reaches the same state
in a second by ending the Keycloak session under a live key rather than waiting
out the idle timeout:

| Step | `/api/me` | key | `/api/admin/sessions` |
|---|---|---|---|
| logged in | 200 | exists | **12** |
| Keycloak session ended | — | exists | **12** |
| past `cookie_refresh` (5 m) | **302** | — | — |
| after that probe | — | gone | **11** |

The screen counted a credential that no longer worked, and stopped only because
something used it. That is the one wrong answer ADR-0028 says the list exists to
avoid, and the ADR now says so.

**What changed:** `cookie_expire` is `10h`, the realm's own
`ssoSessionMaxLifespan`, instead of 168 h. It does not make the count exact —
nothing short of asking Keycloak per subject would, and ADR-0028 refuses to
decrypt the session — but it bounds the window a dead key can be counted in by
the life of the session it stands for, rather than by a week.

**Two harness lessons.** The observer needs touching too: the first run's
`/api/admin/sessions` calls used an admin jar minted at t0 and idle for the same
33 minutes, so they came back empty — the measurement instrument idled out along
with the thing it was measuring. And `oauth2-proxy` does not refuse a cookie the
moment Keycloak ends the session: it revalidates on `cookie_refresh`, so the
five minutes between step 2 and step 3 above are the configured interval, not a
delay in the finding.

## The production shape of Keycloak, tried before it was written

`INSTALL.md` §5's "Keycloak in production" is not from the manual: the shape was
built and run on the lab first, in a throwaway container against a `keycloak`
database on the bundled Postgres, with the serving stack left alone. The
container, the image and the database were removed afterwards and the portal
still answers 302.

- **`start --optimized` exits 2 on a build-time option supplied at runtime.**
  `KC_HEALTH_ENABLED=true` in the environment produced one line —
  *the following build time options have values that differ from what is
  persisted* — and a container that was simply gone. Nothing in that output
  reads like an error, which is why INSTALL puts the variable in the builder
  stage.
- **The two-stage image is enough.** `kc.sh build` with `KC_DB=postgres` in a
  builder, `COPY --from=builder /opt/keycloak/`, then the theme on top: Keycloak
  26.3.5 started in **30.9 s**, imported the realm — `Realm 'openberat'
  imported`, `Import finished successfully` — and listened on 8080.
- **The `sub` survives the container.** `labuser` read `47811b5c-…` on the first
  boot; the container was then destroyed and recreated against the same
  database and it read `47811b5c-…` again. That is the whole reason this section
  exists: on the shipped H2 the same act gives every federated user a new id,
  and `audit_event.actor_sub` keys on it.
- **The realm is imported once.** The second boot logged `Realm 'openberat'
  already exists. Import skipped`, so on a persistent database editing
  `keycloak/realm/` does not reach a running installation — the operational
  consequence INSTALL now names.
- **`KC_HOSTNAME` is what the discovery document says.** Read from a container
  on the same network: `"issuer": "https://auth.apps.example.local/realms/openberat"`
  while the server itself was reachable only as `kc-prod:8080`.

**Not measured:** a browser login against the optimized container. It was never
put behind nginx — the running stack kept serving throughout — so what is proved
is that it starts, imports, persists identities and reports the right issuer.

## TEST — one login end to end with `APPS_DOMAIN` set

Each part of the domain variable was measured on its own when it was written;
the chain between them was not. The lab was still serving the pre-variable
build, with `apps.example.local` written into its files, so the run is also the
migration: `APPS_DOMAIN=apps.example.local` into `.env` — the value it already
had — the changed files copied in, `docker compose build nginx keycloak
backend`, `up -d`.

**Identical behaviour is the whole result**, and it is what came back:

| | |
|---|---|
| `verify-install6.sh` (INSTALL §6 run literally) | **ALL OK** |
| `verify-pattern.sh` | **PASS** |
| `verify-kill.sh` | POST 0.049 s, access gone **0.070 s** after the button |
| portal, anonymous | 302 |
| `/api/me` with a session | 200 |
| `jenkins.apps.example.local`, authorised / anonymous | 200 / 302 |

And the four places the value now comes from a variable, read out of what is
running rather than out of the file that was edited:

- nginx: `server_name portal.apps.example.local` and `auth.apps.example.local`
  in `/etc/nginx/conf.d/*.conf`, rendered by the image's own entrypoint from
  `*.conf.template`.
- oauth2-proxy: `OAUTH2_PROXY_OIDC_ISSUER_URL`, `_REDIRECT_URL`,
  `_COOKIE_DOMAINS`, `_WHITELIST_DOMAINS` — all four carrying the domain, read
  from the container's own environment.
- Keycloak: `redirectUris: ["https://portal.apps.example.local/oauth2/callback"]`
  and the matching `webOrigins`, read back through `kcadm` after the import
  resolved `${APPS_DOMAIN}`.
- The session cookie's TTL is 36000 s, which is the other change in the same
  deployment (`cookie_expire`, above) and not part of this one.

**One thing the migration cost, and it is a lab-only trap.** The lab is a
*copy* of the repository rather than a checkout, so unpacking the new files left
both `00-auth.conf` and `00-auth.conf.template` in `nginx/conf.d/` — the old
file and the template that replaced it, which the image would have baked in
together. A real installation rebuilds from a checkout and never sees it; a copy
has to delete what the rename left behind.

**Also found by doing it:** the lab's Keycloak had no `APPS_DOMAIN` in its
environment at all, which is why the first attempt at the new realm export
stopped it dead — `Invalid client openberat-proxy: A redirect URI is not a valid
URI`, the unresolved `${APPS_DOMAIN}` reaching Keycloak's URI validation. A
placeholder with nothing behind it fails loudly at import, which is the right
direction for it to fail in.
