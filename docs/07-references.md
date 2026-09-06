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


## Unverified, to be tested

These claims have not been confirmed against a source; they will be tried in the
Phase 1 lab:

- [x] **Answered: no.** Can an nginx subrequest (the `auth_request` target)
      itself trigger an `auth_request`? The whole access phase is skipped for a
      subrequest — measured above. The chain stays in the backend and the
      internal HTTP call does not disappear.
- [ ] Can Keycloak carry an AD group's `objectSid` into a token claim? If it can,
      ADR-0008 (name vs SID) becomes easy to resolve.
- [x] **Answered: 283 s ordinarily, 330 s at the ceiling.** The real
      deprovisioning delay as measured with `cookie_refresh`. Measured above,
      through the committed chain and with the directory contributing nothing.
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

## Licences (to be verified)

The licence information in `docs/01-landscape.md` was written from memory and
**has not been confirmed**. Licences change often in this space. Each will be
verified on the tool's own page before it is chosen.
