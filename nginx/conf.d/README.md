# nginx configuration

nginx plays the **PEP** role here: it intercepts every request and asks for an
authorisation decision. Reference pattern and verified details:
`docs/07-references.md`.

| File | Contents | |
|---|---|---|
| `openberat.conf` | The `:80` → `:443` redirect and the default `server`, which answers 404 | now |
| `00-auth.conf` | http-level only: the `map` that strips the session cookie, and the WebSocket upgrade map | now |
| `10-portal.conf` | Portal and admin: frontend static files, `/api/*` → backend — **and the two anonymous hosts**, `/oauth2/*` and Keycloak's `/realms/` + `/resources/` | now, minus `/api/*` |
| `generated/apps.conf` | Protected applications (`*.apps.<domain>`) → upstream. **Not in this repository**: the backend renders it from the `application` table into a shared volume, and the loop in `docker-entrypoint.d/40-generated-reload.sh` installs it (ADR-0011) | now |
| `errors.inc` | `@signin`, `@denied`, and the `/unavailable.html` location — included at **server** level | now |
| `decide.inc` | `location = /decide` — included at **server** level | now |
| `protected.inc` | `auth_request` and the whole header rewrite — included inside a **location** | now |

The three shared pieces are `.inc` and not `.conf` for a mechanical reason:
`nginx.conf` includes `conf.d/*.conf` into the `http` block, and a bare
`location` there is a syntax error. An earlier draft of this table had them all
in `00-auth.conf`, which cannot work.

The rules below apply to all of them.

## Do not skip these

1. **`error_page 401 = @signin`, and the return address never goes in the query
   string.** The `=` means "answer with the code the handler returns", and it
   only bites when the handler is a **proxied** response: measured side by side,
   a `return 302` handler answers 302 with or without it, while a `proxy_pass`
   handler without it answers **401 with a `Location` the browser will not
   follow** (`docs/07`). `@signin` proxies to `/oauth2/start` with the target in
   `X-Auth-Request-Redirect`, because nginx cannot percent-encode
   `$request_uri`: `?rd=$scheme://$host$request_uri` hands the client's own
   `&`-separated query string to oauth2-proxy as extra parameters of that
   request — the user comes back with everything after the first `&` gone, and
   a client-supplied `rd` rides along as a second one. The `?` in
   `rewrite ^ /oauth2/start? break;` is what drops the original query string;
   without it the injection is back.
2. **`auth_request` is one per location.** The chain lives inside the backend
   (ADR-0002). Do not write a second `auth_request`; it silently overrides the first.
3. **Strip incoming `X-Auth-*` headers — in both directions.** In every
   protected location — **and in the portal host's `/api/*` location**: the
   backend's admin check trusts `X-Auth-Request-Groups`, so a client sending
   that header straight to `/api/admin/*` must lose it before the backend sees
   it. Keep it in a shared `include` file and pull it in everywhere — forget it
   in one place and the entire system's security claim falls. The rewrite source
   is `/decide`'s response: on a 200 it returns
   `X-Auth-Subject/-Username/-Email/-Groups`, lifted with `auth_request_set` and
   written upstream with `proxy_set_header` (`docs/02`, response contract).
   **The `/decide` include needs its own copy of the stripping**, because the
   subrequest inherits the main request's headers verbatim (measured, `docs/07`)
   and the upstream include never runs on that path: a client's
   `X-Auth-Request-Groups` otherwise arrives at the PDP untouched. Clear each
   name with `proxy_set_header X-Auth-Request-Groups "";`.
4. **`proxy_pass_request_body off`** + `Content-Length ""` — no body goes to the subrequest.
5. **`/decide` must not be reachable from outside** (`internal;`). It has to be
   `internal;` specifically. nginx **skips the whole access phase for a
   subrequest**, and `allow`/`deny` live in that phase: measured side by side,
   `internal` still returned 404 on a direct request while `deny all` in the
   same location did nothing at all (`docs/07`). An IP ACL on `/decide` would
   test clean and constrain nothing.
6. **Pass the original request's details to `/decide`.** In the subrequest the URI
   is `/decide`; the backend sees host/path/method only through headers:
   `X-App-Slug`, `X-Original-URI`, `X-Original-Method`, `X-Real-IP`,
   `X-Request-Id`. Anything missing means a fail-closed DENY. **`X-App-Slug` is
   written as a constant in every `server` block** — because the subrequest
   inherits the main request's headers, `Host` is client-controlled.
7. **`error_page 403` goes to another host.** The "no access" page lives on the
   portal host, and nginx cannot serve another `server` block internally → a
   **302** via `@denied`. If the portal host gets a DENY on its way through
   `auth_request` the result is an infinite loop; the portal must be open to
   every authenticated user (`docs/02`, "Anonymous endpoints").
8. **`/oauth2/*` and Keycloak's host are anonymous.** Put either behind
   `auth_request` and nobody can log in — you would need to be authenticated in
   order to authenticate. Keycloak is the easy one to forget, because it looks
   like infrastructure rather than a page the browser visits. Proxy only
   `/realms/*` and `/resources/*` on the Keycloak host — never `/admin` (the
   Keycloak admin console) or `/metrics`. The Keycloak host defaults to
   `auth.apps.<domain>`, covered by the wildcard certificate. It carries the
   same session-cookie strip as item 16: Keycloak has no use for our session
   cookie, and forwarding it hands a credential valid for every host on
   `.apps.<domain>` to a service that access-logs requests.
9. **Timeout budget.** For `/decide`: `proxy_connect_timeout 1s; proxy_read_timeout 2s;`
   The default is 60 seconds; if the backend slows down, workers fill up and
   everything stops. `error_page 500 502 503 504 /unavailable.html;` → a local
   static page, never a bare 500. **No `=` on that one**, unlike item 1: with
   it, nginx answers with the status the handler produces — 200 for a static
   file — and an outage becomes indistinguishable from a working page. Without
   it the original 502/503 reaches the client and the page explains it. The
   two rules pull in opposite directions because they are answering different
   questions: item 1 needs the handler's status, this one needs the error's.
10. **Relay `Set-Cookie`.** `auth_request_set $auth_cookie $upstream_http_set_cookie;`
   plus `add_header Set-Cookie $auth_cookie always;` Without it `cookie_refresh`
   does not work.
11. **`proxy_read_timeout 300s` on protected locations — and know what it does
   not do.** A WebSocket/SSE connection is authorised once, at the upgrade. This
   timeout is an **idle** timeout: nginx resets it on every read from the
   upstream, so it cuts an idle connection and never a busy one. Revocation on
   an active long-lived connection is outside the N-03 guarantee (ADR-0016); do
   not write a test asserting otherwise.
12. **No internal redirects in a location that carries `auth_request`.** An
   internal redirect restarts the access phase, so the subrequest runs twice —
   the second one overwrites `$auth_cookie` with an empty string and the
   refreshed session cookie never reaches the browser (measured, `docs/07`).
   It also doubles the decision load. `try_files` with `=404` as the last
   argument serves files in place; a bare URI, a named location, an `index`
   directive or a directory match all redirect.
13. **`client_max_body_size`** defaults to 1m — applications that accept file
   uploads will return 413.
14. **Never answer with `return` in a location that carries `auth_request`.**
   `return` belongs to the rewrite module and runs in the rewrite phase — before
   the access phase where `auth_request` lives. The subrequest never fires, the
   location is wide open, and `nginx -t` says the configuration is fine
   (measured, `docs/07`). Use `proxy_pass`, or `try_files` with `=404` (item
   12), so the answer comes from the content phase. This is the one to watch in
   ADR-0011's generated blocks and in any hand-written maintenance page.
15. **Raise `proxy_buffer_size` on every location whose *response* carries the
   group list.** oauth2-proxy returns every group of the user comma-joined in
   one `X-Auth-Request-Groups`, and `/decide` returns the same list as
   `X-Auth-Groups`. nginx reads a response header block into a **single**
   buffer of `proxy_buffer_size` — one page, 4 KB — and answers 502 above it,
   which `auth_request` turns into a **500 for the client**: a total lockout of
   the users with the most AD groups, arriving without a single warning from
   `nginx -t`. Measured: it breaks between 100 and 200 groups (`docs/07`).
   `proxy_buffer_size 32k;` **plus `proxy_buffers 4 32k;`** — raising the first
   alone makes nginx refuse to start, because `proxy_busy_buffers_size`
   defaults to twice it and must stay under the pool minus one buffer.
16. **Strip the session cookie before proxying upstream.** The `_oauth2_proxy`
   cookie is removed from the `Cookie` header (a `map` rewriting `$http_cookie`
   in the shared include); the application's own cookies pass through. An
   upstream that receives the session cookie is holding — and probably
   access-logging — a credential valid for every host on `.apps.<domain>`
   (ADR-0015, `docs/05`). **One exception, written out where it is made:** the
   portal's `/api/` location keeps it, because the backend derives the
   ADR-0019 session key from it and the portal never reaches `/decide` — a
   signed-in user who has not opened an application yet would otherwise be
   invisible to the kill switch. That upstream is the PDP, which is handed the
   same cookie on `/decide` anyway.
17. **Every variable `log_format` names must be declared at http level.** nginx
   refuses to start if it names one nothing declared, and the things that
   declare `$auth_username` and `$deny_reason` are the protected locations —
   which on a fresh install **do not exist**, because no application has been
   defined yet. Deleting the hand-written application blocks was enough to
   produce `unknown "deny_reason" variable` and a proxy that would not boot, on
   exactly the install where nobody has a working system to compare against.
   `auth_request_set` is legal in the `http` context; the copies in
   `00-auth.conf` are there for declaration, and a location that sets them for
   real overrides them.
18. **A reload does not close an established WebSocket, and leaves a worker
   behind.** ADR-0011 reloads nginx on every application change. The old worker
   goes to `worker process is shutting down` and keeps serving its open
   connections under the **old** configuration — measured across two reloads,
   the same PID still shutting down 133 s later with a live connection on it
   (`docs/07`). `worker_shutdown_timeout` is unset and nginx's default is no
   timeout, so one worker accumulates per reload for as long as any long-lived
   connection is open. Two things follow: a policy change does not reach a
   connection that is already up (ADR-0016 states this; it is measured), and a
   busy admin session can grow the worker count without bound.
