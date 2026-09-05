# nginx configuration

nginx plays the **PEP** role here: it intercepts every request and asks for an
authorisation decision. Reference pattern and verified details:
`docs/07-references.md`.

| File | Contents |
|---|---|
| `00-auth.conf` | `auth_request /decide` + `error_page 401/403` + the shared `X-Auth-*` stripping |
| `10-portal.conf` | Portal and admin: frontend static files, `/api/*` → backend |
| `20-apps.conf` | Protected applications (`*.apps.<domain>`) → upstream |

## Do not skip these

1. **`error_page 401 = @signin`** — the `=` is mandatory. Without it the response
   code stays 401, the browser does not follow the `Location` header, and the
   user never reaches the login page.
2. **`auth_request` is one per location.** The chain lives inside the backend
   (ADR-0002). Do not write a second `auth_request`; it silently overrides the first.
3. **Strip incoming `X-Auth-*` headers.** In every protected location. Keep it in
   a shared `include` file and pull it in everywhere — forget it in one place and
   the entire system's security claim falls.
4. **`proxy_pass_request_body off`** + `Content-Length ""` — no body goes to the subrequest.
5. **`/decide` must not be reachable from outside** (`internal;`).
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
   like infrastructure rather than a page the browser visits.
9. **Timeout budget.** For `/decide`: `proxy_connect_timeout 1s; proxy_read_timeout 2s;`
   The default is 60 seconds; if the backend slows down, workers fill up and
   everything stops. `error_page 500 502 503 504 = @unavailable` → a local static
   page, never a bare 500.
10. **Relay `Set-Cookie`.** `auth_request_set $auth_cookie $upstream_http_set_cookie;`
   plus `add_header Set-Cookie $auth_cookie always;` Without it `cookie_refresh`
   does not work.
11. **Set `proxy_read_timeout` from N-03.** A WebSocket/SSE connection is
   authorised once; its lifetime determines the revocation delay.
12. **`client_max_body_size`** defaults to 1m — applications that accept file
   uploads will return 413.
