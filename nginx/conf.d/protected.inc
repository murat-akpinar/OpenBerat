# SPDX-FileCopyrightText: 2026 OpenBerat contributors
# SPDX-License-Identifier: GPL-3.0-or-later

# Everything a protected location needs. Included *inside* a location, and the
# reason it is one file: forget any line of it in one location and it is not
# that application that falls but the security claim of the whole product
# (docs/05, "Header spoof protection").

# One page of fifty assets is fifty decisions, so the burst has to absorb a
# page load and the rate has to survive a few users behind one address.
limit_req zone=decisions burst=100 nodelay;

auth_request /decide;

# One per location — a second one silently overrides the first, which is why
# the chain lives inside the backend (ADR-0002, README rule 2).
error_page 401 = @signin;
error_page 403 = @denied;
error_page 500 502 503 504 /unavailable.html;

# auth_request passes no response body, so these headers are the only channel
# the verified identity can travel on (docs/02, response contract).
auth_request_set $auth_subject  $upstream_http_x_auth_subject;
auth_request_set $auth_username $upstream_http_x_auth_username;
auth_request_set $auth_email    $upstream_http_x_auth_email;
auth_request_set $auth_groups   $upstream_http_x_auth_groups;
auth_request_set $auth_cookie   $upstream_http_set_cookie;
auth_request_set $deny_reason   $upstream_http_x_deny_reason;

# ADR-0006 lives or dies on this line: while oauth2-proxy performs
# cookie_refresh the new cookie comes back on the *subrequest's* response, and
# nothing relays it to the browser unless it is lifted out by hand.
add_header Set-Cookie $auth_cookie always;
# One add_header in a location drops every header set above it, so the shared
# set is pulled back in here — this is the only place that covers a generated
# application block (README rule 19). No CSP: that one belongs to whoever wrote
# the application's pages, not to the proxy in front of them.
include /etc/nginx/conf.d/security.inc;

# --- Feature Start ---
# Rewritten from the verified identity, unconditionally. A client can send its
# own X-Auth-Groups: whatever it likes, so these are not "set if absent" — they
# overwrite, and the request-side names are cleared outright so an inherited
# copy cannot ride through under a different spelling.
# --- Feature End ---
proxy_set_header X-Auth-Subject    $auth_subject;
proxy_set_header X-Auth-Username   $auth_username;
proxy_set_header X-Auth-Email      $auth_email;
proxy_set_header X-Auth-Groups     $auth_groups;
proxy_set_header X-Auth-Request-Id $request_id;
proxy_set_header X-Auth-Request-User "";
proxy_set_header X-Auth-Request-Preferred-Username "";
proxy_set_header X-Auth-Request-Email "";
proxy_set_header X-Auth-Request-Groups "";
proxy_set_header X-Auth-Request-Redirect "";

# The session cookie never reaches the upstream (README rule 16); the
# application's own cookies do.
proxy_set_header Cookie $upstream_cookie;

proxy_set_header Host              $host;
proxy_set_header X-Real-IP         $remote_addr;
proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;

# WebSocket and SSE. Authorised once, at the upgrade — see below.
proxy_http_version 1.1;
proxy_set_header Upgrade    $http_upgrade;
proxy_set_header Connection $connection_upgrade;

# An *idle* timeout: nginx resets it on every read from the upstream, so it
# cuts an idle long-lived connection and never a busy one. Revocation on an
# active WebSocket is outside the N-03 guarantee and this does not change that
# (ADR-0016, measured in docs/07 — README rule 11).
proxy_read_timeout 300s;

# ponytail: nginx defaults client_max_body_size to 1m, so an application that
# accepts uploads answers 413. Raise it per application when one does.
