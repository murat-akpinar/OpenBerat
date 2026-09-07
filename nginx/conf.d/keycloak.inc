# SPDX-FileCopyrightText: 2026 OpenBerat contributors
# SPDX-License-Identifier: GPL-3.0-or-later

# The Keycloak upstream, in one file because two locations on that host serve
# it and the two must not drift. Keycloak runs with KC_PROXY_HEADERS=xforwarded
# and builds every issuer and redirect URL out of these headers: a wrong value
# here is a token whose `iss` does not match what oauth2-proxy validates, which
# fails at login and nowhere earlier.

set $keycloak keycloak;   # a variable defers DNS to request time
proxy_pass http://$keycloak:8080;

proxy_set_header Host              $host;
proxy_set_header X-Real-IP         $remote_addr;
# --- Feature Start ---
# `$remote_addr` and not `$proxy_add_x_forwarded_for`, which keeps what the
# client sent and appends to it. Keycloak runs KC_PROXY_HEADERS=xforwarded and
# takes the *first* entry as the client address, so the appending form put an
# attacker-chosen IP on every login event this realm records — successful or
# failed — on the one host every browser is redirected to. `limit_req` was never
# affected (it keys on $binary_remote_addr); the record of a password spray was.
proxy_set_header X-Forwarded-For   $remote_addr;
# --- Feature End ---
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Forwarded-Host  $host;
proxy_set_header X-Forwarded-Port  443;

# Keycloak has no use for our session cookie and forwarding it hands a
# credential valid for every host on .apps.<domain> to a service that
# access-logs requests (README rule 16). Keycloak's own cookies pass through —
# the map removes one name, not the header.
proxy_set_header Cookie            $upstream_cookie;
