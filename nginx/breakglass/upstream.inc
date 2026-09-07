# SPDX-FileCopyrightText: 2026 OpenBerat contributors
# SPDX-License-Identifier: GPL-3.0-or-later

# --- Feature Start ---
# There is no identity to forward, and that is exactly why the X-Auth-* family
# still has to be cleared. An upstream that trusts those headers does not know
# the PEP has been bypassed — leave them alone and break-glass turns from "no
# authorisation" into "authorisation the client writes for itself", which is
# worse than the outage it is fixing.
# --- Feature End ---
proxy_set_header X-Auth-Subject "";
proxy_set_header X-Auth-Username "";
proxy_set_header X-Auth-Email "";
proxy_set_header X-Auth-Groups "";
proxy_set_header X-Auth-Request-User "";
proxy_set_header X-Auth-Request-Preferred-Username "";
proxy_set_header X-Auth-Request-Email "";
proxy_set_header X-Auth-Request-Groups "";
proxy_set_header X-Auth-Request-Id $request_id;

# The session cookie has nothing to do here either, and a browser that still
# holds one would otherwise hand it to the upstream (ADR-0015).
proxy_set_header Cookie "";

# Detectable from outside, so "is break-glass still on?" is answerable with one
# curl rather than by reading a compose file over someone's shoulder.
add_header X-OpenBerat-Breakglass "active" always;

proxy_set_header Host              $host;
proxy_set_header X-Real-IP         $remote_addr;
proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_http_version 1.1;
proxy_set_header Upgrade    $http_upgrade;
proxy_set_header Connection $connection_upgrade;
proxy_read_timeout 300s;
