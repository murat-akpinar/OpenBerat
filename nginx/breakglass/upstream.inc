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
proxy_set_header X-Auth-Request-Redirect "";
# Other spellings of an identity that some upstream can be configured to read
# (oauth2-proxy's own, and the generic one). ADR-0021's contract is X-Auth-*,
# so nothing legitimate arrives under these; a client's copy must not either.
proxy_set_header X-Forwarded-User "";
proxy_set_header X-Forwarded-Email "";
proxy_set_header X-Forwarded-Groups "";
proxy_set_header X-Forwarded-Preferred-Username "";
proxy_set_header X-Auth-Request-Access-Token "";
proxy_set_header Remote-User "";
proxy_set_header X-Auth-Request-Id $request_id;

# The session cookie has nothing to do here either, and a browser that still
# holds one would otherwise hand it to the upstream (ADR-0015).
proxy_set_header Cookie "";

# Detectable from outside, so "is break-glass still on?" is answerable with one
# curl rather than by reading a compose file over someone's shoulder.
add_header X-OpenBerat-Breakglass "active" always;
# That add_header drops every one set above it, HSTS included, so the shared
# set comes back in here as protected.inc does (README rule 19).
include /etc/nginx/conf.d/security.inc;

# Pinned for the reason the X-Auth-* names above are cleared: break-glass gives
# up authorisation and nothing else, so what the upstream is told about the
# request must still come from this proxy rather than from the client
# (protected.inc says the rest).
proxy_set_header Host              $host;
proxy_set_header X-Real-IP         $remote_addr;
proxy_set_header X-Forwarded-For   $remote_addr;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Forwarded-Host  $host;
proxy_set_header X-Forwarded-Port  443;
proxy_set_header X-Forwarded-Prefix "";
proxy_set_header X-Original-URL     "";
proxy_set_header X-Rewrite-URL      "";
proxy_http_version 1.1;
proxy_set_header Upgrade    $upstream_upgrade;
proxy_set_header HTTP2-Settings "";
proxy_set_header Connection $connection_upgrade;
proxy_read_timeout 300s;
# An upstream does not steer nginx: X-Accel-Redirect could send the response to
# any internal location of this server. Nothing reachable there is harmful
# today; this keeps the next internal location from becoming reachable.
proxy_ignore_headers X-Accel-Redirect X-Accel-Expires X-Accel-Limit-Rate X-Accel-Buffering X-Accel-Charset;
