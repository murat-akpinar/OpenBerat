# SPDX-FileCopyrightText: 2026 OpenBerat contributors
# SPDX-License-Identifier: GPL-3.0-or-later

# --- Feature Start ---
# nginx writes `$request` verbatim, so the query string of every login landed in
# the access log — and two of its parameters are credentials: the OAuth
# authorization code on `/oauth2/callback`, and Keycloak's `session_code` on
# `/login-actions/authenticate`. From there they reach whoever reads the log, the
# log shipper and the backup. PKCE bounds what a reader could do with the code
# (measured in docs/07: no verifier, wrong verifier and a replay are all
# refused) — which is why this redacts the two values instead of dropping the
# query string, since `state`, `rd` and `error_description` are what a failed
# login is diagnosed from.
# --- Feature End ---
#
# Two maps, because a map matches once and there are two names to redact. The
# `[?&]` in front of `code=` is what stops the first from eating `session_code=`,
# and `[^& ]` ends the value at the next parameter or at ` HTTP/1.1` — no
# backslash escapes, which nginx would consume before PCRE ever saw them.
map $request $request_no_code {
    default                                       $request;
    "~^(?<pre>.*[?&]code=)[^& ]+(?<post>.*)$"     "${pre}REDACTED${post}";
}

map $request_no_code $safe_request {
    default                                       $request_no_code;
    "~^(?<pre2>.*[?&]session_code=)[^& ]+(?<post2>.*)$"  "${pre2}REDACTED${post2}";
}
