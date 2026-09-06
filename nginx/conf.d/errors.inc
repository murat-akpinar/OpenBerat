# The three answers a protected host can give that are not the application.
# Included at server level.

# The `=` is load-bearing and only bites here: @signin answers with a *proxied*
# response, and without it nginx forces the original 401 back with a Location
# the browser will not follow (measured, docs/07 — README rule 1).
location @signin {
    limit_req zone=login burst=20 nodelay;
    set $oauth2_proxy oauth2-proxy;
    # The return address travels in a header. nginx cannot percent-encode
    # $request_uri, so `?rd=…$request_uri` hands the client's own query string
    # to oauth2-proxy as extra parameters of /oauth2/start.
    proxy_set_header X-Auth-Request-Redirect $scheme://$host$request_uri;
    proxy_set_header Host              $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    # The trailing `?` drops the original query string; without it nginx
    # appends it and the injection is back.
    rewrite ^ /oauth2/start? break;
    proxy_pass http://$oauth2_proxy:4180;
}

# The "no access" page lives on the portal host, and nginx cannot serve another
# server block internally — so this is a 302 and not an internal redirect
# (README rule 7). `return` is safe in a named location: it is the locations
# carrying auth_request where the rewrite phase would run first (rule 14).
location @denied {
    return 302 https://portal.apps.example.local/denied?app=$host;
}

# Never a bare 500. Note there is no `=`: with one, nginx would answer with the
# status the handler produces — 200 for a static file — and an outage would be
# indistinguishable from a working page. Without it the 502/503 survives to the
# client and the body explains it.
location = /unavailable.html {
    internal;
    root /usr/share/nginx/html;
}
