# The authorisation subrequest. Included at server level on every protected
# host. The request contract is docs/02; every header here is written
# unconditionally, because the backend treats a missing one as a DENY.

location = /decide {
    # Not an IP ACL: nginx skips the whole access phase for a subrequest, so
    # `deny all` in this position does nothing at all while `internal` still
    # refuses a direct request (measured, docs/07 — README rule 5).
    internal;

    set $backend backend;
    proxy_pass http://$backend:8081/decide;

    proxy_pass_request_body off;
    proxy_set_header Content-Length "";

    # $request_uri and $request_method resolve to the *main* request inside a
    # subrequest, not to this GET /decide (measured, docs/07).
    proxy_set_header X-Original-URI    $request_uri;
    proxy_set_header X-Original-Method $request_method;
    proxy_set_header X-Real-IP         $remote_addr;
    proxy_set_header X-Request-Id      $request_id;
    # The application's identity comes from the server block, never from Host:
    # the subrequest inherits the client's headers verbatim, so Host and
    # X-Forwarded-Host are client-controlled (README rule 6).
    proxy_set_header X-App-Slug        $app_slug;

    # --- Feature Start ---
    # The subrequest inherits the client's headers verbatim (measured,
    # docs/07), and the upstream strip in protected.inc never runs on this
    # path — so a forged X-Auth-Request-Groups would otherwise arrive at the
    # PDP exactly as the client wrote it. This is the second copy of the strip
    # and it is not redundant.
    # --- Feature End ---
    proxy_set_header X-Auth-Request-User "";
    proxy_set_header X-Auth-Request-Preferred-Username "";
    proxy_set_header X-Auth-Request-Email "";
    proxy_set_header X-Auth-Request-Groups "";
    proxy_set_header X-Auth-Request-Redirect "";
    proxy_set_header X-Auth-Subject  "";
    proxy_set_header X-Auth-Username "";
    proxy_set_header X-Auth-Email    "";
    proxy_set_header X-Auth-Groups   "";

    # /decide returns the whole group list in one X-Auth-Groups, and nginx
    # reads a response header block into a single buffer: 4 KB breaks between
    # 100 and 200 groups and auth_request turns the 502 into a 500 for the
    # client (measured, docs/07 — README rule 15).
    proxy_buffer_size 32k;
    proxy_buffers 4 32k;

    # The outer end of the timeout budget (docs/02). The backend's own halves
    # are 1 s for oauth2-proxy and 500 ms for the entitlement query, so a
    # /decide that takes 2 s is not slow, it is broken.
    proxy_connect_timeout 1s;
    proxy_read_timeout 2s;
}
