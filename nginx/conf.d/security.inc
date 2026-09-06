# The response headers every host serves. Set once at http level, from
# nginx.conf, and pulled back in by hand wherever a location writes a header of
# its own.

# nginx inherits add_header by *replacement*, never by merge: one add_header
# anywhere in a location drops every header defined above it. The three places
# that relay the refreshed session cookie by hand (ADR-0006) are therefore
# exactly the places that would silently lose these — the portal, the admin API
# and every protected application, which is all of them (README rule 19).

# `always`, so they also cover the answers that matter most: the 401 on the way
# to login, the 403 from @denied, and the 502 when the chain is down.
#
# No `preload`. Submitting the parent domain to the browsers' preload list is
# effectively irreversible and it commits every future subdomain of it to HTTPS,
# including ones this product does not serve; and the lab domain is `.local`,
# which is not eligible anyway. `includeSubDomains` is here because the one
# hostname that would benefit is the apex, `apps.<domain>`: the wildcard
# certificate covers it (INSTALL.md §1) and the default server answers it, so a
# browser that ever reaches it pins the whole tree.
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

# Upstreams send this one too — measured on the lab, both Jenkins and Keycloak
# do — and nginx appends rather than replaces, so those responses carry it twice
# with the same value. Harmless in this direction: the browser splits the joined
# value and reads the first token, which is `nosniff` either way.
add_header X-Content-Type-Options "nosniff" always;

# Referrer-Policy is deliberately NOT here, and the measurement is why. A second
# copy of it does not double harmlessly: the browser takes the *last* valid
# value, so ours would win — and on the lab Keycloak sends `no-referrer` and
# Jenkins sends `same-origin`, both stricter than anything sensible to impose
# from the proxy. Adding it at http level would silently relax the login host
# and every application that had already made a choice. It is set on the
# portal's own HTML instead (10-portal.conf), where there is no upstream to
# overrule; everywhere else the browsers' own default is
# `strict-origin-when-cross-origin` already (README rule 20).
