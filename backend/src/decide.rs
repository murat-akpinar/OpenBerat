// SPDX-FileCopyrightText: 2026 OpenBerat contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// `GET /decide`, and nothing else: the answer nginx's auth_request subrequest
// gets for every request to a protected application. The contract it works to
// — which request headers arrive, and which response headers carry the
// verified identity back — is in `api.rs`'s header and in docs/02.
//
// The rule the whole file is written around: it never answers 5xx. A database
// or an oauth2-proxy that does not answer denies with a named reason
// (`X-Deny-Reason`), because a 5xx here is a `nginx auth_request` error, which
// is a 500 page for the user and an outage nobody can tell from a denial.

use crate::api::{AUTH_TIMEOUT, Ctx, QUERY_TIMEOUT};
use crate::cache::{self, Cached, Identity, Key};
use crate::metrics;
use crate::policy::{self, Decision, Deny};
use crate::session;
use crate::store::{self, AuditEvent};
use axum::extract::State;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use std::sync::Arc;

enum Authentication {
    Verified(Arc<Identity>, Vec<HeaderValue>),
    Anonymous,
    Unavailable,
}

/// The longest path an audit row keeps. The query string is dropped before
/// this: it is not part of the decision and it is where a credential ends up
/// when somebody puts one in a URL.
const AUDIT_PATH_LIMIT: usize = 512;

// --- Feature Start ---
// The N-01/N-02 stopwatch, around the handler rather than inside it: /decide
// has seven refusal paths, and a timer written at each of them is one somebody
// forgets at the eighth — which is how the slowest branch becomes the one that
// is never measured.
// --- Feature End ---
pub(crate) async fn decide(State(ctx): State<Arc<Ctx>>, headers: HeaderMap) -> Response {
    let start = std::time::Instant::now();
    let response = decided(&ctx, headers).await;
    metrics::observe(start.elapsed());
    response
}

async fn decided(ctx: &Ctx, headers: HeaderMap) -> Response {
    // --- Feature Start ---
    // Every one of these is written unconditionally by the shared nginx include
    // (docs/02, request contract), so a missing one does not mean an unusual
    // request — it means the include did not run on that location. Deciding on
    // half a request is how a location ends up unprotected in silence.
    // --- Feature End ---
    let (Some(slug), Some(uri)) = (
        headers.get("x-app-slug").and_then(|v| v.to_str().ok()),
        headers.get("x-original-uri").and_then(|v| v.to_str().ok()),
    ) else {
        return refuse(Deny::MissingContext);
    };
    if ["x-original-method", "x-real-ip", "x-request-id"]
        .iter()
        .any(|name| !headers.contains_key(*name))
    {
        return refuse(Deny::MissingContext);
    }
    let cookie = headers.get("cookie");
    let request = Subrequest {
        key: Key::new(cookie.and_then(|v| v.to_str().ok()), slug),
        slug: slug.to_string(),
        uri: uri.to_string(),
        audit_path: uri
            .split('?')
            .next()
            .unwrap_or_default()
            .chars()
            .take(AUDIT_PATH_LIMIT)
            .collect(),
        src_ip: header_str(&headers, "x-real-ip").and_then(|v| v.parse().ok()),
        request_id: header_str(&headers, "x-request-id"),
    };

    if let Some(key) = &request.key
        && let Some(cached) = ctx.cache.get(key)
    {
        metrics::cache(true);
        return answer(ctx, &request, &cached);
    }

    // Single-flight: a page of fifty assets arriving on an expired entry
    // refreshes once, not fifty times. Whoever loses the race re-reads the
    // cache under the lock rather than repeating the work.
    let _fill = match &request.key {
        Some(key) => Some(ctx.cache.fill_lock(key).await),
        None => None,
    };
    if let Some(key) = &request.key
        && let Some(cached) = ctx.cache.get(key)
    {
        // Filled by whoever won the single-flight race. It waited, but it was
        // served from the cache, and the hit rate is about the double hop.
        metrics::cache(true);
        return answer(ctx, &request, &cached);
    }
    // A request with no session cookie has no key to cache under: it is not a
    // miss, and counting it would turn the hit rate into a measure of how much
    // anonymous traffic arrived.
    if request.key.is_some() {
        metrics::cache(false);
    }

    let (identity, set_cookie) = match authenticate(ctx, cookie).await {
        Authentication::Verified(identity, set_cookie) => (identity, set_cookie),
        // nginx turns this into the login redirect. A 403 here would show the
        // "no access" page to someone who has simply not logged in yet.
        Authentication::Anonymous => {
            metrics::unauthenticated();
            return StatusCode::UNAUTHORIZED.into_response();
        }
        // Not audited, and not for want of trying: there is no verified actor
        // to name yet. The tracing line inside authenticate is the record.
        Authentication::Unavailable => return refuse(Deny::AuthUnavailable),
    };

    // --- Feature Start ---
    // ADR-0019, and the order is the point: the session is indexed before the
    // decision that depends on it, and before it is cached. A session the kill
    // switch cannot find must not gain access — the narrow case being a Redis
    // that still serves reads but refuses writes, where sessions would
    // otherwise keep working while silently becoming unkillable.
    // --- Feature End ---
    let sub = identity.sub.to_str().unwrap_or_default().to_string();
    let Some(session) = cache::session_cookie(cookie.and_then(|v| v.to_str().ok()))
        .and_then(|value| session::session_key(value, cache::COOKIE_NAME))
    else {
        tracing::error!("no session key could be derived from an authenticated cookie");
        return refuse(Deny::StoreUnavailable);
    };
    if let Err(e) = ctx.index.record(&sub, &session).await {
        tracing::error!(error = %e, "session index write failed");
        return refuse(Deny::StoreUnavailable);
    }

    let cached = match load(ctx, &request, &identity).await {
        Ok(cached) => cached,
        // Auditing a Postgres outage would mean writing a row to the Postgres
        // that is not answering. tracing carries this one.
        Err(reason) => return refuse(reason),
    };
    if let Some(key) = &request.key {
        ctx.cache.insert(key.clone(), sub, cached.clone());
    }

    let mut response = answer(ctx, &request, &cached);
    // --- Feature Start ---
    // The relay is not conditional on the answer. oauth2-proxy refreshes the
    // session on the subrequest whatever the decision turns out to be, and a
    // denied user whose refreshed cookie is swallowed never refreshes again —
    // their groups freeze until the cookie expires and they are sent back to
    // Keycloak. ADR-0006 rests on this arriving at the browser.
    // --- Feature End ---
    for cookie in set_cookie {
        response.headers_mut().append("set-cookie", cookie);
    }
    response
}

/// The inputs the nginx include hands `/decide`, gathered once.
struct Subrequest {
    key: Option<Key>,
    slug: String,
    uri: String,
    audit_path: String,
    src_ip: Option<std::net::IpAddr>,
    request_id: Option<String>,
}

async fn load(ctx: &Ctx, request: &Subrequest, identity: &Arc<Identity>) -> Result<Cached, Deny> {
    let groups: Vec<String> = identity
        .groups
        .to_str()
        .unwrap_or_default()
        .split(',')
        .filter(|g| !g.is_empty())
        .map(str::to_owned)
        .collect();
    let sub = identity.sub.to_str().unwrap_or_default();

    let found = tokio::time::timeout(
        QUERY_TIMEOUT,
        store::rules_for(&ctx.pool, &request.slug, sub, &groups),
    )
    .await;
    // A slow or unreachable Postgres is an outage, not a decision — but
    // /decide still may not answer 5xx, so it denies and names the dependency.
    let found = match found {
        Ok(Ok(found)) => found,
        Ok(Err(e)) => {
            tracing::error!(error = %e, "entitlement query failed");
            return Err(Deny::StoreUnavailable);
        }
        Err(_) => {
            tracing::error!("entitlement query exceeded {QUERY_TIMEOUT:?}");
            return Err(Deny::StoreUnavailable);
        }
    };

    // A slug with no row decides the same as a disabled application (docs/02).
    Ok(match found {
        Some(app) => Cached {
            identity: identity.clone(),
            rules: Arc::new(app.rules),
            enabled: app.enabled,
            application_id: Some(app.id),
        },
        None => Cached {
            identity: identity.clone(),
            rules: Arc::new(Vec::new()),
            enabled: false,
            application_id: None,
        },
    })
}

/// The decision itself: a pure function over data already in memory, run on
/// every request — hit or miss — against the full rule list.
fn answer(ctx: &Ctx, request: &Subrequest, cached: &Cached) -> Response {
    let decision = policy::decide(
        cached.enabled,
        &cached.rules,
        &request.uri,
        chrono::Utc::now(),
    );
    let counted = match &request.key {
        Some(key) => ctx.cache.count(
            key,
            decision,
            &request.audit_path,
            request.src_ip,
            request.request_id.clone(),
        ),
        None => false,
    };
    // The entry that was just filled can be gone again — evicted by the
    // capacity bound between the insert and here — and a decision with nowhere
    // to be counted writes its own row rather than going unrecorded.
    if !counted {
        let now = chrono::Utc::now();
        ctx.audit.record(AuditEvent {
            application_id: cached.application_id,
            application_slug: request.slug.clone(),
            actor_sub: cached.identity.sub.to_str().unwrap_or_default().to_string(),
            actor_name: cached
                .identity
                .username
                .to_str()
                .ok()
                .filter(|v| !v.is_empty())
                .map(str::to_owned),
            decision,
            count: 1,
            first_seen: now,
            last_seen: now,
            distinct_path: 1,
            first_path: request.audit_path.clone(),
            src_ip: request.src_ip,
            request_id: request.request_id.clone(),
        });
    }
    let mut response = match decision {
        Decision::Allow => {
            metrics::outcome(decision);
            StatusCode::OK.into_response()
        }
        Decision::Deny(reason) => refuse(reason),
    };
    identify(&mut response, &cached.identity);
    response
}

fn header_str(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

async fn authenticate(ctx: &Ctx, cookie: Option<&HeaderValue>) -> Authentication {
    let mut request = ctx.http.get(format!("{}/oauth2/auth", ctx.oauth2_proxy));
    if let Some(cookie) = cookie {
        request = request.header("cookie", cookie);
    }
    let response = match request.timeout(AUTH_TIMEOUT).send().await {
        Ok(response) => response,
        Err(e) => {
            tracing::error!(error = %e, "oauth2-proxy did not answer");
            return Authentication::Unavailable;
        }
    };
    if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        return Authentication::Anonymous;
    }
    if !response.status().is_success() {
        tracing::error!(status = %response.status(), "oauth2-proxy answered unusably");
        return Authentication::Unavailable;
    }

    let headers = response.headers();
    let value = |name: &str| {
        headers
            .get(name)
            .cloned()
            .unwrap_or(HeaderValue::from_static(""))
    };
    // Without a sub there is nothing to key the ADR-0019 kill-switch index on,
    // and nothing to write in the audit record. Treat it as an outage rather
    // than deciding for an unnamed user.
    let sub = match headers.get("x-auth-request-user") {
        Some(sub) if !sub.is_empty() => sub.clone(),
        _ => {
            tracing::error!("oauth2-proxy returned no x-auth-request-user");
            return Authentication::Unavailable;
        }
    };
    Authentication::Verified(
        Arc::new(Identity {
            sub,
            username: value("x-auth-request-preferred-username"),
            email: value("x-auth-request-email"),
            groups: value("x-auth-request-groups"),
        }),
        headers.get_all("set-cookie").iter().cloned().collect(),
    )
}

// --- Feature Start ---
// auth_request passes no response body, so these headers are the only channel
// nginx can lift the verified identity from (docs/02, response contract). They
// are written on a DENY as well as on an ALLOW: nginx never proxies upstream
// after a deny, so nothing is rewritten from them, but the access log is, and
// without them a denied line can say why and not who — which is the one
// question anybody asks about a denial. They do not reach the client either
// way; auth_request response headers only reach nginx.
// --- Feature End ---
fn identify(response: &mut Response, identity: &Identity) {
    let headers = response.headers_mut();
    headers.insert("x-auth-subject", identity.sub.clone());
    headers.insert("x-auth-username", identity.username.clone());
    headers.insert("x-auth-email", identity.email.clone());
    headers.insert("x-auth-groups", identity.groups.clone());
}

// Every refusal in the file goes through here, which is why the counter is
// here and not at each caller: /decide answers 403 for a policy denial and for
// an outage alike (ADR-0017), and the series that separates them is the only
// place the difference is visible from outside.
fn refuse(reason: Deny) -> Response {
    metrics::outcome(Decision::Deny(reason));
    let mut response = StatusCode::FORBIDDEN.into_response();
    response.headers_mut().insert(
        HeaderName::from_static("x-deny-reason"),
        HeaderValue::from_static(reason.as_str()),
    );
    response
}
