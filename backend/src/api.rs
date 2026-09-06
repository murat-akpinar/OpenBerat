// HTTP endpoints:
//   GET /decide       for the nginx auth_request — 200 / 401 / 403, never 5xx.
//                     Inputs: X-App-Slug, X-Original-URI, X-Original-Method,
//                     X-Real-IP, X-Request-Id, Cookie. Anything missing is a DENY.
//                     The Set-Cookie from oauth2-proxy is relayed verbatim;
//                     without it cookie_refresh silently stops (ADR-0006).
//                     On 200 the verified identity is returned as X-Auth-Subject/
//                     -Username/-Email/-Groups response headers — auth_request
//                     passes no body, so response headers are the only channel
//                     nginx can lift the identity from to rewrite the upstream
//                     headers (docs/02, response contract).
//   GET /api/apps     the applications the portal lists (called by the frontend)
//   GET /api/me       the signed-in user: name, email, groups, admin flag
//   POST /api/logout  the caller's own kill switch, run BEFORE the sign-out
//                     redirect: session key (derived from the cookie it holds),
//                     cache entries, this session's index membership —
//                     kill-switch order (docs/02 "Logout"). Only this session
//                     leaves the index; the same user's other browser must stay
//                     killable. The frontend then sends the browser through
//                     /signout -> /oauth2/sign_out -> Keycloak end_session.
//   GET /healthz      the process is alive; no dependencies checked
//   GET /readyz       Postgres and Redis reachable — 200 or 503. /decide cannot
//                     report an outage (a dead DB looks like a denied user), so
//                     this is the only outage signal the operator has.
//   /api/admin/*      application and entitlement management, audit viewing —
//                     requires ADMIN_GROUP
//                     membership, never cached, Origin checked on state-changing
//                     endpoints
//   GET /api/admin/audit
//                     the audit record, filtered by actor / app / decision /
//                     reason / since / until and paged with a
//                     (before_ts, before_id) keyset cursor. A filter it cannot
//                     honour answers 400 rather than being ignored: an ignored
//                     filter widens the list, and a list that is silently not
//                     the one asked for is the failure this table exists to
//                     prevent.
//   GET /api/admin/explain
//                     the decision the PEP would reach for
//                     ?user&groups&host&path, and every entitlement row it
//                     walked, each marked matched / expired. The verdict is
//                     policy::decide's own and the rows are the decision path's
//                     own (store's `applicable!`): a screen answering
//                     differently from the PEP sends an admin to fix the wrong
//                     rule. `groups` is required rather than defaulted to none
//                     — the backend keeps no directory, and answering without
//                     them reports a denial that would not happen. Read-only:
//                     it fills no cache entry and writes no audit row, so
//                     asking why cannot change the answer. It reads the
//                     entitlement table, not the decision cache, so for up to
//                     one cache TTL after a rule change it is right and the PEP
//                     is stale (docs/07) — the intended direction, but the
//                     admin sees the old answer at the URL for that long.
//   POST /api/admin/kill/{sub}
//                     four ordered steps: Keycloak logout-all -> the session keys
//                     from the sub -> session index -> that user's cache entries
//                     -> the index entry (ADR-0019). Reversing any pair lets a
//                     request in the gap refill what was just cleared.
// Contract: docs/02-architecture.md

use crate::cache::{self, Cache, Cached, Identity, Key};
use crate::keycloak::Keycloak;
use crate::policy::{self, Decision, Deny};
use crate::session::{self, Index};
use crate::store::{self, AuditEvent};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use std::sync::Arc;
use std::time::Duration;

/// The outer budget belongs to nginx (`proxy_read_timeout 2s` on the subrequest
/// location); these two are the halves the backend owns (docs/02).
const AUTH_TIMEOUT: Duration = Duration::from_secs(1);
const QUERY_TIMEOUT: Duration = Duration::from_millis(500);

pub struct Ctx {
    pub pool: sqlx::PgPool,
    pub http: reqwest::Client,
    /// Base URL of oauth2-proxy on the `core` network, no trailing slash.
    pub oauth2_proxy: String,
    pub cache: Arc<Cache>,
    pub audit: store::Audit,
    pub index: Index,
    /// The Admin API, for the kill switch's first step (ADR-0019).
    pub keycloak: Keycloak,
    /// The AD group that grants the management plane (ADR-0008). It comes from
    /// the environment and never from the database: in a fail-closed system the
    /// first admin cannot come from a table nobody can write to yet.
    pub admin_group: String,
    /// The origin state-changing admin calls must come from (docs/02).
    pub portal_origin: String,
    /// Where generated application blocks are staged for nginx (ADR-0011).
    /// `None` means "do not generate", which is what the tests want.
    pub nginx_conf_dir: Option<String>,
}

pub fn router(ctx: Arc<Ctx>) -> Router {
    // Everything a signed-in person calls, behind the ADR-0019 index write.
    // /decide is not here: it writes its own entry, at the one point in the
    // flow where it holds the raw cookie for another reason anyway.
    let api = Router::new()
        .route("/api/me", get(me))
        .route("/api/apps", get(apps))
        .route("/api/logout", axum::routing::post(logout))
        .merge(crate::admin::routes(ctx.clone()))
        .route_layer(middleware::from_fn_with_state(ctx.clone(), indexed));
    Router::new()
        .route("/decide", get(decide))
        .route("/healthz", get(async || StatusCode::OK))
        .route("/readyz", get(readyz))
        .merge(api)
        .with_state(ctx)
}

// --- Feature Start ---
// ADR-0019, and this half was found by measuring rather than by reading: the
// index was written only on a /decide miss, and the portal does not go through
// /decide. A user who logged in and had not yet opened an application was
// therefore invisible to the kill switch — it reported zero sessions and left
// them holding every application they opened next. Every authenticated /api
// call records the session now, and a session that cannot be recorded is
// refused for the same reason it is on /decide: one the kill switch cannot
// find must not carry access.
// --- Feature End ---
async fn indexed(State(ctx): State<Arc<Ctx>>, request: Request, next: Next) -> Response {
    let headers = request.headers();
    // No identity means nginx put none there, and the handler's own 401 is the
    // answer. There is no session to index for an anonymous caller.
    let Some(sub) = headers
        .get("x-auth-subject")
        .and_then(|v| v.to_str().ok())
        .filter(|sub| !sub.is_empty())
        .map(str::to_owned)
    else {
        return next.run(request).await;
    };
    let cookie = headers.get("cookie").and_then(|v| v.to_str().ok());
    let Some(key) =
        cache::session_cookie(cookie).and_then(|v| session::session_key(v, cache::COOKIE_NAME))
    else {
        tracing::error!("no session key could be derived from an authenticated /api request");
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    if let Err(e) = ctx.index.record(&sub, &key).await {
        tracing::error!(error = %e, "session index write failed");
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    next.run(request).await
}

/// The signed-in user, as nginx rewrote them onto the request. Read from the
/// `X-Auth-*` set — the same names a protected application receives — because
/// the shared include clears the `X-Auth-Request-*` family before proxying
/// anywhere, this endpoint included. Reading the cleared family here would need
/// one location that must *not* run the shared strip, which is exactly the
/// "forget it in one place" hazard the include exists to remove.
pub struct Caller {
    pub sub: String,
    pub username: String,
    pub email: String,
    pub groups: Vec<String>,
}

impl Caller {
    pub fn from(headers: &HeaderMap) -> Option<Caller> {
        let value = |name: &str| {
            headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string()
        };
        // nginx never proxies here without one; if it did, the request has no
        // identity and there is nothing to answer it with.
        let sub = value("x-auth-subject");
        (!sub.is_empty()).then(|| Caller {
            sub,
            username: value("x-auth-username"),
            email: value("x-auth-email"),
            groups: value("x-auth-groups")
                .split(',')
                .filter(|g| !g.is_empty())
                .map(str::to_owned)
                .collect(),
        })
    }
}

// --- Feature Start ---
// The guard on every state-changing call, here rather than spelled out at each
// one: SameSite cannot do this job, because the portal and the applications are
// same-site by design (ADR-0015) and a compromised application's page is
// therefore a same-site caller. Two copies of this test would eventually
// disagree, and the one that drifted would be the one nobody reads.
// --- Feature End ---
pub fn from_portal(headers: &HeaderMap, portal_origin: &str) -> bool {
    headers.get("origin").and_then(|v| v.to_str().ok()) == Some(portal_origin)
}

// --- Feature Start ---
// The caller's own kill switch (docs/02, "Logout"), and the four steps are the
// kill switch's four in the same order for the same reasons. The IdP first, or
// the browser is signed straight back in with no password; the oauth2-proxy
// session before the cache, or a request in the gap refills the cache from a
// session that is still there; the index entry last, because it is the map to
// everything above it.
//
// Why the sign-out is a call from here rather than a redirect the browser
// walks afterwards: oauth2-proxy performs the RP-initiated logout out of the
// session's own id_token, which is inside the session it is being asked to
// destroy. Deleting the session key first leaves it nothing to log out with —
// measured on the lab, where exactly that left the IdP session alive and the
// next request signed the user back in without a prompt (docs/07). Ordering it
// here is what makes the four steps one call instead of a race with the
// browser's next navigation.
//
// Only this browser leaves the index. `forget` would take the same user's other
// sessions with it, and a live session in no index is one the kill switch
// cannot find.
// --- Feature End ---
async fn logout(State(ctx): State<Arc<Ctx>>, headers: HeaderMap) -> Response {
    let Some(caller) = Caller::from(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if !from_portal(&headers, &ctx.portal_origin) {
        tracing::warn!(actor = %caller.username, "logout refused: wrong or missing Origin");
        return StatusCode::FORBIDDEN.into_response();
    }
    // Unreachable through nginx: `indexed` runs first and answers 503 for an
    // authenticated request whose session key cannot be derived.
    let Some(cookie) = headers.get("cookie") else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Some(key) = cache::session_cookie(cookie.to_str().ok())
        .and_then(|v| session::session_key(v, cache::COOKIE_NAME))
    else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    // A failed step stops the ones after it: carrying on would report a logout
    // nobody got. The sign-out link's own href is the retry — it is steps 1 and
    // 2 on its own.
    let refused = |step: &str| {
        tracing::error!(actor = %caller.username, step, "logout failed");
        StatusCode::SERVICE_UNAVAILABLE.into_response()
    };
    let signed_out = ctx
        .http
        .get(format!("{}/oauth2/sign_out", ctx.oauth2_proxy))
        .header("cookie", cookie)
        .timeout(AUTH_TIMEOUT)
        .send()
        .await;
    // The 302 is the answer, not something to follow (main.rs).
    match signed_out {
        Ok(response) if response.status().is_success() || response.status().is_redirection() => {}
        Ok(response) => {
            tracing::error!(status = %response.status(), "oauth2-proxy refused the sign-out");
            return refused("oauth2_proxy_sign_out");
        }
        Err(e) => {
            tracing::error!(error = %e, "oauth2-proxy did not answer the sign-out");
            return refused("oauth2_proxy_sign_out");
        }
    }
    // oauth2-proxy has just dropped this session itself. The DEL is still ours:
    // it is the step that actually cuts access, and a sign-out that answered
    // without deleting would otherwise leave the session live and unnoticed.
    if let Err(e) = ctx.index.drop_sessions(std::slice::from_ref(&key)).await {
        tracing::error!(error = %e, "deleting the oauth2-proxy session failed");
        return refused("delete_session");
    }
    ctx.cache.drop_sub(&caller.sub);
    if let Err(e) = ctx.index.forget_session(&caller.sub, &key).await {
        tracing::error!(error = %e, "dropping the index entry failed");
        return refused("forget_index_entry");
    }
    tracing::info!(actor = %caller.username, "logout");
    StatusCode::NO_CONTENT.into_response()
}

#[derive(Serialize)]
struct PortalApp {
    slug: String,
    name: String,
    icon: Option<String>,
    url: String,
}

// --- Feature Start ---
// The portal grants nothing: this list is `policy::decide` run over the same
// rules the PEP would use, at the application's root. A second implementation
// of "can this user reach it" would eventually disagree with the first, and the
// disagreement shows up either as a button that 403s or — worse — as an
// application the portal hides while the PEP allows it.
// --- Feature End ---
async fn apps(State(ctx): State<Arc<Ctx>>, headers: HeaderMap) -> Response {
    let Some(caller) = Caller::from(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let found = match store::portal_apps(&ctx.pool, &caller.sub, &caller.groups).await {
        Ok(found) => found,
        Err(e) => {
            tracing::error!(error = %e, "listing portal applications failed");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let now = chrono::Utc::now();
    let reachable: Vec<PortalApp> = found
        .into_iter()
        .filter(|app| policy::decide(true, &app.rules, "/", now) == Decision::Allow)
        .map(|app| PortalApp {
            slug: app.slug,
            name: app.name,
            icon: app.icon,
            url: format!("https://{}/", app.external_hostname),
        })
        .collect();
    Json(reachable).into_response()
}

#[derive(Serialize)]
struct Me {
    sub: String,
    username: String,
    email: String,
    groups: Vec<String>,
    admin: bool,
}

async fn me(State(ctx): State<Arc<Ctx>>, headers: HeaderMap) -> Response {
    let Some(caller) = Caller::from(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    // The frontend uses this to hide things. Hiding is a convenience; the
    // refusal is the guard in admin.rs (ADR-0007).
    let admin = policy::is_admin(&caller.groups, &ctx.admin_group);
    Json(Me {
        sub: caller.sub,
        username: caller.username,
        email: caller.email,
        groups: caller.groups,
        admin,
    })
    .into_response()
}

// --- Feature Start ---
// The fail-closed rule hides the outage: with Postgres down, /decide answers
// 403 for everybody, which from outside is indistinguishable from a policy that
// denies everybody. This endpoint is the only place the difference is visible,
// and it is why it names the failed dependency rather than answering 503 bare.
// --- Feature End ---
async fn readyz(State(ctx): State<Arc<Ctx>>) -> Response {
    let mut down = Vec::new();
    let query = sqlx::query("select 1").execute(&ctx.pool);
    if !matches!(tokio::time::timeout(QUERY_TIMEOUT, query).await, Ok(Ok(_))) {
        down.push("postgres");
    }
    let ping = tokio::time::timeout(QUERY_TIMEOUT, ctx.index.ping()).await;
    if !matches!(ping, Ok(Ok(()))) {
        down.push("redis");
    }
    if down.is_empty() {
        return StatusCode::OK.into_response();
    }
    (
        StatusCode::SERVICE_UNAVAILABLE,
        format!("unreachable: {}\n", down.join(" ")),
    )
        .into_response()
}

enum Authentication {
    Verified(Arc<Identity>, Vec<HeaderValue>),
    Anonymous,
    Unavailable,
}

/// The longest path an audit row keeps. The query string is dropped before
/// this: it is not part of the decision and it is where a credential ends up
/// when somebody puts one in a URL.
const AUDIT_PATH_LIMIT: usize = 512;

async fn decide(State(ctx): State<Arc<Ctx>>, headers: HeaderMap) -> Response {
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
        return answer(&ctx, &request, &cached);
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
        return answer(&ctx, &request, &cached);
    }

    let (identity, set_cookie) = match authenticate(&ctx, cookie).await {
        Authentication::Verified(identity, set_cookie) => (identity, set_cookie),
        // nginx turns this into the login redirect. A 403 here would show the
        // "no access" page to someone who has simply not logged in yet.
        Authentication::Anonymous => return StatusCode::UNAUTHORIZED.into_response(),
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

    let cached = match load(&ctx, &request, &identity).await {
        Ok(cached) => cached,
        // Auditing a Postgres outage would mean writing a row to the Postgres
        // that is not answering. tracing carries this one.
        Err(reason) => return refuse(reason),
    };
    if let Some(key) = &request.key {
        ctx.cache.insert(key.clone(), sub, cached.clone());
    }

    let mut response = answer(&ctx, &request, &cached);
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
        Decision::Allow => StatusCode::OK.into_response(),
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

fn refuse(reason: Deny) -> Response {
    let mut response = StatusCode::FORBIDDEN.into_response();
    response.headers_mut().insert(
        HeaderName::from_static("x-deny-reason"),
        HeaderValue::from_static(reason.as_str()),
    );
    response
}
