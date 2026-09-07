// SPDX-FileCopyrightText: 2026 OpenBerat contributors
// SPDX-License-Identifier: GPL-3.0-or-later

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
//   GET /metrics      decision latency, error rate, cache hit rate and the audit
//                     loss counter, in Prometheus text format. Unauthenticated
//                     and internal-network only, like the two below, so it
//                     carries counters and no identities (`metrics.rs`).
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
//   GET /api/admin/sessions
//                     who is signed in (ADR-0028): every subject with at least
//                     one session key that still EXISTS, and how many. Read out
//                     of the kill-switch index, which is the only thing that
//                     knows about a session that has reached no application —
//                     the audit record is 35 s behind and never sees that one at
//                     all. It counts keys that exist rather than set members: a
//                     session that merely expired leaves its key in the set, and
//                     cardinality would report it as somebody signed in. The
//                     name is the audit record's (`last_seen_as`), null for a
//                     subject it has never seen. Read-only; nothing is written
//                     back, not even to prune.
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
//
// The table above is the whole contract and stays here, next to the router
// that mounts it, whichever file a handler lives in: `decide.rs` for /decide,
// `portal.rs` for what the portal page calls, `admin.rs` and `audit.rs` for
// the management plane. What is left in this file is the plumbing they share
// — the context, the router, the session-index middleware, the identity every
// handler reads off the request, and the three endpoints that answer without
// one.

use crate::cache::{self, Cache};
use crate::keycloak::Keycloak;
use crate::session::{self, Index};
use crate::store;
use crate::{decide, metrics, portal};
use axum::Router;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use std::sync::Arc;
use std::time::Duration;

/// The outer budget belongs to nginx (`proxy_read_timeout 2s` on the subrequest
/// location); these two are the halves the backend owns (docs/02). Shared with
/// `decide.rs` and `portal.rs`, which spend them.
pub(crate) const AUTH_TIMEOUT: Duration = Duration::from_secs(1);
pub(crate) const QUERY_TIMEOUT: Duration = Duration::from_millis(500);

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
        .route("/api/me", get(portal::me))
        .route("/api/apps", get(portal::apps))
        .route("/api/logout", axum::routing::post(portal::logout))
        .merge(crate::admin::routes(ctx.clone()))
        .route_layer(middleware::from_fn_with_state(ctx.clone(), indexed));
    Router::new()
        .route("/decide", get(decide::decide))
        .route("/metrics", get(exposition))
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

/// Prometheus reads this; nothing else does. The version parameter is the
/// exposition format's own and is what a scraper content-negotiates on.
async fn exposition() -> Response {
    (
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        metrics::render(),
    )
        .into_response()
}
