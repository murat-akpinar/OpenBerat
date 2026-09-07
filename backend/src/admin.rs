// SPDX-FileCopyrightText: 2026 OpenBerat contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// The management plane: /api/admin/*. Not protected by the entitlement table —
// the portal is open to every authenticated user, so if reaching it were enough
// then anyone could grant themselves entitlements (docs/02, "Management plane").
//
// Two guards, both in `guard` below rather than on each handler: ADMIN_GROUP
// membership, and an Origin check on anything state-changing.

use crate::api::{Caller, Ctx};
use crate::keycloak::LogoutError;
use crate::policy;
use crate::store;
use axum::extract::{Path, Query, Request, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::Path as FsPath;
use std::sync::Arc;
use url::{Host, Url};
use uuid::Uuid;

pub fn routes(ctx: Arc<Ctx>) -> Router<Arc<Ctx>> {
    Router::new()
        .route(
            "/api/admin/applications",
            get(list_applications).post(create_application),
        )
        .route(
            "/api/admin/applications/{id}",
            axum::routing::patch(update_application).delete(delete_application),
        )
        .route(
            "/api/admin/entitlements",
            get(list_entitlements).post(create_entitlement),
        )
        .route(
            "/api/admin/entitlements/{id}",
            axum::routing::delete(delete_entitlement),
        )
        .route("/api/admin/audit", get(list_audit))
        .route("/api/admin/explain", get(explain))
        .route("/api/admin/kill/{sub}", axum::routing::post(kill))
        .route_layer(middleware::from_fn_with_state(ctx, guard))
}

// --- Feature Start ---
// Both management-plane guards live here rather than on each handler. A guard
// written per handler is a guard somebody forgets on the handler added at
// 3 a.m., and the one it is forgotten on is the one that grants entitlements.
// --- Feature End ---
async fn guard(
    State(ctx): State<Arc<Ctx>>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Response {
    let Some(caller) = Caller::from(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    // Never cached and never derived from the decision path: losing ADMIN_GROUP
    // in AD must not wait out a cache TTL before it takes effect.
    if !policy::is_admin(&caller.groups, &ctx.admin_group) {
        tracing::warn!(actor = %caller.username, path = %request.uri().path(),
            "admin refused: not in ADMIN_GROUP");
        return StatusCode::FORBIDDEN.into_response();
    }
    if !matches!(*request.method(), Method::GET | Method::HEAD)
        && !crate::api::from_portal(&headers, &ctx.portal_origin)
    {
        tracing::warn!(actor = %caller.username, path = %request.uri().path(),
            "admin refused: wrong or missing Origin");
        return StatusCode::FORBIDDEN.into_response();
    }
    next.run(request).await
}

// --- Feature Start ---
// The kill switch (ADR-0019). The order of the four steps is the whole design:
// Keycloak first, because a live SSO session signs the user straight back in;
// the oauth2-proxy session before the cache, because a request arriving in the
// gap would otherwise refill the cache with a fresh ALLOW from a session that
// is still there; the index entry last, because it is the map to everything
// above it. Only this user's cache entries are dropped — clearing the cache for
// everybody is self-DoS (docs/05).
//
// A step that fails stops the ones after it. Carrying on would report a
// success nobody got, and it would delete the index entry that makes the call
// retryable once the failed dependency answers again. The admin sees which
// step, and the break-glass runbook (docs/08) is what is left if none of them
// can run.
// --- Feature End ---
// ponytail: one window the order does not close — a request that oauth2-proxy
// already answered 200 to when step 2 runs still inserts its cache entry after
// step 3, and keeps access for up to cache::TTL. It is one /decide miss wide
// and needs a request in flight at that instant. Close it with a
// `killed:{sub}` tombstone in Redis, read on the miss path, if a measurement
// ever shows it.
async fn kill(State(ctx): State<Arc<Ctx>>, headers: HeaderMap, Path(sub): Path<Uuid>) -> Response {
    let actor = Caller::from(&headers)
        .map(|c| c.username)
        .unwrap_or_default();
    let refused = |step: &str, why: String| {
        tracing::error!(actor, action = "kill", target = %sub, outcome = "error",
            step, error = %why, "admin");
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": why, "step": step })),
        )
            .into_response()
    };
    match ctx.keycloak.logout_all(&sub).await {
        Ok(()) => {}
        // Not an outage: this sub names nobody, and answering 503 would send an
        // operator mid-incident to look at a Keycloak that is working.
        Err(e @ LogoutError::NoSuchUser) => {
            tracing::warn!(actor, action = "kill", target = %sub, outcome = "not_found", "admin");
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response();
        }
        Err(e) => return refused("keycloak_logout_all", e.to_string()),
    }
    let sub = sub.to_string();
    let sessions = match ctx.index.sessions(&sub).await {
        Ok(sessions) => sessions,
        Err(e) => return refused("read_session_index", e.to_string()),
    };
    if let Err(e) = ctx.index.drop_sessions(&sessions).await {
        return refused("delete_sessions", e.to_string());
    }
    ctx.cache.drop_sub(&sub);
    if let Err(e) = ctx.index.forget(&sub).await {
        return refused("forget_index_entry", e.to_string());
    }
    // F-14, and the count is the operator's answer to "did it find anything":
    // a user signed in on an instance that never served them has no index
    // entry here, and zero is what says so.
    tracing::warn!(actor, action = "kill", target = %sub, outcome = "ok",
        sessions = sessions.len(), "admin");
    Json(serde_json::json!({ "sessions": sessions.len() })).into_response()
}

#[derive(Serialize, sqlx::FromRow)]
pub struct Application {
    id: Uuid,
    slug: String,
    name: String,
    icon: Option<String>,
    upstream_url: String,
    external_hostname: String,
    enabled: bool,
}

#[derive(Deserialize)]
struct NewApplication {
    slug: String,
    name: String,
    icon: Option<String>,
    upstream_url: String,
    external_hostname: String,
    #[serde(default = "yes")]
    enabled: bool,
}

fn yes() -> bool {
    true
}

#[derive(Deserialize)]
struct ApplicationPatch {
    name: Option<String>,
    icon: Option<String>,
    upstream_url: Option<String>,
    enabled: Option<bool>,
}

/// Renders the whole file and hands it to nginx. Called after every change to
/// an application, because F-13 is "an application an admin defines becomes
/// genuinely reachable" and a row nothing acts on is not that.
///
/// It writes a *staged* file: installing it, testing it and rolling back if
/// nginx refuses it is the reloader's job in the nginx container, which is the
/// only place an `nginx -t` can run (ADR-0011).
async fn publish(ctx: &Ctx) -> Result<(), String> {
    let Some(dir) = &ctx.nginx_conf_dir else {
        return Ok(());
    };
    publish_conf(&ctx.pool, dir, &ctx.portal_origin).await
}

/// The same work without a `Ctx`, because startup calls it too: the file is a
/// pure function of the table, so a database restored into an empty volume
/// brings every application back with nobody editing a row (INSTALL.md §9).
pub async fn publish_conf(
    pool: &sqlx::PgPool,
    dir: &str,
    portal_origin: &str,
) -> Result<(), String> {
    let applications: Vec<Application> = sqlx::query_as(
        "select id, slug, name, icon, upstream_url, external_hostname, enabled
           from application order by slug",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| format!("reading applications: {e}"))?;

    let rendered = render_apps_conf(&applications, portal_origin);
    // Written under a different name and renamed, so the reloader can never see
    // half a file: rename within a filesystem is atomic, a write is not.
    let staging = FsPath::new(dir).join("apps.conf.writing");
    let staged = FsPath::new(dir).join("apps.conf.staged");
    tokio::fs::write(&staging, rendered)
        .await
        .map_err(|e| format!("writing {}: {e}", staging.display()))?;
    tokio::fs::rename(&staging, &staged)
        .await
        .map_err(|e| format!("staging {}: {e}", staged.display()))
}

/// Best effort, and clearly labelled as such: the row exists either way, and an
/// admin who cannot see this has no way to tell "saved but not published" from
/// "saved and live".
async fn publish_status(ctx: &Ctx) -> serde_json::Value {
    match publish(ctx).await {
        Ok(()) => serde_json::json!("staged"),
        Err(why) => {
            tracing::error!("generating nginx configuration failed: {why}");
            serde_json::json!(why)
        }
    }
}

fn bad_request(message: impl Into<String>) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "error": message.into() })),
    )
        .into_response()
}

/// Everything the admin API can do to the database ends here, so the mapping
/// from a database error to an answer is written once.
fn failed(action: &str, actor: &str, e: sqlx::Error) -> Response {
    if let sqlx::Error::Database(ref db) = e
        && db.is_unique_violation()
    {
        tracing::warn!(actor, action, outcome = "conflict", "admin");
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "error": "slug or external_hostname already exists" })),
        )
            .into_response();
    }
    tracing::error!(actor, action, outcome = "error", error = %e, "admin");
    StatusCode::SERVICE_UNAVAILABLE.into_response()
}

async fn list_applications(State(ctx): State<Arc<Ctx>>) -> Response {
    let found: Result<Vec<Application>, _> = sqlx::query_as(
        "select id, slug, name, icon, upstream_url, external_hostname, enabled
               from application order by slug",
    )
    .fetch_all(&ctx.pool)
    .await;
    match found {
        Ok(applications) => Json(applications).into_response(),
        Err(e) => failed("list_applications", "-", e),
    }
}

async fn create_application(
    State(ctx): State<Arc<Ctx>>,
    headers: HeaderMap,
    Json(new): Json<NewApplication>,
) -> Response {
    let actor = Caller::from(&headers)
        .map(|c| c.username)
        .unwrap_or_default();
    if let Err(why) = validate_upstream(&new.upstream_url) {
        return bad_request(why);
    }
    if let Err(why) = validate_hostname(&new.external_hostname, &ctx.portal_origin) {
        return bad_request(why);
    }
    let created: Result<Application, _> = sqlx::query_as(
        "insert into application (slug, name, icon, upstream_url, external_hostname, enabled)
         values ($1, $2, $3, $4, $5, $6)
         returning id, slug, name, icon, upstream_url, external_hostname, enabled",
    )
    .bind(&new.slug)
    .bind(&new.name)
    .bind(&new.icon)
    .bind(&new.upstream_url)
    .bind(&new.external_hostname)
    .bind(new.enabled)
    .fetch_one(&ctx.pool)
    .await;
    match created {
        Ok(application) => {
            // F-14: actor, action, target, outcome. The structured stream and
            // not audit_event — that table's rows are decision summaries and
            // its format is immutable (docs/02).
            tracing::info!(actor, action = "create_application", target = %new.slug,
                outcome = "ok", "admin");
            let nginx = publish_status(&ctx).await;
            (
                StatusCode::CREATED,
                Json(serde_json::json!({ "application": application, "nginx": nginx })),
            )
                .into_response()
        }
        // The schema's CHECK constraints are the second line here: a slug with
        // a semicolon in it is nginx config injection (ADR-0011), and it is
        // refused by the database even if this function is ever bypassed.
        Err(e) => failed("create_application", &actor, e),
    }
}

async fn update_application(
    State(ctx): State<Arc<Ctx>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(patch): Json<ApplicationPatch>,
) -> Response {
    let actor = Caller::from(&headers)
        .map(|c| c.username)
        .unwrap_or_default();
    if let Some(url) = &patch.upstream_url
        && let Err(why) = validate_upstream(url)
    {
        return bad_request(why);
    }
    // The hostname and the slug are not patchable: both are written into
    // generated nginx blocks and into every audit row that names this
    // application, and renaming one silently reassigns history.
    let updated: Result<Option<Application>, _> = sqlx::query_as(
        "update application set
           name = coalesce($2, name),
           icon = coalesce($3, icon),
           upstream_url = coalesce($4, upstream_url),
           enabled = coalesce($5, enabled)
         where id = $1
         returning id, slug, name, icon, upstream_url, external_hostname, enabled",
    )
    .bind(id)
    .bind(&patch.name)
    .bind(&patch.icon)
    .bind(&patch.upstream_url)
    .bind(patch.enabled)
    .fetch_optional(&ctx.pool)
    .await;
    match updated {
        Ok(Some(application)) => {
            tracing::info!(actor, action = "update_application", target = %id,
                outcome = "ok", "admin");
            let nginx = publish_status(&ctx).await;
            Json(serde_json::json!({ "application": application, "nginx": nginx })).into_response()
        }
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => failed("update_application", &actor, e),
    }
}

async fn delete_application(
    State(ctx): State<Arc<Ctx>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Response {
    let actor = Caller::from(&headers)
        .map(|c| c.username)
        .unwrap_or_default();
    let deleted = sqlx::query("delete from application where id = $1")
        .bind(id)
        .execute(&ctx.pool)
        .await;
    match deleted {
        // The entitlements go with it and the audit rows do not — audit_event
        // carries no foreign key and keeps the slug (migrations/0001_init.sql).
        Ok(result) if result.rows_affected() > 0 => {
            tracing::info!(actor, action = "delete_application", target = %id,
                outcome = "ok", "admin");
            let nginx = publish_status(&ctx).await;
            Json(serde_json::json!({ "nginx": nginx })).into_response()
        }
        Ok(_) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => failed("delete_application", &actor, e),
    }
}

#[derive(Serialize, sqlx::FromRow)]
pub struct Entitlement {
    id: Uuid,
    application_id: Option<Uuid>,
    subject_type: String,
    subject_id: String,
    effect: String,
    path_pattern: String,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Deserialize)]
struct NewEntitlement {
    /// Absent or null means every application — the wildcard of `docs/05`
    /// rule 4, which is why creating one is logged differently below.
    application_id: Option<Uuid>,
    subject_type: String,
    subject_id: String,
    effect: String,
    #[serde(default)]
    path_pattern: String,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

async fn list_entitlements(State(ctx): State<Arc<Ctx>>) -> Response {
    let found: Result<Vec<Entitlement>, _> = sqlx::query_as(
        "select id, application_id, subject_type, subject_id, effect, path_pattern, expires_at
           from entitlement order by subject_id, effect",
    )
    .fetch_all(&ctx.pool)
    .await;
    match found {
        Ok(entitlements) => Json(entitlements).into_response(),
        Err(e) => failed("list_entitlements", "-", e),
    }
}

async fn create_entitlement(
    State(ctx): State<Arc<Ctx>>,
    headers: HeaderMap,
    Json(new): Json<NewEntitlement>,
) -> Response {
    let actor = Caller::from(&headers)
        .map(|c| c.username)
        .unwrap_or_default();
    // The schema enforces all four of these too. They are checked here so that
    // a typo comes back as a sentence rather than as a 503 with a constraint
    // name in the log.
    if !["ad_group", "user"].contains(&new.subject_type.as_str()) {
        return bad_request("subject_type must be ad_group or user");
    }
    if !["allow", "deny"].contains(&new.effect.as_str()) {
        return bad_request("effect must be allow or deny");
    }
    if new.subject_id.trim().is_empty() {
        return bad_request("subject_id is required");
    }
    // --- Feature Start ---
    // Group names arrive comma-joined in one header and are split back apart
    // before matching (docs/07), so an `ad_group` name containing a comma can
    // never equal anything in that list. Refused rather than stored: a rule
    // that silently never fires is worse than one that was never accepted,
    // because the admin believes the access was granted.
    if new.subject_type == "ad_group" && new.subject_id.contains(',') {
        return bad_request("an AD group name cannot contain a comma");
    }
    // --- Feature End ---
    if !new.path_pattern.is_empty() && !new.path_pattern.starts_with('/') {
        return bad_request("path_pattern must be empty or start with /");
    }

    let created: Result<Entitlement, _> = sqlx::query_as(
        "insert into entitlement
           (application_id, subject_type, subject_id, effect, path_pattern, expires_at)
         values ($1, $2, $3, $4, $5, $6)
         returning id, application_id, subject_type, subject_id, effect, path_pattern, expires_at",
    )
    .bind(new.application_id)
    .bind(&new.subject_type)
    .bind(&new.subject_id)
    .bind(&new.effect)
    .bind(&new.path_pattern)
    .bind(new.expires_at)
    .fetch_one(&ctx.pool)
    .await;
    match created {
        Ok(entitlement) => {
            // --- Feature Start ---
            // A rule with no application_id applies to every application, present
            // and future (docs/05 rule 4). It is the one grant nobody should be
            // able to make by accident, so it is logged as its own action and at
            // its own level rather than disappearing into the ordinary stream.
            // --- Feature End ---
            if new.application_id.is_none() {
                tracing::warn!(actor, action = "create_wildcard_entitlement",
                    target = %new.subject_id, effect = %new.effect, outcome = "ok", "admin");
            } else {
                tracing::info!(actor, action = "create_entitlement",
                    target = %new.subject_id, effect = %new.effect, outcome = "ok", "admin");
            }
            (StatusCode::CREATED, Json(entitlement)).into_response()
        }
        Err(e) => failed("create_entitlement", &actor, e),
    }
}

async fn delete_entitlement(
    State(ctx): State<Arc<Ctx>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Response {
    let actor = Caller::from(&headers)
        .map(|c| c.username)
        .unwrap_or_default();
    let deleted = sqlx::query("delete from entitlement where id = $1")
        .bind(id)
        .execute(&ctx.pool)
        .await;
    match deleted {
        Ok(result) if result.rows_affected() > 0 => {
            tracing::info!(actor, action = "delete_entitlement", target = %id,
                outcome = "ok", "admin");
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(_) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => failed("delete_entitlement", &actor, e),
    }
}

/// One `audit_event` row as the admin reads it. Every column, because the
/// summary columns are the row — a viewer showing only the decision hides that
/// it stands for 50,000 requests (docs/02, "Audit granularity").
#[derive(Serialize, sqlx::FromRow)]
struct AuditRow {
    id: Uuid,
    ts: DateTime<Utc>,
    actor_sub: String,
    actor_name: Option<String>,
    application_id: Option<Uuid>,
    application_slug: String,
    decision: String,
    reason: String,
    count: i32,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    distinct_path: i32,
    first_path: String,
    src_ip: Option<IpAddr>,
    request_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum AuditDecision {
    Allow,
    Deny,
}

// --- Feature Start ---
// Every rule below refuses the one answer an audit viewer must never give: a
// list that is quietly not the list that was asked for. `deny_unknown_fields`
// turns a mistyped filter name into a 400 rather than dropping it — a dropped
// filter widens the result, and the admin then reads "these are the denials"
// off a page with allows on it. `decision` is an enum for the same reason. And
// the page cursor is a keyset, `(ts, id)` from the last row shown, not an
// OFFSET: rows arrive at the head of this ordering while an admin pages through
// it, so OFFSET repeats page one's rows on page two, and once the retention job
// starts deleting from the tail (N-04) it skips rows instead.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditQuery {
    /// The `actor_sub` the kill switch takes or the `actor_name` a person reads
    /// off a ticket — whichever of the two the admin happens to have.
    actor: Option<String>,
    app: Option<String>,
    decision: Option<AuditDecision>,
    reason: Option<String>,
    /// Inclusive; `until` is exclusive, so consecutive windows neither overlap
    /// nor leave a gap.
    since: Option<DateTime<Utc>>,
    until: Option<DateTime<Utc>>,
    before_ts: Option<DateTime<Utc>>,
    before_id: Option<Uuid>,
    limit: Option<i64>,
}

async fn list_audit(State(ctx): State<Arc<Ctx>>, Query(q): Query<AuditQuery>) -> Response {
    if q.before_ts.is_some() != q.before_id.is_some() {
        return bad_request("before_ts and before_id are one cursor: pass both or neither");
    }
    // A cap, not a preference: this table is designed to grow without bound and
    // an unbounded LIMIT is a self-DoS an admin can type by accident.
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    let decision = q.decision.as_ref().map(|d| match d {
        AuditDecision::Allow => "allow",
        AuditDecision::Deny => "deny",
    });
    // ponytail: matching `actor` against either column defeats
    // audit_event_actor_idx, which leads on actor_sub alone. The ts index still
    // bounds the common case — a recent page — and the alternative is two
    // parameters for one question the admin can only answer one way. Split them
    // when a search far down the table is measurably slow.
    let found: Result<Vec<AuditRow>, _> = sqlx::query_as(
        "select id, ts, actor_sub, actor_name, application_id, application_slug,
                decision, reason, count, first_seen, last_seen, distinct_path,
                first_path, src_ip, request_id
           from audit_event
          where ($1::text is null or actor_sub = $1 or actor_name = $1)
            and ($2::text is null or application_slug = $2)
            and ($3::text is null or decision = $3)
            and ($4::text is null or reason = $4)
            and ($5::timestamptz is null or ts >= $5)
            and ($6::timestamptz is null or ts < $6)
            and ($7::timestamptz is null or (ts, id) < ($7, $8::uuid))
          order by ts desc, id desc
          limit $9",
    )
    .bind(&q.actor)
    .bind(&q.app)
    .bind(decision)
    .bind(&q.reason)
    .bind(q.since)
    .bind(q.until)
    .bind(q.before_ts)
    .bind(q.before_id)
    .bind(limit)
    .fetch_all(&ctx.pool)
    .await;
    match found {
        Ok(rows) => Json(rows).into_response(),
        Err(e) => failed("list_audit", "-", e),
    }
}
// --- Feature End ---

/// `GET /api/admin/explain?user&groups&host&path` — the decision the PEP would
/// reach for that request, and the rules it walked to get there.
///
/// Read-only: it fills no cache entry, writes no audit row and derives no
/// identity from the caller, so asking why a user was denied cannot itself
/// change what happens to them next. The verdict is `policy::decide`'s own
/// (`policy::explain` annotates, it does not decide) over the rows store's
/// `applicable!` hands the decision path — a screen answering differently from
/// the PEP would send an admin to fix the wrong rule. The one disagreement left
/// is deliberate: this reads the table while the PEP may still be serving a
/// cache entry, so for up to `cache::TTL` after a rule change the explanation
/// is right and the URL is stale. Reading the cache instead would make it
/// explain a decision that is about to stop being true.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExplainQuery {
    /// The Keycloak `sub`, the same value the kill switch takes and the audit
    /// record's `actor_sub` column holds — not the username. It is echoed back
    /// so an admin who passed the wrong one can see that they did.
    user: String,
    /// Comma-separated, as the token carries them.
    groups: Option<String>,
    /// The `external_hostname`, which is how nginx picks the application.
    host: String,
    /// As the client would send it, query string and all: half the tickets this
    /// endpoint answers are a path that normalised into something else.
    path: String,
}

async fn explain(State(ctx): State<Arc<Ctx>>, Query(q): Query<ExplainQuery>) -> Response {
    // --- Feature Start ---
    // Required, not defaulted to none. The backend keeps no directory of its
    // own, so a missing `groups` cannot be filled in — and answering anyway
    // drops every ad_group rule and reports `no_matching_grant` for a user who
    // has access. That is the one answer this endpoint must never give.
    // --- Feature End ---
    let Some(groups) = q.groups else {
        return bad_request(
            "groups is required (comma-separated, empty for a user in none): \
             the backend holds no directory, and explaining without them drops \
             every group rule and reports a denial that would not happen",
        );
    };
    let groups: Vec<String> = groups
        .split(',')
        .map(str::trim)
        .filter(|g| !g.is_empty())
        .map(str::to_owned)
        .collect();

    // An admin pastes a URL's authority, and the schema stores neither a port
    // nor an uppercase letter.
    let host = q
        .host
        .split(':')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let found: Result<Option<(Uuid, String, bool)>, _> =
        sqlx::query_as("select id, slug, enabled from application where external_hostname = $1")
            .bind(&host)
            .fetch_optional(&ctx.pool)
            .await;
    let (application_id, slug, enabled) = match found {
        Ok(Some(row)) => row,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": "no application answers on that hostname",
                    "host": host,
                })),
            )
                .into_response();
        }
        Err(e) => return failed("explain", "-", e),
    };

    let traced = match store::traced_rules_for(&ctx.pool, application_id, &q.user, &groups).await {
        Ok(traced) => traced,
        Err(e) => return failed("explain", "-", e),
    };
    let rules: Vec<policy::Rule> = traced.iter().map(|t| t.rule.clone()).collect();
    let trace = policy::explain(enabled, &rules, &q.path, Utc::now());
    let (decision, reason) = trace.decision.as_pair();

    let walked: Vec<serde_json::Value> = traced
        .iter()
        .zip(&trace.rules)
        .map(|(row, verdict)| {
            serde_json::json!({
                "id": row.id,
                // Null is the wildcard of docs/05 rule 4: this rule applies to
                // every application, not only the one being explained.
                "application_id": row.application_id,
                "subject_type": row.subject_type,
                "subject_id": row.subject_id,
                "effect": match row.rule.effect {
                    policy::Effect::Allow => "allow",
                    policy::Effect::Deny => "deny",
                },
                "path_pattern": row.rule.path_pattern,
                "expires_at": row.rule.expires_at,
                "matched": verdict.matched,
                "expired": verdict.expired,
            })
        })
        .collect();

    Json(serde_json::json!({
        "subject": { "sub": q.user, "groups": groups },
        "resource": {
            "host": host,
            "application": slug,
            "enabled": enabled,
            "path": q.path,
            // What the rules were actually matched against. `null` means the
            // URI was refused before any rule was consulted.
            "normalised_path": trace.path,
        },
        "decision": decision,
        "reason": reason,
        "rules": walked,
    }))
    .into_response()
}

// --- Feature Start ---
// upstream_url is a trust boundary input (ADR-0011): it becomes a `proxy_pass`
// in generated nginx configuration, on an nginx that sits on *both* networks.
// A record naming an infrastructure service would publish Postgres or Redis
// through the proxy, and one naming a link-local address would publish a cloud
// metadata endpoint. Private ranges are deliberately allowed — every real
// upstream is on one.
// --- Feature End ---
pub fn validate_upstream(raw: &str) -> Result<(), String> {
    let url = Url::parse(raw).map_err(|_| "upstream_url is not a URL".to_string())?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err("upstream_url must be http or https".into());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("upstream_url must not carry credentials".into());
    }
    if !matches!(url.path(), "" | "/") || url.query().is_some() || url.fragment().is_some() {
        return Err("upstream_url must be scheme://host:port with no path".into());
    }
    // Blunt, and deliberately so: an admin typing an IP address instead of a
    // service name would walk past the name check below, and nothing legitimate
    // behind this proxy speaks Postgres or Redis over HTTP.
    if let Some(port) = url.port()
        && [5432, 6379, 389, 636, 3268, 3269].contains(&port)
    {
        return Err("upstream_url names an infrastructure port".into());
    }
    match url.host().ok_or("upstream_url has no host".to_string())? {
        Host::Domain(name) => {
            let name = name.to_ascii_lowercase();
            if [
                "localhost",
                "postgres",
                "redis",
                "keycloak",
                "backend",
                "oauth2-proxy",
                "nginx",
                "samba-ad",
                "dc01",
            ]
            .contains(&name.as_str())
            {
                return Err("upstream_url names an infrastructure service".into());
            }
        }
        Host::Ipv4(ip) => reject_reserved(IpAddr::V4(ip))?,
        Host::Ipv6(ip) => reject_reserved(IpAddr::V6(ip))?,
    }
    Ok(())
}

fn reject_reserved(ip: IpAddr) -> Result<(), String> {
    let bad = match ip {
        // 169.254.0.0/16 is where a cloud metadata service lives.
        IpAddr::V4(v4) => {
            v4.is_loopback() || v4.is_link_local() || v4.is_unspecified() || v4.is_multicast()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    };
    if bad {
        return Err("upstream_url names a loopback, link-local or multicast address".into());
    }
    Ok(())
}

/// A generated block for `portal.…` or `auth.…` would shadow the portal or the
/// login flow — and nginx would serve it without complaint, because the first
/// matching `server_name` wins (ADR-0011).
pub fn validate_hostname(hostname: &str, portal_origin: &str) -> Result<(), String> {
    let hostname = hostname.to_ascii_lowercase();
    let first = hostname.split('.').next().unwrap_or_default();
    if ["portal", "auth"].contains(&first) {
        return Err("external_hostname uses a reserved name (portal, auth)".into());
    }
    if Url::parse(portal_origin)
        .ok()
        .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
        .is_some_and(|portal| portal == hostname)
    {
        return Err("external_hostname is the portal's own hostname".into());
    }
    Ok(())
}

// --- Feature Start ---
// The generated blocks are a security boundary, not a convenience: every one of
// them has to pull in protected.inc (the X-Auth-* strip and the auth_request)
// and decide.inc. Forget either in this template and the claim falls for every
// application it generates, silently and with `nginx -t` reporting success
// (ADR-0011). A row that does not validate is skipped rather than rendered —
// one bad record must not take the whole file, and therefore every other
// application, down with it.
// --- Feature End ---
/// The certificate is not written here: it is set once at http level in
/// `nginx/conf.d/tls.inc`, so this template cannot drift from the hand-written
/// blocks over where the operator's certificate lives.
pub fn render_apps_conf(applications: &[Application], portal_origin: &str) -> String {
    let mut out = String::from(
        "# Generated from the `application` table by the backend (ADR-0011).\n         # Do not edit: the next admin change overwrites it. The hand-written\n         # half of the configuration is in the image; only this file is not.\n",
    );
    for app in applications {
        if !app.enabled {
            continue;
        }
        // Belt and braces over the schema's CHECK constraints and the API's
        // validation: this is the last point before the value becomes nginx
        // configuration, and it is the only one that is not on a happy path.
        if let Err(why) = validate_upstream(&app.upstream_url)
            .and_then(|()| validate_hostname(&app.external_hostname, portal_origin))
        {
            tracing::error!(slug = %app.slug, "skipping application in generated config: {why}");
            continue;
        }
        let Ok(url) = Url::parse(&app.upstream_url) else {
            continue;
        };
        let (Some(host), Some(port)) = (url.host_str(), url.port_or_known_default()) else {
            continue;
        };
        out.push_str(&format!(
            "\nserver {{\n\
             \x20   listen 443 ssl;\n\
             \x20   http2 on;\n\
             \x20   server_name {hostname};\n\n\
             \x20   # Fixed here, never taken from the request: the subrequest\n\
             \x20   # inherits the client's Host verbatim.\n\
             \x20   set $app_slug {slug};\n\n\
             \x20   include /etc/nginx/conf.d/errors.inc;\n\
             \x20   include /etc/nginx/conf.d/decide.inc;\n\n\
             \x20   location / {{\n\
             \x20       include /etc/nginx/conf.d/protected.inc;\n\
             \x20       set $upstream {host};\n\
             \x20       proxy_pass {scheme}://$upstream:{port};\n\
             \x20   }}\n\
             }}\n",
            hostname = app.external_hostname,
            slug = app.slug,
            host = host,
            port = port,
            scheme = url.scheme(),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const PORTAL: &str = "https://portal.apps.example.local";

    #[test]
    fn an_upstream_may_be_an_ordinary_private_address() {
        for good in [
            "http://sample-app:80",
            "https://intranet.example.local",
            "http://10.1.2.3:8080",
            "http://172.19.0.5",
            "http://192.168.1.10:3000",
            "http://[fd00::1]:8080",
        ] {
            assert!(
                validate_upstream(good).is_ok(),
                "{good}: {:?}",
                validate_upstream(good)
            );
        }
    }

    #[test]
    fn an_upstream_may_not_be_the_infrastructure() {
        // Every one of these becomes a proxy_pass on an nginx that sits on both
        // networks, so each is a way to publish something that should never be
        // reachable from a browser.
        for bad in [
            "http://postgres:5432",
            "http://redis:6379",
            "http://keycloak:8080",
            "http://backend:8081",
            "http://oauth2-proxy:4180",
            "http://127.0.0.1:8080",
            "http://localhost:8080",
            "http://[::1]:8080",
            "http://169.254.169.254/", // cloud metadata
            "http://[fe80::1]:80",
            "http://0.0.0.0:80",
            "http://10.1.2.3:5432", // the name check would have missed this
            "http://10.1.2.3:389",  // and this is the directory
        ] {
            assert!(validate_upstream(bad).is_err(), "{bad} should be refused");
        }
    }

    #[test]
    fn an_upstream_is_a_host_and_a_port_and_nothing_else() {
        for bad in [
            "",
            "not a url",
            "ftp://files.example.local",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "http://user:pass@app.example.local",
            "http://app.example.local/some/path",
            "http://app.example.local/?a=1",
        ] {
            assert!(validate_upstream(bad).is_err(), "{bad} should be refused");
        }
    }

    fn app(slug: &str, upstream: &str, hostname: &str, enabled: bool) -> Application {
        Application {
            id: Uuid::nil(),
            slug: slug.into(),
            name: slug.into(),
            icon: None,
            upstream_url: upstream.into(),
            external_hostname: hostname.into(),
            enabled,
        }
    }

    #[test]
    fn every_generated_location_pulls_in_the_strip() {
        let rendered = render_apps_conf(
            &[
                app(
                    "wiki",
                    "http://wiki-app:8080",
                    "wiki.apps.example.local",
                    true,
                ),
                app("crm", "https://crm-app", "crm.apps.example.local", true),
            ],
            PORTAL,
        );
        // The one thing that must never be missing. Without it a generated
        // application trusts whatever X-Auth-* the client sent, and `nginx -t`
        // is perfectly happy (ADR-0011).
        assert_eq!(
            rendered
                .matches("include /etc/nginx/conf.d/protected.inc;")
                .count(),
            2
        );
        assert_eq!(
            rendered
                .matches("include /etc/nginx/conf.d/decide.inc;")
                .count(),
            2
        );
        assert_eq!(
            rendered
                .matches("include /etc/nginx/conf.d/errors.inc;")
                .count(),
            2
        );
        // One location per server, so the count above is per application and
        // not two includes on one of them and none on the other.
        assert_eq!(rendered.matches("location / {").count(), 2);
        assert_eq!(rendered.matches("server {").count(), 2);
        // The slug is fixed in the block, never read from the request.
        assert!(rendered.contains("set $app_slug wiki;"));
        // A variable in proxy_pass is what defers DNS to request time, so a
        // stopped upstream costs one 502 instead of nginx refusing to start.
        assert!(
            rendered.contains("set $upstream wiki-app;\n        proxy_pass http://$upstream:8080;")
        );
        // https keeps its scheme and its default port.
        assert!(rendered.contains("proxy_pass https://$upstream:443;"));
        // Never a `return`: that would run before auth_request and leave the
        // location open (nginx/conf.d/README.md rule 14).
        assert!(!rendered.contains("return "));
    }

    #[test]
    fn a_row_that_should_not_be_there_is_skipped_not_rendered() {
        // The schema and the API both refuse these, so a row like this means
        // something reached the table another way. One bad record must not take
        // every other application down with it.
        let rendered = render_apps_conf(
            &[
                app(
                    "good",
                    "http://good-app:80",
                    "good.apps.example.local",
                    true,
                ),
                app("pg", "http://postgres:5432", "pg.apps.example.local", true),
                app("shadow", "http://x:80", "portal.apps.example.local", true),
                app("off", "http://off-app:80", "off.apps.example.local", false),
            ],
            PORTAL,
        );
        assert_eq!(rendered.matches("server {").count(), 1);
        assert!(rendered.contains("good.apps.example.local"));
        assert!(!rendered.contains("postgres"));
        assert!(!rendered.contains("portal.apps.example.local"));
        assert!(
            !rendered.contains("off-app"),
            "a disabled application has no block"
        );
    }

    #[test]
    fn a_hostname_may_not_shadow_the_portal_or_the_login_flow() {
        assert!(validate_hostname("sample.apps.example.local", PORTAL).is_ok());
        for bad in [
            "portal.apps.example.local",
            "PORTAL.apps.example.local",
            "auth.apps.example.local",
            "portal.somewhere.else",
        ] {
            assert!(
                validate_hostname(bad, PORTAL).is_err(),
                "{bad} should be refused"
            );
        }
    }
}
