// SPDX-FileCopyrightText: 2026 OpenBerat contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// The management plane: /api/admin/*. Not protected by the entitlement table —
// the portal is open to every authenticated user, so if reaching it were enough
// then anyone could grant themselves entitlements (docs/02, "Management plane").
//
// Two guards, both in `guard` below rather than on each handler: ADMIN_GROUP
// membership, and an Origin check on anything state-changing. Every route the
// management plane has is mounted here, including the read-only screens whose
// handlers live in `audit.rs`, so there is one list to read the guard against.
//
// What the endpoints here change is applications, entitlements and sessions.
// What they refuse to store is `validate.rs`; what an application row becomes
// once stored is `nginx.rs`.

use crate::api::{Caller, Ctx};
use crate::keycloak::LogoutError;
use crate::policy;
use crate::validate::{validate_hostname, validate_path_pattern, validate_slug, validate_upstream};
use crate::{audit, nginx};
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
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
        .route("/api/admin/audit", get(audit::list_audit))
        .route("/api/admin/sessions", get(audit::list_sessions))
        .route("/api/admin/explain", get(audit::explain))
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

/// One `application` row. `nginx.rs` renders it into a server block, which is
/// why the fields are reachable from there and nowhere else.
#[derive(Serialize, sqlx::FromRow)]
pub struct Application {
    pub(crate) id: Uuid,
    pub(crate) slug: String,
    pub(crate) name: String,
    pub(crate) icon: Option<String>,
    pub(crate) upstream_url: String,
    pub(crate) external_hostname: String,
    pub(crate) enabled: bool,
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
    nginx::publish_conf(&ctx.pool, dir, &ctx.portal_origin).await
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

pub(crate) fn bad_request(message: impl Into<String>) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "error": message.into() })),
    )
        .into_response()
}

/// Everything the admin API can do to the database ends here, so the mapping
/// from a database error to an answer is written once.
pub(crate) fn failed(action: &str, actor: &str, e: sqlx::Error) -> Response {
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
    if let Err(why) = validate_slug(&new.slug) {
        return bad_request(why);
    }
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
    if let Err(why) = validate_path_pattern(&new.path_pattern) {
        return bad_request(why);
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
