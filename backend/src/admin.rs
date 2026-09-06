// The management plane: /api/admin/*. Not protected by the entitlement table —
// the portal is open to every authenticated user, so if reaching it were enough
// then anyone could grant themselves entitlements (docs/02, "Management plane").
//
// Two guards, both in `guard` below rather than on each handler: ADMIN_GROUP
// membership, and an Origin check on anything state-changing.

use crate::api::{Caller, Ctx};
use crate::policy;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
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
    // SameSite cannot do this job: the portal and the applications are
    // same-site by design (ADR-0015), so a compromised application's page is a
    // same-site caller.
    if !matches!(*request.method(), Method::GET | Method::HEAD)
        && headers.get("origin").and_then(|v| v.to_str().ok()) != Some(ctx.portal_origin.as_str())
    {
        tracing::warn!(actor = %caller.username, path = %request.uri().path(),
            "admin refused: wrong or missing Origin");
        return StatusCode::FORBIDDEN.into_response();
    }
    next.run(request).await
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
            (StatusCode::CREATED, Json(application)).into_response()
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
            Json(application).into_response()
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
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(_) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => failed("delete_application", &actor, e),
    }
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
