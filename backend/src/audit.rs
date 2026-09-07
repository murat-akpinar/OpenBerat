// SPDX-FileCopyrightText: 2026 OpenBerat contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// The three admin screens that only read: the audit record, who is signed in
// (ADR-0028) and why a decision came out the way it did. None of them writes
// anything — no row, no cache entry, no Redis key — so asking a question here
// can never change the answer to it. They are routed and guarded in `admin.rs`
// like every other management-plane endpoint.

use crate::admin::{bad_request, failed};
use crate::api::Ctx;
use crate::policy;
use crate::store;
use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;
use uuid::Uuid;

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
pub(crate) struct AuditQuery {
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

pub(crate) async fn list_audit(
    State(ctx): State<Arc<Ctx>>,
    Query(q): Query<AuditQuery>,
) -> Response {
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

/// One signed-in subject, as `GET /api/admin/sessions` reports it (ADR-0028).
/// `sessions` counts session keys that still exist, not set members.
#[derive(Serialize)]
struct LiveSession {
    sub: String,
    sessions: usize,
    /// From the audit record, and null for a subject it has never seen — which
    /// is the portal-only session ADR-0019 exists for. The index holds a `sub`
    /// and nothing else, and the name inside the session is behind the cookie
    /// secret this backend deliberately never holds (`session.rs`).
    last_seen_as: Option<String>,
    last_activity: Option<DateTime<Utc>>,
}

// --- Feature Start ---
// Who is signed in (ADR-0028), read out of the kill-switch index. Read-only in
// both directions: nothing is written to Redis, not even to prune a dead member,
// and no route on this screen revokes anything — revocation stays
// `POST /api/admin/kill/{sub}`, which an operator runs deliberately.
// --- Feature End ---
pub(crate) async fn list_sessions(State(ctx): State<Arc<Ctx>>) -> Response {
    let live = match ctx.index.live().await {
        Ok(live) => live,
        Err(e) => {
            tracing::error!(actor = "-", action = "list_sessions", outcome = "error", error = %e, "admin");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };

    let subs: Vec<String> = live.iter().map(|(sub, _)| sub.clone()).collect();
    // The most recent audit row per subject. `distinct on` needs the same
    // leading column in the ordering, which is also what audit_event_actor_idx
    // leads on.
    let seen: Vec<(String, Option<String>, DateTime<Utc>)> = match sqlx::query_as(
        "select distinct on (actor_sub) actor_sub, actor_name, ts
           from audit_event where actor_sub = any($1)
          order by actor_sub, ts desc",
    )
    .bind(&subs)
    .fetch_all(&ctx.pool)
    .await
    {
        Ok(seen) => seen,
        // The list is still worth answering without names: a subject with a
        // session and no name is the one case this endpoint exists for.
        Err(e) => {
            tracing::warn!(error = %e, "sessions: the audit record could not be read for names");
            Vec::new()
        }
    };

    let mut rows: Vec<LiveSession> = live
        .into_iter()
        .map(|(sub, sessions)| {
            let seen = seen.iter().find(|(actor, _, _)| *actor == sub);
            LiveSession {
                sub,
                sessions,
                last_seen_as: seen.and_then(|(_, name, _)| name.clone()),
                last_activity: seen.map(|(_, _, ts)| *ts),
            }
        })
        .collect();
    // Most recently active first; a subject the audit record has never seen
    // sorts last rather than being dropped.
    rows.sort_by(|a, b| {
        b.last_activity
            .cmp(&a.last_activity)
            .then_with(|| a.sub.cmp(&b.sub))
    });
    Json(rows).into_response()
}

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
pub(crate) struct ExplainQuery {
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

pub(crate) async fn explain(
    State(ctx): State<Arc<Ctx>>,
    Query(q): Query<ExplainQuery>,
) -> Response {
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
