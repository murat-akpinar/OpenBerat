// Postgres access (sqlx). application / entitlement / audit_event queries.
// Schema: migrations/0001_init.sql, model: docs/02-architecture.md

use crate::policy::{Decision, Effect, Rule};
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::mpsc;
use uuid::Uuid;

// --- Feature Start ---
// The schema is applied by the process itself and a failure is fatal. A backend
// answering /decide against a schema it has not migrated decides with rules it
// cannot see, and fail-closed means refusing to start rather than guessing.
// --- Feature End ---
pub async fn connect(url: &str) -> Result<PgPool, sqlx::Error> {
    // Long enough to ride out Postgres still starting on the first `docker
    // compose up`, short enough that an absent one fails and lets compose retry
    // with backoff instead of holding the process for sqlx's default 30 s.
    // The decision path wants far less than this (TODO.md Phase 3, 500 ms).
    let pool = PgPoolOptions::new()
        .acquire_timeout(Duration::from_secs(5))
        .connect(url)
        .await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
}

/// One application and the rules that apply to one user on it — the whole of
/// what a cache entry is filled from (docs/05, "Decision cache").
#[derive(Debug)]
pub struct AppRules {
    pub id: Uuid,
    pub enabled: bool,
    pub rules: Vec<Rule>,
}

// --- Feature Start ---
// The two things this query gets wrong silently. A rule with a NULL
// application_id applies to every application (docs/05 rule 4), so the id
// cannot simply be equality-matched. And expiry is deliberately not filtered
// here: the rules live in a cache entry for a TTL, and policy.rs re-checks
// expires_at against the clock on every hit — filtering now would freeze the
// answer at the moment of the query and keep an expired grant alive for the
// rest of the TTL.
// --- Feature End ---
pub async fn rules_for(
    pool: &PgPool,
    slug: &str,
    sub: &str,
    groups: &[String],
) -> Result<Option<AppRules>, sqlx::Error> {
    let Some((id, enabled)): Option<(Uuid, bool)> =
        sqlx::query_as("select id, enabled from application where slug = $1")
            .bind(slug)
            .fetch_optional(pool)
            .await?
    else {
        return Ok(None);
    };

    let rows: Vec<(String, String, Option<DateTime<Utc>>)> = sqlx::query_as(
        "select effect, path_pattern, expires_at from entitlement
          where (application_id = $1 or application_id is null)
            and ( (subject_type = 'ad_group' and subject_id = any($2))
               or (subject_type = 'user' and subject_id = $3) )",
    )
    .bind(id)
    .bind(groups)
    .bind(sub)
    .fetch_all(pool)
    .await?;

    let rules = rows
        .into_iter()
        .map(|(effect, path_pattern, expires_at)| Rule {
            // The column is constrained to these two values by the schema, so
            // anything else means the schema moved underneath the code.
            effect: if effect == "deny" {
                Effect::Deny
            } else {
                Effect::Allow
            },
            path_pattern,
            expires_at,
        })
        .collect();

    Ok(Some(AppRules { id, enabled, rules }))
}

/// One application the portal might show, with the rules that apply to this
/// user on it. The verdict is `policy::decide`'s to make — the portal must not
/// contain a second, subtly different one (docs/02, "Flow: the portal").
#[derive(Debug)]
pub struct PortalApp {
    pub slug: String,
    pub name: String,
    pub icon: Option<String>,
    pub external_hostname: String,
    pub rules: Vec<Rule>,
}

// --- Feature Start ---
// One query for every application rather than one per application, and a LEFT
// JOIN rather than an inner one: an application with no matching entitlement
// still has to come back, because "no rule" is a decision (`no_matching_grant`)
// and not an absence. An inner join would quietly hide exactly the applications
// the portal is being asked about.
// --- Feature End ---
/// slug, name, icon, external_hostname, and the joined rule's effect, pattern
/// and expiry — all three None for an application with no matching rule.
type PortalRow = (
    String,
    String,
    Option<String>,
    String,
    Option<String>,
    Option<String>,
    Option<DateTime<Utc>>,
);

pub async fn portal_apps(
    pool: &PgPool,
    sub: &str,
    groups: &[String],
) -> Result<Vec<PortalApp>, sqlx::Error> {
    let rows: Vec<PortalRow> = sqlx::query_as(
        "select a.slug, a.name, a.icon, a.external_hostname,
                    e.effect, e.path_pattern, e.expires_at
               from application a
               left join entitlement e
                 on (e.application_id = a.id or e.application_id is null)
                and ( (e.subject_type = 'ad_group' and e.subject_id = any($1))
                   or (e.subject_type = 'user' and e.subject_id = $2) )
              where a.enabled
              -- name alone would not group the rows of one application
              -- together if two applications shared a name; slug is unique.
              order by a.name, a.slug",
    )
    .bind(groups)
    .bind(sub)
    .fetch_all(pool)
    .await?;

    let mut apps: Vec<PortalApp> = Vec::new();
    for (slug, name, icon, external_hostname, effect, path_pattern, expires_at) in rows {
        if apps.last().is_none_or(|a| a.slug != slug) {
            apps.push(PortalApp {
                slug,
                name,
                icon,
                external_hostname,
                rules: Vec::new(),
            });
        }
        if let (Some(effect), Some(path_pattern)) = (effect, path_pattern) {
            apps.last_mut().expect("just pushed").rules.push(Rule {
                effect: if effect == "deny" {
                    Effect::Deny
                } else {
                    Effect::Allow
                },
                path_pattern,
                expires_at,
            });
        }
    }
    Ok(apps)
}

/// One summary row: a cache entry's requests for one outcome, folded together
/// (docs/02, "Audit granularity").
#[derive(Debug)]
pub struct AuditEvent {
    pub application_id: Option<Uuid>,
    pub application_slug: String,
    pub actor_sub: String,
    pub actor_name: Option<String>,
    pub decision: Decision,
    pub count: i32,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub distinct_path: i32,
    pub first_path: String,
    pub src_ip: Option<IpAddr>,
    pub request_id: Option<String>,
}

static AUDIT_DROPPED: AtomicU64 = AtomicU64::new(0);

/// Summaries lost because the channel was full or the insert failed. Read by
/// the operator, not by the decision path.
pub fn audit_dropped() -> u64 {
    AUDIT_DROPPED.load(Ordering::Relaxed)
}

#[derive(Clone)]
pub struct Audit(mpsc::Sender<AuditEvent>);

impl Audit {
    // --- Feature Start ---
    // Never waits. A blocking send would put the audit write back on the
    // decision path, which is the one thing docs/02 says it must not be — a
    // slow Postgres would then become a slow /decide and, through the timeout
    // budget, a denial. Losing a summary row is the lesser failure, and it is
    // counted rather than silent.
    // --- Feature End ---
    pub fn record(&self, event: AuditEvent) {
        if self.0.try_send(event).is_err() {
            AUDIT_DROPPED.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(dropped = audit_dropped(), "audit channel full");
        }
    }
}

pub fn audit_channel(capacity: usize) -> (Audit, mpsc::Receiver<AuditEvent>) {
    let (tx, rx) = mpsc::channel(capacity);
    (Audit(tx), rx)
}

/// Drains the channel until every sender is gone, which is what shutdown looks
/// like from here.
pub async fn write_audit(pool: PgPool, mut rx: mpsc::Receiver<AuditEvent>) {
    while let Some(event) = rx.recv().await {
        let (decision, reason) = match event.decision {
            Decision::Allow => ("allow", "allowed"),
            Decision::Deny(reason) => ("deny", reason.as_str()),
        };
        let written = sqlx::query(
            "insert into audit_event
               (application_id, application_slug, actor_sub, actor_name, decision, reason,
                count, first_seen, last_seen, distinct_path, first_path, src_ip, request_id)
             values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
        )
        .bind(event.application_id)
        .bind(&event.application_slug)
        .bind(&event.actor_sub)
        .bind(&event.actor_name)
        .bind(decision)
        .bind(reason)
        .bind(event.count)
        .bind(event.first_seen)
        .bind(event.last_seen)
        .bind(event.distinct_path)
        .bind(&event.first_path)
        .bind(event.src_ip)
        .bind(&event.request_id)
        .execute(&pool)
        .await;
        if let Err(e) = written {
            AUDIT_DROPPED.fetch_add(1, Ordering::Relaxed);
            tracing::error!(error = %e, dropped = audit_dropped(), "audit row lost");
        }
    }
}
