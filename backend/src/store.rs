// Postgres access (sqlx). application / entitlement / audit_event queries.
// Schema: migrations/0001_init.sql, model: docs/02-architecture.md

use crate::policy::{Decision, Effect, Rule};
use chrono::{DateTime, Datelike, Utc};
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
// The rows that apply to one user on one application, written once because two
// copies drift: `/api/admin/explain` answering from a different rule set than
// `/decide` is a screen that confidently explains a decision nobody made.
// Binds: $1 the application id, $2 the user's groups, $3 their sub.
// --- Feature End ---
// A macro rather than a `const` because sqlx accepts only `&'static str`, by
// design: it is what stops a query being built by `format!` from user input.
macro_rules! applicable {
    () => {
        "(application_id = $1 or application_id is null)
            and ( (subject_type = 'ad_group' and subject_id = any($2))
               or (subject_type = 'user' and subject_id = $3) )"
    };
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

    let rows: Vec<(String, String, Option<DateTime<Utc>>)> = sqlx::query_as(concat!(
        "select effect, path_pattern, expires_at from entitlement where ",
        applicable!()
    ))
    .bind(id)
    .bind(groups)
    .bind(sub)
    .fetch_all(pool)
    .await?;

    let rules = rows
        .into_iter()
        .map(|(effect, path_pattern, expires_at)| Rule {
            effect: effect_of(&effect),
            path_pattern,
            expires_at,
        })
        .collect();

    Ok(Some(AppRules { id, enabled, rules }))
}

/// One entitlement row as `/api/admin/explain` shows it: the rule the decision
/// was made from, plus enough of the row for the admin to find it and change it.
#[derive(Debug)]
pub struct TracedRule {
    pub id: Uuid,
    pub application_id: Option<Uuid>,
    pub subject_type: String,
    pub subject_id: String,
    pub rule: Rule,
}

/// id, application_id, subject_type, subject_id, and the rule's effect, pattern
/// and expiry.
type TracedRow = (
    Uuid,
    Option<Uuid>,
    String,
    String,
    String,
    String,
    Option<DateTime<Utc>>,
);

/// The same rows `rules_for` would hand the decision path, with their identity
/// kept. The application is already resolved here because the explain screen
/// arrives with a hostname rather than a slug.
pub async fn traced_rules_for(
    pool: &PgPool,
    application_id: Uuid,
    sub: &str,
    groups: &[String],
) -> Result<Vec<TracedRule>, sqlx::Error> {
    let rows: Vec<TracedRow> = sqlx::query_as(concat!(
        "select id, application_id, subject_type, subject_id,
                effect, path_pattern, expires_at
           from entitlement where ",
        applicable!(),
        " order by effect, subject_id"
    ))
    .bind(application_id)
    .bind(groups)
    .bind(sub)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(
            |(id, application_id, subject_type, subject_id, effect, path_pattern, expires_at)| {
                TracedRule {
                    id,
                    application_id,
                    subject_type,
                    subject_id,
                    rule: Rule {
                        effect: effect_of(&effect),
                        path_pattern,
                        expires_at,
                    },
                }
            },
        )
        .collect())
}

/// The column is constrained to these two values by the schema, so anything
/// else means the schema moved underneath the code.
fn effect_of(effect: &str) -> Effect {
    if effect == "deny" {
        Effect::Deny
    } else {
        Effect::Allow
    }
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
        let (decision, reason) = event.decision.as_pair();
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

// --- Feature Start ---
// Audit rows leave the database as a DROP and not as a DELETE: `audit_event` is
// partitioned by month (0001_init.sql), so a month falling out of retention is
// one DDL statement instead of a row-by-row delete of everything in it. The two
// halves belong together — the partitions created ahead here are the ones a
// later run drops. `audit_event_default` is never dropped: it is what keeps an
// INSERT for an uncovered month from failing off the request path, so rows that
// land in it are deleted rather than detached. Retention is counted in months
// because the unit that leaves is a month; a figure in days would promise a
// precision the mechanism does not have (ADR-0022).
// --- Feature End ---
pub async fn maintain_audit(pool: &PgPool, months: u32) -> Result<(), sqlx::Error> {
    let this_month = Utc::now()
        .date_naive()
        .with_day(1)
        .expect("every month has a first day");

    for ahead in 0..=1 {
        let from = this_month + chrono::Months::new(ahead);
        let to = from + chrono::Months::new(1);
        let create = format!(
            "create table if not exists audit_event_{} partition of audit_event \
             for values from ('{from} 00:00:00+00') to ('{to} 00:00:00+00')",
            from.format("%Y_%m"),
        );
        // Deliberately not `?`: a month whose rows are already in the default
        // partition cannot be split out from under them, and the expiry below
        // is the half that still has to run. It heals itself next month.
        if let Err(e) = sqlx::query(sqlx::AssertSqlSafe(create)).execute(pool).await {
            tracing::warn!(error = %e, month = %from, "cannot create the audit partition");
        }
    }

    // A deletion that cannot compute its own cutoff deletes nothing.
    let Some(cutoff) = this_month.checked_sub_months(chrono::Months::new(months)) else {
        tracing::error!("AUDIT_RETENTION_MONTHS={months} puts the cutoff off the calendar");
        return Ok(());
    };

    // The name pattern is what makes interpolating the result below safe, and it
    // is also what excludes audit_event_default — by shape rather than by an
    // equality test somebody can delete.
    let expired: Vec<String> = sqlx::query_scalar(
        r#"select c.relname::text from pg_class c
             join pg_inherits i on i.inhrelid = c.oid
            where i.inhparent = 'audit_event'::regclass
              and c.relname::text ~ '^audit_event_[0-9]{4}_[0-9]{2}$'
              and c.relname::text collate "C" < $1"#,
    )
    .bind(format!("audit_event_{}", cutoff.format("%Y_%m")))
    .fetch_all(pool)
    .await?;
    for name in &expired {
        sqlx::query(sqlx::AssertSqlSafe(format!("drop table {name}")))
            .execute(pool)
            .await?;
    }

    let rows = sqlx::query("delete from audit_event_default where ts < $1")
        .bind(
            cutoff
                .and_hms_opt(0, 0, 0)
                .expect("midnight exists")
                .and_utc(),
        )
        .execute(pool)
        .await?
        .rows_affected();

    // The record of a deletion cannot be a row in the table it deletes from, so
    // it goes to the structured stream the SIEM reads (F-23).
    if !expired.is_empty() || rows > 0 {
        tracing::info!(
            partitions = ?expired,
            stray_rows = rows,
            "audit retention: everything before {cutoff} removed"
        );
    }
    Ok(())
}
