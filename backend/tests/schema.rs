// The migration runs unattended on an operator's first install, so this is the
// only place its SQL is executed before it reaches one. Needs a live Postgres:
//   docker run --rm -d -p 55432:5432 -e POSTGRES_PASSWORD=test \
//     -e POSTGRES_USER=openberat -e POSTGRES_DB=openberat postgres:17-alpine
//   DATABASE_URL=postgres://openberat:test@localhost:55432/openberat cargo test
// Without DATABASE_URL the test skips loudly rather than failing.

use sqlx::PgPool;
use uuid::Uuid;

async fn fresh_db() -> Option<PgPool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let pool = PgPool::connect(&url)
        .await
        .expect("connect to DATABASE_URL");
    for stmt in ["drop schema public cascade", "create schema public"] {
        sqlx::query(stmt)
            .execute(&pool)
            .await
            .expect("reset schema");
    }
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("0001_init.sql applies to an empty database");
    Some(pool)
}

async fn insert_app(pool: &PgPool, slug: &str) -> Uuid {
    sqlx::query_scalar(
        "insert into application (slug, name, upstream_url, external_hostname)
         values ($1, $1, 'http://sample-app:80', $1 || '.apps.example.local')
         returning id",
    )
    .bind(slug)
    .fetch_one(pool)
    .await
    .expect("insert application")
}

async fn insert_audit(pool: &PgPool, app: Uuid, ts: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "insert into audit_event
           (application_id, application_slug, actor_sub, actor_name, decision,
            reason, count, first_seen, last_seen, distinct_path, first_path, src_ip, ts)
         values ($1, 'sample', '11111111-1111-1111-1111-111111111111', 'labuser',
            'deny', 'no_matching_grant', 3, now(), now(), 2, '/admin/', '10.0.0.7',
            $2::text::timestamptz)",
    )
    .bind(app)
    .bind(ts)
    .execute(pool)
    .await
    .map(|_| ())
}

// ponytail: one test, not five — they all reset the same database and cargo
// test runs tests in parallel. Split it when it stops being readable, giving
// each its own Postgres schema and a search_path on the pool.
#[tokio::test]
async fn migration_0001() {
    let Some(pool) = fresh_db().await else {
        eprintln!("SKIPPED migration_0001: DATABASE_URL is not set");
        return;
    };

    // Re-running the migrator on an already-migrated database is what every
    // restart does.
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("migrator is idempotent");

    // --- application ---
    let sample = insert_app(&pool, "sample").await;

    // The slug and the hostname are interpolated into generated nginx config
    // (ADR-0011); a value with whitespace or a semicolon in it is a config
    // injection, so the constraint is in the schema and not only in the API.
    for bad in ["Sample", "sample app", "a;b", "", "-lead", "trail-"] {
        let e = sqlx::query(
            "insert into application (slug, name, upstream_url, external_hostname)
             values ($1, 'x', 'http://x:80', 'x.apps.example.local')",
        )
        .bind(bad)
        .execute(&pool)
        .await;
        assert!(e.is_err(), "slug {bad:?} should be rejected");
    }
    for bad in ["ftp://x", "/x", "javascript:alert(1)"] {
        let e = sqlx::query(
            "insert into application (slug, name, upstream_url, external_hostname)
             values ('x', 'x', $1, 'x.apps.example.local')",
        )
        .bind(bad)
        .execute(&pool)
        .await;
        assert!(e.is_err(), "upstream_url {bad:?} should be rejected");
    }
    // Without this the loops above could be passing on the unique hostname
    // rather than on the constraint each one is aimed at.
    let rows: i64 = sqlx::query_scalar("select count(*) from application")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows, 1, "no rejected application was actually inserted");

    let dup = sqlx::query(
        "insert into application (slug, name, upstream_url, external_hostname)
         values ('other', 'x', 'http://x:80', 'sample.apps.example.local')",
    )
    .execute(&pool)
    .await;
    assert!(dup.is_err(), "two applications cannot share a hostname");

    // --- entitlement ---
    sqlx::query(
        "insert into entitlement (application_id, subject_type, subject_id, effect, path_pattern)
         values ($1, 'ad_group', 'OpenBerat-Sample', 'allow', '')",
    )
    .bind(sample)
    .execute(&pool)
    .await
    .expect("grant a group access to an application");

    let bad_type = sqlx::query(
        "insert into entitlement (application_id, subject_type, subject_id, effect)
         values ($1, 'group', 'OpenBerat-Sample', 'allow')",
    )
    .bind(sample)
    .execute(&pool)
    .await;
    assert!(bad_type.is_err(), "subject_type 'group' should be rejected");

    let bad_effect = sqlx::query(
        "insert into entitlement (application_id, subject_type, subject_id, effect)
         values ($1, 'ad_group', 'OpenBerat-Sample', 'maybe')",
    )
    .bind(sample)
    .execute(&pool)
    .await;
    assert!(bad_effect.is_err(), "effect 'maybe' should be rejected");

    let e = sqlx::query(
        "insert into entitlement (application_id, subject_type, subject_id, effect, path_pattern)
         values ($1, 'ad_group', 'OpenBerat-Sample', 'allow', 'admin/*')",
    )
    .bind(sample)
    .execute(&pool)
    .await;
    assert!(
        e.is_err(),
        "a path_pattern that is not rooted should be rejected"
    );

    // A wildcard entitlement has application_id NULL, and NULLs are distinct in
    // a plain unique index — so the admin UI's double-click would insert the
    // dangerous rule (docs/05 rule 4) twice.
    for i in 0..2 {
        let r = sqlx::query(
            "insert into entitlement (application_id, subject_type, subject_id, effect)
             values (null, 'ad_group', 'OpenBerat-Admins', 'allow')",
        )
        .execute(&pool)
        .await;
        assert_eq!(r.is_ok(), i == 0, "wildcard entitlement, attempt {i}");
    }

    // --- audit_event ---
    // No monthly partition exists yet — the retention job that creates them is
    // Phase 6 — so both of these land in the DEFAULT partition. Without one the
    // INSERT errors, and it happens off the request path where nobody sees it.
    insert_audit(&pool, sample, "2026-09-06T10:00:00Z")
        .await
        .expect("audit row for the current month");
    insert_audit(&pool, sample, "2999-01-01T00:00:00Z")
        .await
        .expect("a month far outside any partition still has somewhere to go");
    let part: Vec<String> =
        sqlx::query_scalar("select distinct tableoid::regclass::text from audit_event")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(
        part,
        ["audit_event_default"],
        "which partition took the rows"
    );

    let bad_count = sqlx::query(
        "insert into audit_event
           (application_slug, actor_sub, decision, reason, count, first_seen, last_seen, first_path)
         values ('sample', 'x', 'allow', 'allowed', 0, now(), now(), '/')",
    )
    .execute(&pool)
    .await;
    assert!(
        bad_count.is_err(),
        "a summary row folding zero requests is a bug"
    );
    // The control: the same row with count = 1 goes in, so the rejection above
    // was the count check and not a column this insert forgot.
    sqlx::query(
        "insert into audit_event
           (application_slug, actor_sub, decision, reason, count, first_seen, last_seen, first_path)
         values ('sample', 'x', 'allow', 'allowed', 1, now(), now(), '/')",
    )
    .execute(&pool)
    .await
    .expect("the same row with count = 1");

    // Deleting an application takes its entitlements with it and must leave the
    // audit trail standing — which is why audit_event has no foreign key to it,
    // and why the slug is denormalised into the row.
    sqlx::query("delete from application where id = $1")
        .bind(sample)
        .execute(&pool)
        .await
        .expect("delete application");
    let left: i64 =
        sqlx::query_scalar("select count(*) from entitlement where application_id = $1")
            .bind(sample)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(left, 0, "entitlements follow their application");
    let kept: i64 =
        sqlx::query_scalar("select count(*) from audit_event where application_id = $1")
            .bind(sample)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(kept, 2, "audit rows survive their application");

    // Postgres requires the partition key in the primary key of a partitioned
    // table; getting this wrong is only discovered when the table is created.
    let pk: Vec<String> = sqlx::query_scalar(
        "select a.attname from pg_constraint c
           join pg_attribute a on a.attrelid = c.conrelid and a.attnum = any(c.conkey)
          where c.conrelid = 'audit_event'::regclass and c.contype = 'p'
          order by a.attname",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(pk, ["id", "ts"], "audit_event primary key");

    store_section(&pool).await;

    // --- startup ---
    // The operator never runs the migration by hand, so these three are the
    // whole of what stands between an install and a process deciding /decide
    // against a schema it has not seen.
    for stmt in ["drop schema public cascade", "create schema public"] {
        sqlx::query(stmt)
            .execute(&pool)
            .await
            .expect("reset schema");
    }
    let url = std::env::var("DATABASE_URL").unwrap();
    openberat::store::connect(&url)
        .await
        .expect("startup migrates an empty database");

    // Nothing is listening yet, and a database that refuses the connection must
    // come back as an error rather than a hang or a panic.
    openberat::store::connect("postgres://openberat:test@127.0.0.1:1/openberat")
        .await
        .expect_err("an unreachable database is an error");

    // What an edited migration looks like on the second install. Left last: it
    // leaves the migration table poisoned.
    sqlx::query("update _sqlx_migrations set checksum = '\\x00' where version = 1")
        .execute(&pool)
        .await
        .expect("tamper with the applied migration");
    openberat::store::connect(&url)
        .await
        .expect_err("a checksum mismatch stops the process");
}

/// The entitlement query and the audit writer. Its own section rather than its
/// own test for the reason above: they share one database.
async fn store_section(pool: &sqlx::PgPool) {
    use openberat::policy::{Decision, Deny, Effect};
    use openberat::store::{self, AuditEvent};

    for stmt in ["drop schema public cascade", "create schema public"] {
        sqlx::query(stmt).execute(pool).await.expect("reset schema");
    }
    sqlx::migrate!("./migrations")
        .run(pool)
        .await
        .expect("migrate");

    let finance = insert_app(pool, "finance").await;
    let payroll = insert_app(pool, "payroll").await;
    let grant = |app: Option<uuid::Uuid>, subject_type, subject_id, effect, pattern| {
        sqlx::query(
            "insert into entitlement (application_id, subject_type, subject_id, effect, path_pattern)
             values ($1, $2, $3, $4, $5)",
        )
        .bind(app)
        .bind(subject_type)
        .bind(subject_id)
        .bind(effect)
        .bind(pattern)
        .execute(pool)
    };
    grant(Some(finance), "ad_group", "OpenBerat-Finance", "allow", "")
        .await
        .unwrap();
    grant(
        Some(finance),
        "ad_group",
        "OpenBerat-Finance",
        "deny",
        "/admin/*",
    )
    .await
    .unwrap();
    grant(Some(payroll), "ad_group", "OpenBerat-Finance", "allow", "")
        .await
        .unwrap();
    grant(Some(finance), "ad_group", "OpenBerat-Hr", "allow", "")
        .await
        .unwrap();
    grant(
        Some(finance),
        "user",
        "sub-of-one-person",
        "allow",
        "/reports/*",
    )
    .await
    .unwrap();
    grant(None, "ad_group", "OpenBerat-Admins", "allow", "")
        .await
        .unwrap();

    let groups = ["OpenBerat-Finance".to_string()];
    let found = store::rules_for(pool, "finance", "sub-of-someone-else", &groups)
        .await
        .expect("query")
        .expect("the application exists");
    assert!(found.enabled);
    assert_eq!(found.id, finance);
    // Two rules for this group on this application. Not the other application's,
    // not the other group's, and not the one keyed to a different person.
    assert_eq!(found.rules.len(), 2, "{:?}", found.rules);
    assert!(found.rules.iter().any(|r| r.effect == Effect::Deny));

    // A rule with no application_id applies to every application — docs/05
    // rule 4, and the reason the query cannot simply equality-match the id.
    let admin_groups = ["OpenBerat-Admins".to_string()];
    let found = store::rules_for(pool, "payroll", "x", &admin_groups)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.rules.len(), 1, "the wildcard entitlement");

    // Keyed to the person rather than to a group.
    let found = store::rules_for(pool, "finance", "sub-of-one-person", &[])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.rules.len(), 1);
    assert_eq!(found.rules[0].path_pattern, "/reports/*");

    // A user in no relevant group gets an empty rule set, not an error — the
    // deny is policy.rs's to make, and it is `no_matching_grant`.
    let found = store::rules_for(pool, "finance", "x", &[])
        .await
        .unwrap()
        .unwrap();
    assert!(found.rules.is_empty());

    // An expired rule still comes back: the cache holds this list for a TTL and
    // policy.rs re-checks expiry against the clock on every hit, so filtering
    // here would freeze the answer at the moment of the query.
    grant(Some(payroll), "ad_group", "OpenBerat-Hr", "allow", "")
        .await
        .unwrap();
    sqlx::query("update entitlement set expires_at = now() - interval '1 day' where subject_id = 'OpenBerat-Hr'")
        .execute(pool)
        .await
        .unwrap();
    let hr = ["OpenBerat-Hr".to_string()];
    let found = store::rules_for(pool, "payroll", "x", &hr)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        found.rules.len(),
        1,
        "an expired rule is policy.rs's to ignore"
    );
    assert!(found.rules[0].expires_at.is_some());

    // A slug nobody defined is None, which the caller turns into
    // `application_disabled` — the same answer as a disabled one (docs/02).
    assert!(
        store::rules_for(pool, "no-such-app", "x", &groups)
            .await
            .unwrap()
            .is_none()
    );
    sqlx::query("update application set enabled = false where slug = 'payroll'")
        .execute(pool)
        .await
        .unwrap();
    assert!(
        !store::rules_for(pool, "payroll", "x", &groups)
            .await
            .unwrap()
            .unwrap()
            .enabled
    );

    // --- audit ---
    let event = |slug: &str| AuditEvent {
        application_id: Some(finance),
        application_slug: slug.to_string(),
        actor_sub: "11111111-1111-1111-1111-111111111111".to_string(),
        actor_name: Some("labuser".to_string()),
        decision: Decision::Deny(Deny::NoMatchingGrant),
        count: 4,
        first_seen: chrono::Utc::now(),
        last_seen: chrono::Utc::now(),
        distinct_path: 2,
        first_path: "/admin/".to_string(),
        src_ip: Some("10.0.0.7".parse().unwrap()),
        request_id: Some("req-1".to_string()),
    };

    // A full channel drops the summary and counts the loss; it never waits.
    // Blocking here would put the audit write back on the decision path, which
    // is the one thing docs/02 says it must never be.
    let (audit, rx) = store::audit_channel(1);
    let before = store::audit_dropped();
    for _ in 0..5 {
        audit.record(event("finance"));
    }
    assert_eq!(
        store::audit_dropped() - before,
        4,
        "four of five did not fit"
    );
    drop(rx);

    // And what is handed to a channel with a writer on the other end reaches
    // the table, with the decision vocabulary the audit column is checked
    // against.
    let (audit, rx) = store::audit_channel(8);
    let writer = tokio::spawn(store::write_audit(pool.clone(), rx));
    audit.record(event("finance"));
    audit.record(AuditEvent {
        decision: Decision::Allow,
        count: 1,
        ..event("finance")
    });
    drop(audit);
    writer
        .await
        .expect("the writer drains and exits when the sender goes");
    let rows: Vec<(String, String, i32)> =
        sqlx::query_as("select decision, reason, count from audit_event order by count desc")
            .fetch_all(pool)
            .await
            .unwrap();
    assert_eq!(
        rows,
        [
            ("deny".to_string(), "no_matching_grant".to_string(), 4),
            ("allow".to_string(), "allowed".to_string(), 1),
        ]
    );
}
