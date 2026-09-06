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

// One test, not five: they all reset the same database and cargo test runs
// tests in parallel.
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
}
