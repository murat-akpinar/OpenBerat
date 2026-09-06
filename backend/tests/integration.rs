// The migration runs unattended on an operator's first install, so this is the
// only place its SQL is executed before it reaches one. Needs a live Postgres:
//   docker run --rm -d -p 55432:5432 -e POSTGRES_PASSWORD=test \
//     -e POSTGRES_USER=openberat -e POSTGRES_DB=openberat postgres:17-alpine
//   DATABASE_URL=postgres://openberat:test@localhost:55432/openberat cargo test
// Without DATABASE_URL the test skips loudly rather than failing.

use sqlx::PgPool;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
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

// ponytail: one test, not one per section — they all reset the same database
// and cargo test runs tests in parallel. Split it when it stops being readable,
// giving each its own Postgres schema and a search_path on the pool.
#[tokio::test]
async fn backend_against_postgres() {
    let Some(pool) = fresh_db().await else {
        eprintln!("SKIPPED backend_against_postgres: DATABASE_URL is not set");
        return;
    };
    schema_section(&pool).await;
    store_section(&pool).await;
    decide_section(&pool).await;
    // Last: it leaves the migration table poisoned.
    startup_section(&pool).await;
}

/// What `0001_init.sql` promises the rest of the code.
async fn schema_section(pool: &PgPool) {
    // Re-running the migrator on an already-migrated database is what every
    // restart does.
    let pool = pool.clone();
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

/// The operator never runs the migration by hand, so these three are the whole
/// of what stands between an install and a process deciding `/decide` against a
/// schema it has not seen.
async fn startup_section(pool: &PgPool) {
    let pool = pool.clone();
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

/// A stand-in for oauth2-proxy that answers `/oauth2/auth` from the cookie it is
/// given, so one server covers every branch the backend has to survive.
async fn fake_oauth2_proxy() -> (String, Arc<AtomicUsize>) {
    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::{IntoResponse, Response};

    async fn auth(State(calls): State<Arc<AtomicUsize>>, headers: HeaderMap) -> Response {
        calls.fetch_add(1, Ordering::SeqCst);
        let cookie = headers
            .get("cookie")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        if cookie.contains("broken") {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        if cookie.contains("slow") {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        }
        if !cookie.contains("valid") {
            return StatusCode::UNAUTHORIZED.into_response();
        }
        // The group list is the one header in this chain that grows without
        // bound: every group a user is in arrives comma-joined in this one
        // value. nginx needed a 32k buffer for it (docs/07); this is the same
        // question asked of the backend's own HTTP client.
        let many = cookie
            .split("groups=")
            .nth(1)
            .and_then(|n| n.split(';').next())
            .and_then(|n| n.trim().parse::<usize>().ok());
        let groups = match many {
            Some(n) => std::iter::once("OpenBerat-Finance".to_string())
                .chain((0..n).map(|i| format!("OpenBerat-Generated-{i:04}")))
                .collect::<Vec<_>>()
                .join(","),
            None if cookie.contains("admin") => "OpenBerat-Admins,OpenBerat-Finance".to_string(),
            None => "OpenBerat-Finance".to_string(),
        };
        let mut response = StatusCode::ACCEPTED.into_response();
        let h = response.headers_mut();
        h.insert("x-auth-request-user", "sub-labuser".parse().unwrap());
        h.insert(
            "x-auth-request-preferred-username",
            "labuser".parse().unwrap(),
        );
        h.insert(
            "x-auth-request-email",
            "labuser@example.local".parse().unwrap(),
        );
        h.insert("x-auth-request-groups", groups.parse().unwrap());
        // What cookie_refresh looks like on the wire: ADR-0006 collapses in
        // silence if this does not come back out of /decide unchanged.
        h.insert(
            "set-cookie",
            "_oauth2_proxy=refreshed|1|abc; Path=/; Domain=.apps.example.local; HttpOnly; Secure"
                .parse()
                .unwrap(),
        );
        response
    }

    let calls = Arc::new(AtomicUsize::new(0));
    let app = axum::Router::new()
        .route("/oauth2/auth", axum::routing::get(auth))
        .with_state(calls.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}"), calls)
}

/// A cookie header carrying a real oauth2-proxy ticket for `id`, plus a marker
/// the stand-in reads to decide how to answer. The ticket format is the
/// measured one (docs/07, VERIFY (4)).
fn session(id: &str, mode: &str) -> String {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    let ticket = format!(
        "v2.{}.{}",
        B64.encode(format!("_oauth2_proxy-{id}")),
        B64.encode("secret")
    );
    format!(
        "_oauth2_proxy={}|1788662043|sig; mode={mode}",
        B64.encode(ticket)
    )
}

/// `GET /decide` — the endpoint nginx asks on every single request.
async fn decide_section(pool: &PgPool) {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use openberat::api::{Ctx, router};
    use openberat::cache::Cache;
    use openberat::session::Index;
    use openberat::store::audit_channel;
    use tower::ServiceExt;

    for stmt in ["drop schema public cascade", "create schema public"] {
        sqlx::query(stmt).execute(pool).await.expect("reset schema");
    }
    sqlx::migrate!("./migrations")
        .run(pool)
        .await
        .expect("migrate");
    let finance = insert_app(pool, "finance").await;
    sqlx::query(
        "insert into entitlement (application_id, subject_type, subject_id, effect, path_pattern)
         values ($1, 'ad_group', 'OpenBerat-Finance', 'allow', ''),
                ($1, 'ad_group', 'OpenBerat-Finance', 'deny', '/admin/*')",
    )
    .bind(finance)
    .execute(pool)
    .await
    .unwrap();

    let Ok(redis_url) = std::env::var("REDIS_URL") else {
        eprintln!("SKIPPED decide_section: REDIS_URL is not set");
        return;
    };
    let index = Index::connect(&redis_url)
        .await
        .expect("connect to REDIS_URL");
    let (upstream, calls) = fake_oauth2_proxy().await;
    let ctx = |oauth2_proxy: &str, pool: PgPool| {
        let (audit, _queue) = audit_channel(1024);
        Arc::new(Ctx {
            pool,
            http: reqwest::Client::new(),
            oauth2_proxy: oauth2_proxy.to_string(),
            cache: Arc::new(Cache::new(audit.clone())),
            audit,
            index: index.clone(),
        })
    };
    let ask = async |ctx: Arc<Ctx>, headers: Vec<(&str, String)>| {
        let mut request = Request::builder().uri("/decide");
        for (name, value) in headers {
            request = request.header(name, value);
        }
        router(ctx)
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap()
    };
    // Everything nginx's include writes unconditionally, plus a live session.
    // The session cookie has to be a real oauth2-proxy ticket: the ADR-0019
    // index is derived from it before any ALLOW is returned.
    let full = |uri: &str, cookie: &str| {
        vec![
            ("x-app-slug", "finance".to_string()),
            ("x-original-uri", uri.to_string()),
            ("x-original-method", "GET".to_string()),
            ("x-real-ip", "10.0.0.7".to_string()),
            ("x-request-id", "req-1".to_string()),
            ("cookie", cookie.to_string()),
        ]
    };
    let reason = |r: &axum::response::Response| {
        r.headers()
            .get("x-deny-reason")
            .map(|v| v.to_str().unwrap().to_string())
    };

    // A header the include always writes is missing, so the include did not
    // run. That is a misconfiguration, and it fails closed rather than
    // deciding on half a request.
    for missing in [
        "x-app-slug",
        "x-original-uri",
        "x-original-method",
        "x-real-ip",
        "x-request-id",
    ] {
        let headers = full("/", &session("one", "valid"))
            .into_iter()
            .filter(|(name, _)| *name != missing)
            .collect();
        let response = ask(ctx(&upstream, pool.clone()), headers).await;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "without {missing}"
        );
        assert_eq!(reason(&response).as_deref(), Some("missing_context"));
    }

    // No session: 401 is nginx's cue to start the login flow. A 403 here would
    // show the "no access" page to someone who has simply not logged in yet.
    let response = ask(
        ctx(&upstream, pool.clone()),
        full("/", &session("one", "anonymous")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response.headers().get("x-auth-subject").is_none());

    // The happy path, and the two things nginx lifts off it.
    let response = ask(
        ctx(&upstream, pool.clone()),
        full("/reports/q1", &session("one", "valid")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let h = response.headers();
    assert_eq!(h.get("x-auth-subject").unwrap(), "sub-labuser");
    assert_eq!(h.get("x-auth-username").unwrap(), "labuser");
    assert_eq!(h.get("x-auth-email").unwrap(), "labuser@example.local");
    assert_eq!(h.get("x-auth-groups").unwrap(), "OpenBerat-Finance");
    assert_eq!(
        h.get("set-cookie").unwrap(),
        "_oauth2_proxy=refreshed|1|abc; Path=/; Domain=.apps.example.local; HttpOnly; Secure",
        "the refreshed cookie is relayed verbatim or ADR-0006 collapses in silence"
    );

    // The deny rule, reached through the normalisation policy.rs does.
    for uri in ["/admin/users", "/%61dmin/", "/x/../admin/"] {
        let response = ask(
            ctx(&upstream, pool.clone()),
            full(uri, &session("one", "valid")),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{uri}");
        assert_eq!(reason(&response).as_deref(), Some("explicit_deny"), "{uri}");
        // The identity comes back on a deny too. Nothing is proxied upstream
        // after one, so nothing is rewritten from it — the nginx access log is,
        // and a denied line that can say why but not who is half a diagnostic.
        assert_eq!(
            response.headers().get("x-auth-username").unwrap(),
            "labuser"
        );
        // The refresh happened at oauth2-proxy whatever the answer turned out
        // to be. Swallow it here and a denied user's groups freeze until their
        // cookie expires — which is the one thing ADR-0006 cannot survive.
        assert!(
            response.headers().get("set-cookie").is_some(),
            "{uri} relays the refresh"
        );
    }

    // An application nobody defined answers the same as a disabled one.
    let mut headers = full("/", &session("two", "valid"));
    headers[0] = ("x-app-slug", "no-such-app".to_string());
    let response = ask(ctx(&upstream, pool.clone()), headers).await;
    assert_eq!(reason(&response).as_deref(), Some("application_disabled"));

    // Identity comes from oauth2-proxy's answer and from nowhere else. nginx
    // clears these on the subrequest, but the backend must not be the only
    // thing standing between a forged header and an admin group either.
    let mut headers = full("/admin/", &session("three", "valid"));
    headers.push(("x-auth-request-groups", "OpenBerat-Admins".to_string()));
    headers.push(("x-auth-groups", "OpenBerat-Admins".to_string()));
    headers.push(("x-auth-request-user", "sub-someone-else".to_string()));
    let response = ask(ctx(&upstream, pool.clone()), headers).await;
    assert_eq!(
        reason(&response).as_deref(),
        Some("explicit_deny"),
        "forged identity headers"
    );

    // /decide never returns 5xx: nginx maps one to a 500 for the client, which
    // is an outage rather than a decision. Each dependency failing is a 403
    // naming which one, because at 3 a.m. that is the difference between
    // restarting Postgres and restarting oauth2-proxy.
    let response = ask(
        ctx(&upstream, pool.clone()),
        full("/", &session("four", "broken")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(reason(&response).as_deref(), Some("auth_unavailable"));

    let response = ask(
        ctx("http://127.0.0.1:1", pool.clone()),
        full("/", &session("five", "valid")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(reason(&response).as_deref(), Some("auth_unavailable"));

    let started = std::time::Instant::now();
    let response = ask(
        ctx(&upstream, pool.clone()),
        full("/", &session("six", "valid-slow")),
    )
    .await;
    assert_eq!(reason(&response).as_deref(), Some("auth_unavailable"));
    assert!(
        started.elapsed() < std::time::Duration::from_secs(3),
        "the 1 s budget held"
    );

    let dead = sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_millis(100))
        .connect_lazy("postgres://openberat:test@127.0.0.1:1/openberat")
        .unwrap();
    let response = ask(ctx(&upstream, dead), full("/", &session("seven", "valid"))).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(reason(&response).as_deref(), Some("store_unavailable"));

    // --- the cache, through the endpoint ---
    // This one keeps its receiver, so the audit half is observable too.
    let (audit, mut queue) = audit_channel(1024);
    let shared = Arc::new(Ctx {
        pool: pool.clone(),
        http: reqwest::Client::new(),
        oauth2_proxy: upstream.clone(),
        cache: Arc::new(Cache::new(audit.clone())),
        audit,
        index: index.clone(),
    });

    // Fifty assets of one page arriving together on a cold key. Without
    // single-flight this is fifty oauth2-proxy calls and fifty entitlement
    // queries for one decision.
    calls.store(0, Ordering::SeqCst);
    let burst: Vec<_> = (0..50)
        .map(|_| {
            let ctx = shared.clone();
            tokio::spawn(
                async move { ask(ctx, full("/reports/q1", &session("burst", "valid"))).await },
            )
        })
        .collect();
    for task in burst {
        assert_eq!(task.await.unwrap().status(), StatusCode::OK);
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "fifty requests, one refresh"
    );

    // And the hit costs nothing at all upstream.
    let response = ask(
        shared.clone(),
        full("/reports/q2", &session("burst", "valid")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "a hit does not call oauth2-proxy"
    );
    assert!(
        response.headers().get("set-cookie").is_none(),
        "there was no refresh to relay on a hit"
    );

    // What is cached is the rule list, not the verdict: the entry was filled by
    // an allowed request and the deny rule still bites on the next path. This
    // is the whole reason the matched pattern is not in the key (docs/05).
    let response = ask(
        shared.clone(),
        full("/admin/users", &session("burst", "valid")),
    )
    .await;
    assert_eq!(reason(&response).as_deref(), Some("explicit_deny"));
    assert_eq!(calls.load(Ordering::SeqCst), 1, "still a hit");

    // A different session is a different key.
    let response = ask(shared.clone(), full("/", &session("other", "valid"))).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    // An authenticated session whose oauth2-proxy key cannot be derived is one
    // the kill switch could never find. It is refused rather than allowed with
    // a hole in the revocation path (ADR-0019).
    let response = ask(shared.clone(), full("/", "some_other_cookie=valid")).await;
    assert_eq!(reason(&response).as_deref(), Some("store_unavailable"));

    // And so is a session Redis will not record. This is the narrow case
    // ADR-0019 names: reads still work, writes do not, and without this the
    // session keeps working while silently becoming unkillable.
    let redis = redis::Client::open(redis_url.as_str())
        .unwrap()
        .get_multiplexed_async_connection()
        .await
        .unwrap();
    let maxmemory = async |bytes: &str| {
        let mut redis = redis.clone();
        redis::cmd("CONFIG")
            .arg("SET")
            .arg("maxmemory")
            .arg(bytes)
            .exec_async(&mut redis)
            .await
            .unwrap();
    };
    maxmemory("1").await;
    let response = ask(shared.clone(), full("/", &session("unwritable", "valid"))).await;
    maxmemory("0").await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(reason(&response).as_deref(), Some("store_unavailable"));

    // What the kill switch will read in Phase 5.
    let sessions = index.sessions("sub-labuser").await.unwrap();
    assert!(
        sessions.contains(&"_oauth2_proxy-burst".to_string()),
        "the derived session key reached the index: {sessions:?}"
    );
    index.forget("sub-labuser").await.unwrap();
    while queue.try_recv().is_ok() {}

    // --- how many AD groups the backend's own HTTP client survives ---
    // nginx's half of this is measured (docs/07): the group list travels
    // comma-joined in one header, and a 4 KB buffer breaks between 100 and 200
    // groups, which auth_request turns into a 500 for the client — a lockout of
    // exactly the users with the most groups. The backend reads that same
    // header off oauth2-proxy's response with a different HTTP client, so the
    // limit is a different number and had never been asked for.
    //
    // Measured here: it holds to 15,000 groups (380 KB) and fails at 20,000
    // (510 KB), which is hyper's header buffer — 8 KB + 4 KB per allowed
    // header, about 408 KB — and not the 1 s budget: raising that to 20 s
    // changed nothing. That is an order of magnitude above the 32 KB nginx
    // buffer in front of it, so nginx is still what binds. The numbers below
    // stay well inside both.
    for count in [200usize, 800, 2000] {
        let cookie = format!(
            "{}; groups={count}",
            session(&format!("many{count}"), "valid")
        );
        let response = ask(shared.clone(), full("/reports/q1", &cookie)).await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "a user in {count} groups still gets a decision"
        );
        let echoed = response.headers().get("x-auth-groups").unwrap().len();
        assert!(
            echoed > count * 15,
            "{count} groups came back whole: {echoed} bytes"
        );
    }

    // --- the two endpoints that can tell an outage from a policy ---
    let probe = async |ctx: Arc<Ctx>, path: &str| {
        let request = Request::builder().uri(path).body(Body::empty()).unwrap();
        router(ctx).oneshot(request).await.unwrap()
    };
    assert_eq!(
        probe(shared.clone(), "/healthz").await.status(),
        StatusCode::OK
    );
    assert_eq!(
        probe(shared.clone(), "/readyz").await.status(),
        StatusCode::OK
    );

    // With Postgres unreachable, /decide answers 403 for everybody — which from
    // outside is a policy that denies everybody. This is the only place the
    // difference shows, so it has to name the dependency and not just fail.
    let dead = sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_millis(100))
        .connect_lazy("postgres://openberat:test@127.0.0.1:1/openberat")
        .unwrap();
    let blind = ctx(&upstream, dead);
    let response = probe(blind.clone(), "/readyz").await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&body).trim(),
        "unreachable: postgres"
    );
    // /healthz says nothing about dependencies, on purpose: it answers whether
    // this process is alive, and a restart loop is a different problem.
    assert_eq!(probe(blind, "/healthz").await.status(), StatusCode::OK);

    // And the counters the cache is holding reach the channel on shutdown.
    shared.cache.flush_all();
    let mut summaries = Vec::new();
    while let Ok(event) = queue.try_recv() {
        summaries.push(event);
    }
    let burst = summaries
        .iter()
        .find(|e| e.count == 51)
        .expect("the burst plus the two hits after it, folded into one row");
    // /admin/users is not here: counters are per outcome, so the denied path
    // is in the deny row rather than inflating the allow row's path count.
    assert_eq!(burst.distinct_path, 2, "/reports/q1 and /reports/q2");
    assert!(
        summaries.iter().any(|e| e.decision
            == openberat::policy::Decision::Deny(openberat::policy::Deny::ExplicitDeny)),
        "the deny is its own row"
    );
}
