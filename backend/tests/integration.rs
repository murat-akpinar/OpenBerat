// Everything that needs a real Postgres and a real Redis: the migration an
// operator's first install runs unattended, the entitlement query, the audit
// writer, /decide, the cache and the management plane. CI provides both
// services; locally:
//   docker run --rm -d -p 55432:5432 -e POSTGRES_PASSWORD=test \
//     -e POSTGRES_USER=openberat -e POSTGRES_DB=openberat postgres:17-alpine
//   docker run --rm -d -p 56379:6379 redis:7-alpine
//   DATABASE_URL=postgres://openberat:test@localhost:55432/openberat \
//     REDIS_URL=redis://127.0.0.1:56379 cargo test
// Without them the test skips loudly rather than failing.

use sqlx::PgPool;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use uuid::Uuid;

/// The `sub` oauth2-proxy puts in `X-Auth-Request-User`: Keycloak's user id,
/// which is a UUID (`docs/07`, "Which claim lands in X-Auth-Request-User").
/// The kill switch takes it as one, so the fixture is one.
const LABUSER_SUB: &str = "cae7c116-24a0-42b8-ac6e-9961b34f5d6b";

/// The backend's own client (main.rs): /oauth2/sign_out answers 302 and that
/// 302 is the answer, not something to follow.
fn no_redirects() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

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
#[allow(clippy::type_complexity)]
async fn fake_oauth2_proxy(
    redis_url: &str,
) -> (String, Arc<AtomicUsize>, Arc<std::sync::Mutex<Vec<String>>>) {
    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::{IntoResponse, Response};

    #[derive(Clone)]
    struct Upstream {
        calls: Arc<AtomicUsize>,
        redis: redis::aio::MultiplexedConnection,
        signed_out: Arc<std::sync::Mutex<Vec<String>>>,
    }

    /// Logout's first step. It records the cookie and deletes nothing: the real
    /// one drops the session too, but then "the session is gone" would be an
    /// assertion about this stand-in rather than about the backend's own DEL.
    /// A 302 is what oauth2-proxy answers, and following it is not the client's
    /// job (main.rs).
    async fn sign_out(State(state): State<Upstream>, headers: HeaderMap) -> Response {
        state.signed_out.lock().unwrap().push(
            headers
                .get("cookie")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string(),
        );
        (StatusCode::FOUND, [("location", "/")]).into_response()
    }

    async fn auth(State(state): State<Upstream>, headers: HeaderMap) -> Response {
        let calls = state.calls.clone();
        calls.fetch_add(1, Ordering::SeqCst);
        let cookie = headers
            .get("cookie")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        // --- Feature Start ---
        // The one oauth2-proxy behaviour the kill switch rests on: a ticket
        // whose Redis key has been deleted cannot be loaded, so the answer is
        // 401. Modelled here rather than assumed, or "access is cut" would be
        // an assertion about the stand-in and not about the kill switch.
        // --- Feature End ---
        if cookie.contains("revocable")
            && let Some(value) = openberat::cache::session_cookie(Some(&cookie))
            && let Some(key) = openberat::session::session_key(value, openberat::cache::COOKIE_NAME)
        {
            let live: bool = redis::cmd("EXISTS")
                .arg(&key)
                .query_async(&mut state.redis.clone())
                .await
                .unwrap();
            if !live {
                return StatusCode::UNAUTHORIZED.into_response();
            }
        }
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
        h.insert("x-auth-request-user", LABUSER_SUB.parse().unwrap());
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
    let signed_out = Arc::new(std::sync::Mutex::new(Vec::new()));
    let redis = redis::Client::open(redis_url)
        .unwrap()
        .get_multiplexed_async_connection()
        .await
        .unwrap();
    let app = axum::Router::new()
        .route("/oauth2/auth", axum::routing::get(auth))
        .route("/oauth2/sign_out", axum::routing::get(sign_out))
        .with_state(Upstream {
            calls: calls.clone(),
            redis,
            signed_out: signed_out.clone(),
        });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}"), calls, signed_out)
}

/// Keycloak's Admin API, as much of it as the kill switch's first step touches:
/// the service-account token endpoint and `users/{id}/logout`. It records the
/// subs it was asked to log out, because "step 1 ran" is otherwise invisible
/// from outside — and a kill switch that skips it leaves a live SSO session
/// that signs the user straight back in.
async fn fake_keycloak() -> (String, Arc<std::sync::Mutex<Vec<String>>>) {
    use axum::extract::{Path, State};
    use axum::http::StatusCode;
    use axum::response::{IntoResponse, Response};

    type Killed = Arc<std::sync::Mutex<Vec<String>>>;

    async fn token() -> Response {
        axum::Json(serde_json::json!({ "access_token": "service-account-token" })).into_response()
    }
    async fn logout(State(killed): State<Killed>, Path(sub): Path<String>) -> Response {
        killed.lock().unwrap().push(sub.clone());
        // Two subs Keycloak refuses, so the test can watch the kill switch stop
        // at a failed first step instead of reporting a success it did not get
        // — and tell "nobody by that name" from "Keycloak is down", which are
        // different answers to the admin holding the button.
        if sub.ends_with("ffff") {
            return StatusCode::NOT_FOUND.into_response();
        }
        if sub.ends_with("eeee") {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        StatusCode::NO_CONTENT.into_response()
    }

    let killed: Killed = Arc::new(std::sync::Mutex::new(Vec::new()));
    let app = axum::Router::new()
        .route(
            "/realms/openberat/protocol/openid-connect/token",
            axum::routing::post(token),
        )
        .route(
            "/admin/realms/openberat/users/{sub}/logout",
            axum::routing::post(logout),
        )
        .with_state(killed.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}"), killed)
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
    let (upstream, calls, signed_out) = fake_oauth2_proxy(&redis_url).await;
    let (keycloak_url, killed) = fake_keycloak().await;
    let ctx = |oauth2_proxy: &str, pool: PgPool| {
        let (audit, _queue) = audit_channel(1024);
        Arc::new(Ctx {
            pool,
            http: no_redirects(),
            oauth2_proxy: oauth2_proxy.to_string(),
            cache: Arc::new(Cache::new(audit.clone())),
            audit,
            index: index.clone(),
            keycloak: openberat::keycloak::Keycloak::new(
                &reqwest::Client::new(),
                &keycloak_url,
                "openberat",
                "openberat-backend",
                "test-secret",
            ),
            admin_group: "OpenBerat-Admins".to_string(),
            portal_origin: "https://portal.apps.example.local".to_string(),
            nginx_conf_dir: None,
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
    assert_eq!(h.get("x-auth-subject").unwrap(), LABUSER_SUB);
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
        http: no_redirects(),
        oauth2_proxy: upstream.clone(),
        cache: Arc::new(Cache::new(audit.clone())),
        audit,
        index: index.clone(),
        keycloak: openberat::keycloak::Keycloak::new(
            &reqwest::Client::new(),
            &keycloak_url,
            "openberat",
            "openberat-backend",
            "test-secret",
        ),
        admin_group: "OpenBerat-Admins".to_string(),
        portal_origin: "https://portal.apps.example.local".to_string(),
        nginx_conf_dir: None,
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
    let sessions = index.sessions(LABUSER_SUB).await.unwrap();
    assert!(
        sessions.contains(&"_oauth2_proxy-burst".to_string()),
        "the derived session key reached the index: {sessions:?}"
    );
    index.forget(LABUSER_SUB).await.unwrap();
    while queue.try_recv().is_ok() {}

    // --- the management plane ---
    let call = async |method: &str, path: &str, headers: Vec<(&str, String)>| {
        let mut request = Request::builder().method(method).uri(path);
        for (name, value) in headers {
            request = request.header(name, value);
        }
        router(shared.clone())
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap()
    };
    // The cookie is not decoration: nginx proxies it to every /api location,
    // and the backend records the session it names so the kill switch can find
    // it (ADR-0019). A fixture without one would test a request nginx never
    // makes.
    let identity = |groups: &str| {
        vec![
            ("x-auth-subject", LABUSER_SUB.to_string()),
            ("x-auth-username", "labuser".to_string()),
            ("x-auth-email", "labuser@example.local".to_string()),
            ("x-auth-groups", groups.to_string()),
            ("cookie", session("portal", "valid")),
        ]
    };

    // /api/me reads the identity nginx rewrote and answers whether it grants
    // the management plane. The frontend hides things with this; it is not what
    // refuses anything.
    let response = call("GET", "/api/me", identity("OpenBerat-Finance")).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 65536)
        .await
        .unwrap();
    let me: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(me["username"], "labuser");
    assert_eq!(me["admin"], false);
    let response = call(
        "GET",
        "/api/me",
        identity("OpenBerat-Admins,OpenBerat-Finance"),
    )
    .await;
    let body = axum::body::to_bytes(response.into_body(), 65536)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap()["admin"],
        true
    );

    // No identity at all means nginx did not put one there, which means the
    // request did not come through nginx.
    assert_eq!(
        call("GET", "/api/me", vec![]).await.status(),
        StatusCode::UNAUTHORIZED
    );

    // A portal user is not an admin. This is the attack docs/05 names: the
    // portal is open to every authenticated user, so if reaching it were
    // enough, anyone could grant themselves entitlements.
    assert_eq!(
        call(
            "GET",
            "/api/admin/applications",
            identity("OpenBerat-Finance")
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(
            "GET",
            "/api/admin/applications",
            identity("OpenBerat-Admins")
        )
        .await
        .status(),
        StatusCode::OK
    );
    // Nor is a group that merely looks like the admin one.
    for pretender in [
        "openberat-admins",
        "OpenBerat-Admins-Readonly",
        "Domain Admins",
    ] {
        assert_eq!(
            call("GET", "/api/admin/applications", identity(pretender))
                .await
                .status(),
            StatusCode::FORBIDDEN,
            "{pretender}"
        );
    }

    // Origin on anything state-changing. SameSite cannot do this job: the
    // portal and the applications are same-site by design (ADR-0015), so a
    // compromised application's page is a same-site caller.
    let mut admin = identity("OpenBerat-Admins");
    admin.push(("origin", "https://sample.apps.example.local".to_string()));
    assert_eq!(
        call("DELETE", "/api/admin/applications", admin)
            .await
            .status(),
        StatusCode::FORBIDDEN,
        "an admin acting from another host on the same domain"
    );
    let mut admin = identity("OpenBerat-Admins");
    admin.push(("origin", "https://portal.apps.example.local".to_string()));
    assert_ne!(
        call("DELETE", "/api/admin/applications", admin)
            .await
            .status(),
        StatusCode::FORBIDDEN,
        "the portal's own origin passes the guard"
    );
    // And a missing Origin is not a pass.
    assert_eq!(
        call(
            "DELETE",
            "/api/admin/applications",
            identity("OpenBerat-Admins")
        )
        .await
        .status(),
        StatusCode::FORBIDDEN,
        "no Origin at all"
    );

    // Application CRUD, through the guard.
    let post = async |path: &str, body: serde_json::Value| {
        let mut request = Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .header("origin", "https://portal.apps.example.local");
        for (name, value) in identity("OpenBerat-Admins") {
            request = request.header(name, value);
        }
        router(shared.clone())
            .oneshot(request.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap()
    };
    let response = post(
        "/api/admin/applications",
        serde_json::json!({
            "slug": "wiki", "name": "Wiki",
            "upstream_url": "http://wiki-app:8080",
            "external_hostname": "wiki.apps.example.local"
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = axum::body::to_bytes(response.into_body(), 65536)
        .await
        .unwrap();
    let created: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(created["application"]["enabled"], true);
    // Nothing to publish to in the tests, so this says so rather than lying.
    assert_eq!(created["nginx"], "staged");
    let wiki = created["application"]["id"].as_str().unwrap().to_string();

    // A duplicate is a conflict, not a 500 — the admin gets told which field.
    let response = post(
        "/api/admin/applications",
        serde_json::json!({
            "slug": "wiki", "name": "Wiki again",
            "upstream_url": "http://other:8080",
            "external_hostname": "other.apps.example.local"
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);

    // The validation from admin.rs, reaching the caller as a 400 with a reason
    // rather than a database error.
    for (field, value) in [
        ("upstream_url", "http://postgres:5432"),
        ("upstream_url", "http://169.254.169.254/"),
        ("external_hostname", "portal.apps.example.local"),
    ] {
        let mut body = serde_json::json!({
            "slug": "probe", "name": "Probe",
            "upstream_url": "http://probe-app:8080",
            "external_hostname": "probe.apps.example.local"
        });
        body[field] = serde_json::Value::String(value.to_string());
        let response = post("/api/admin/applications", body).await;
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "{field} = {value}"
        );
        let body = axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap();
        let refused: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            refused["error"].is_string(),
            "{field} = {value}: no reason given"
        );
    }

    // A slug the schema would refuse is refused before it gets there, and the
    // caller is told rather than seeing a 500.
    let send = async |method: &str, path: String, body: serde_json::Value| {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json")
            .header("origin", "https://portal.apps.example.local");
        for (name, value) in identity("OpenBerat-Admins") {
            request = request.header(name, value);
        }
        router(shared.clone())
            .oneshot(request.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap()
    };
    let response = send(
        "PATCH",
        format!("/api/admin/applications/{wiki}"),
        serde_json::json!({"enabled": false}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 65536)
        .await
        .unwrap();
    let patched: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(patched["application"]["enabled"], false);
    assert_eq!(
        patched["application"]["name"], "Wiki",
        "an absent field is left alone"
    );

    let response = send(
        "PATCH",
        format!("/api/admin/applications/{wiki}"),
        serde_json::json!({"upstream_url": "http://redis:6379"}),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "patching in an infrastructure host"
    );

    let response = send(
        "DELETE",
        format!("/api/admin/applications/{wiki}"),
        serde_json::json!({}),
    )
    .await;
    // 200 and not 204: the body carries whether the generated nginx
    // configuration was staged, which is the difference between "saved" and
    // "actually unreachable now".
    assert_eq!(response.status(), StatusCode::OK);
    let response = send(
        "DELETE",
        format!("/api/admin/applications/{wiki}"),
        serde_json::json!({}),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "deleting it twice"
    );

    // Entitlements, and the portal list they drive.
    let response = post(
        "/api/admin/applications",
        serde_json::json!({
            "slug": "reports", "name": "Reports",
            "upstream_url": "http://reports-app:8080",
            "external_hostname": "reports.apps.example.local"
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = axum::body::to_bytes(response.into_body(), 65536)
        .await
        .unwrap();
    let reports: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let reports_id = reports["application"]["id"].as_str().unwrap().to_string();

    for bad in [
        serde_json::json!({"application_id": reports_id, "subject_type": "group",
                           "subject_id": "OpenBerat-Finance", "effect": "allow"}),
        serde_json::json!({"application_id": reports_id, "subject_type": "ad_group",
                           "subject_id": "OpenBerat-Finance", "effect": "maybe"}),
        serde_json::json!({"application_id": reports_id, "subject_type": "ad_group",
                           "subject_id": "", "effect": "allow"}),
        serde_json::json!({"application_id": reports_id, "subject_type": "ad_group",
                           "subject_id": "OpenBerat-Finance", "effect": "allow",
                           "path_pattern": "admin/*"}),
    ] {
        let response = post("/api/admin/entitlements", bad.clone()).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{bad}");
    }

    // The portal shows nothing until a rule says so — default deny reaches all
    // the way to the buttons.
    // Only the application this section created — `finance` from the /decide
    // section is legitimately in the list and is not what is being measured.
    let listed = async |groups: &str| {
        let response = call("GET", "/api/apps", identity(groups)).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap();
        serde_json::from_slice::<Vec<serde_json::Value>>(&body)
            .unwrap()
            .into_iter()
            .filter(|app| app["slug"] == "reports")
            .collect::<Vec<_>>()
    };
    assert!(
        listed("OpenBerat-Finance").await.is_empty(),
        "nothing granted yet"
    );

    let response = post(
        "/api/admin/entitlements",
        serde_json::json!({"application_id": reports_id, "subject_type": "ad_group",
                           "subject_id": "OpenBerat-Finance", "effect": "allow"}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let shown = listed("OpenBerat-Finance").await;
    assert_eq!(shown.len(), 1);
    assert_eq!(shown[0]["slug"], "reports");
    assert_eq!(shown[0]["url"], "https://reports.apps.example.local/");
    assert!(
        listed("OpenBerat-Hr").await.is_empty(),
        "another group sees nothing"
    );

    // A deny at the root takes the button away, because the portal asks
    // policy.rs the same question the PEP asks and gets the same answer.
    let response = post(
        "/api/admin/entitlements",
        serde_json::json!({"application_id": reports_id, "subject_type": "ad_group",
                           "subject_id": "OpenBerat-Finance", "effect": "deny"}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    assert!(
        listed("OpenBerat-Finance").await.is_empty(),
        "deny beats allow here too"
    );

    // A disabled application is not a button either.
    sqlx::query("delete from entitlement where effect = 'deny'")
        .execute(pool)
        .await
        .unwrap();
    assert_eq!(listed("OpenBerat-Finance").await.len(), 1);
    let response = send(
        "PATCH",
        format!("/api/admin/applications/{reports_id}"),
        serde_json::json!({"enabled": false}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        listed("OpenBerat-Finance").await.is_empty(),
        "a disabled application"
    );

    // --- the whole management plane, not one route of it ---
    // A portal user reaching /api/admin/* is the attack docs/02 names: the
    // portal is open to every authenticated user, so if reaching it were enough
    // then anyone could grant themselves entitlements. One route was checked
    // above; the guard is a `route_layer`, so it protects a handler only if the
    // handler was registered on `admin::routes()`. A route added to the main
    // router in api.rs instead — the kill switch is the next one (Phase 5) —
    // would be reachable and nothing would fail. Enumerated, with a valid
    // Origin and a body that would really work, so the group check is the only
    // thing left that can refuse and a hole shows up as a written row.
    // Not any entitlement: `application_id` cascades on delete, and the admin
    // pass below deletes `reports` two steps before it deletes this row.
    let ent_id: Uuid = sqlx::query_scalar("select id from entitlement where application_id = $1")
        .bind(finance)
        .fetch_one(pool)
        .await
        .unwrap();
    let rows = async || -> (i64, i64, bool) {
        (
            sqlx::query_scalar("select count(*) from application")
                .fetch_one(pool)
                .await
                .unwrap(),
            sqlx::query_scalar("select count(*) from entitlement")
                .fetch_one(pool)
                .await
                .unwrap(),
            sqlx::query_scalar("select enabled from application where slug = 'reports'")
                .fetch_one(pool)
                .await
                .unwrap(),
        )
    };
    let before = rows().await;
    let sneak = async |method: &str, path: String, body: serde_json::Value| {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json")
            .header("origin", "https://portal.apps.example.local");
        for (name, value) in identity("OpenBerat-Finance") {
            request = request.header(name, value);
        }
        router(shared.clone())
            .oneshot(request.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap()
    };
    // The wildcard entitlement is the one that matters here: no application_id,
    // so it grants every application present and future (docs/05 rule 4).
    let plane = [
        (
            "GET",
            "/api/admin/applications".to_string(),
            serde_json::json!(null),
        ),
        (
            "POST",
            "/api/admin/applications".to_string(),
            serde_json::json!({
                "slug": "sneak", "name": "Sneak",
                "upstream_url": "http://sneak-app:8080",
                "external_hostname": "sneak.apps.example.local"
            }),
        ),
        (
            "PATCH",
            format!("/api/admin/applications/{reports_id}"),
            serde_json::json!({"enabled": true}),
        ),
        (
            "DELETE",
            format!("/api/admin/applications/{reports_id}"),
            serde_json::json!(null),
        ),
        (
            "GET",
            "/api/admin/entitlements".to_string(),
            serde_json::json!(null),
        ),
        (
            "POST",
            "/api/admin/entitlements".to_string(),
            serde_json::json!({"subject_type": "ad_group",
                               "subject_id": "OpenBerat-Finance", "effect": "allow"}),
        ),
        (
            "DELETE",
            format!("/api/admin/entitlements/{ent_id}"),
            serde_json::json!(null),
        ),
        (
            "GET",
            "/api/admin/audit".to_string(),
            serde_json::json!(null),
        ),
        (
            "POST",
            format!("/api/admin/kill/{LABUSER_SUB}"),
            serde_json::json!(null),
        ),
    ];
    for (method, path, body) in &plane {
        let response = sneak(method, path.clone(), body.clone()).await;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "a portal user reached {method} {path}"
        );
    }
    assert_eq!(
        rows().await,
        before,
        "a refused portal user still changed something"
    );
    // The same eight with the admin group, and this is what stops the loop
    // above from being vacuous: a mistyped path answers 404 and a wrong method
    // 405, neither of which is the 403 asserted — but a route that quietly
    // stopped existing would still need something to say so. Run last in this
    // section, because these ones land.
    for (method, path, body) in &plane {
        let mut request = Request::builder()
            .method(*method)
            .uri(path)
            .header("content-type", "application/json")
            .header("origin", "https://portal.apps.example.local");
        for (name, value) in identity("OpenBerat-Admins") {
            request = request.header(name, value);
        }
        let response = router(shared.clone())
            .oneshot(request.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap();
        assert_ne!(
            response.status(),
            StatusCode::FORBIDDEN,
            "an admin was refused {method} {path}"
        );
        assert!(
            response.status().is_success(),
            "{method} {path} answered {}",
            response.status()
        );
    }

    // Refused for the same reason with no Origin and with a foreign one: the
    // group check runs first, so a missing Origin cannot be what a reviewer
    // mistakes for the thing keeping a non-admin out.
    for origin in ["", "https://sample.apps.example.local"] {
        let mut headers = identity("OpenBerat-Finance");
        if !origin.is_empty() {
            headers.push(("origin", origin.to_string()));
        }
        assert_eq!(
            call("DELETE", "/api/admin/applications", headers)
                .await
                .status(),
            StatusCode::FORBIDDEN,
            "origin {origin:?}"
        );
    }

    // --- reading the audit record back ---
    // The table is append-only and the admin's question is "did I see
    // everything", so the two things tested hardest here are the ones that
    // answer it wrongly in silence: a filter that does not narrow, and a second
    // page that repeats or skips a row.
    let audit_row =
        async |slug: &str, sub: &str, name: &str, decision: &str, reason: &str, ts: &str| {
            sqlx::query(
                "insert into audit_event
                   (application_slug, actor_sub, actor_name, decision, reason, count,
                    first_seen, last_seen, distinct_path, first_path, src_ip, request_id, ts)
                 values ($1, $2, $3, $4, $5, 1, now(), now(), 1, '/', '10.0.0.7', 'req-1',
                         $6::text::timestamptz)",
            )
            .bind(slug)
            .bind(sub)
            .bind(name)
            .bind(decision)
            .bind(reason)
            .bind(ts)
            .execute(pool)
            .await
            .expect("audit row");
        };
    audit_row(
        "wiki",
        "sub-a",
        "alice",
        "allow",
        "allowed",
        "2026-09-01T10:00:00Z",
    )
    .await;
    audit_row(
        "wiki",
        "sub-b",
        "bob",
        "deny",
        "no_matching_grant",
        "2026-09-02T10:00:00Z",
    )
    .await;
    audit_row(
        "reports",
        "sub-a",
        "alice",
        "deny",
        "explicit_deny",
        "2026-09-03T10:00:00Z",
    )
    .await;
    audit_row(
        "reports",
        "sub-a",
        "alice",
        "allow",
        "allowed",
        "2026-09-04T10:00:00Z",
    )
    .await;

    let audit = async |query: &str| -> (StatusCode, serde_json::Value) {
        let response = call(
            "GET",
            &format!("/api/admin/audit{query}"),
            identity("OpenBerat-Admins"),
        )
        .await;
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let parsed = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
        (status, parsed)
    };
    let slugs = |rows: &serde_json::Value| -> Vec<String> {
        rows.as_array()
            .expect("an array of rows")
            .iter()
            .map(|r| r["application_slug"].as_str().unwrap().to_string())
            .collect()
    };

    let (status, rows) = audit("").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        slugs(&rows),
        ["reports", "reports", "wiki", "wiki"],
        "newest first"
    );
    // inet is the one column whose decode can only fail at runtime, and it
    // fails as a 503 that reads like an outage rather than as a type error.
    assert_eq!(rows[0]["src_ip"], "10.0.0.7");
    assert_eq!(rows[0]["reason"], "allowed");
    assert_eq!(rows[0]["count"], 1);

    for (query, expected) in [
        ("?app=wiki", 2),
        ("?decision=deny", 2),
        ("?reason=explicit_deny", 1),
        // Whichever of the two the admin has: the sub is what the kill switch
        // takes, the name is what a person reads off a ticket.
        ("?actor=alice", 3),
        ("?actor=sub-b", 1),
        ("?since=2026-09-03T00:00:00Z", 2),
        ("?until=2026-09-03T00:00:00Z", 2),
        ("?since=2026-09-02T00:00:00Z&until=2026-09-04T00:00:00Z", 2),
        ("?app=wiki&decision=allow", 1),
        ("?app=nonexistent", 0),
    ] {
        let (status, rows) = audit(query).await;
        assert_eq!(status, StatusCode::OK, "{query}");
        assert_eq!(rows.as_array().unwrap().len(), expected, "{query}");
    }

    // Keyset and not OFFSET: rows arrive at the head of this ordering while an
    // admin is paging through it, and OFFSET answers that by showing page one's
    // rows again on page two — or, when a row ages out, by skipping one. Either
    // is a lie told by the one table that exists not to tell them.
    let (_, page1) = audit("?limit=2").await;
    assert_eq!(slugs(&page1), ["reports", "reports"]);
    let cursor = format!(
        "?limit=2&before_ts={}&before_id={}",
        page1[1]["ts"].as_str().unwrap(),
        page1[1]["id"].as_str().unwrap()
    );
    let (_, page2) = audit(&cursor).await;
    assert_eq!(slugs(&page2), ["wiki", "wiki"], "no repeat and no skip");

    // A filter the backend cannot honour is refused, never ignored. Ignoring it
    // returns MORE rows than were asked for, under a heading that says
    // otherwise — the admin reads "these are the denials" off a list with
    // allows in it.
    for bad in [
        "?decision=nope",
        "?desicion=deny",
        "?since=yesterday",
        "?limit=abc",
        // The cursor is a pair; half of one silently matches nothing at all.
        "?before_ts=2026-09-03T00:00:00Z",
        "?before_id=00000000-0000-0000-0000-000000000000",
    ] {
        let (status, _) = audit(bad).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
    }

    // --- the delimiter the group list is joined with ---
    // Groups arrive comma-joined in one header (docs/07) and are split back
    // apart here, so one AD group *named* `Payroll,OpenBerat-Admins` splits
    // into two, and the second one is the management plane. This is pinned,
    // not fixed: the array was flattened upstream by oauth2-proxy and the fact
    // that it was ever one name is gone before the request arrives, so no
    // amount of care on this side can tell the two apart. The control is
    // ADR-0008 mitigation 1 — the Keycloak mapper filter, which matches the
    // whole `cn` against `OpenBerat-*` and never lets such a name into the
    // claim. The day this assertion fails, the split changed.
    assert_eq!(
        call(
            "GET",
            "/api/admin/applications",
            identity("Payroll,OpenBerat-Admins")
        )
        .await
        .status(),
        StatusCode::OK,
        "a comma in an AD group name is the whole management plane (docs/07)"
    );
    // The other half of the same delimiter, and this one the backend can
    // refuse: an `ad_group` grant whose name contains a comma can never match
    // anything, because the list it is matched against was split on commas. A
    // rule that silently never fires is worse than a refusal — the admin
    // believes the access was granted.
    let response = post(
        "/api/admin/entitlements",
        serde_json::json!({"application_id": reports_id, "subject_type": "ad_group",
                           "subject_id": "Payroll,OpenBerat-Finance", "effect": "allow"}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

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

    // --- the kill switch (ADR-0019) ---
    // Last, because it empties the cache and the index the sections above fill.
    let redis = redis::Client::open(redis_url.as_str())
        .unwrap()
        .get_multiplexed_async_connection()
        .await
        .unwrap();
    let exists = async |key: &str| -> bool {
        redis::cmd("EXISTS")
            .arg(key)
            .query_async(&mut redis.clone())
            .await
            .unwrap()
    };
    let seed = async |key: &str| {
        redis::cmd("SET")
            .arg(key)
            .arg("a live oauth2-proxy session")
            .exec_async(&mut redis.clone())
            .await
            .unwrap();
    };
    // An admin killing somebody else, which is the case that matters: with the
    // caller's own identity the count below would include the session this very
    // request records on its way in.
    let kill = async |sub: &str| {
        let request = Request::builder()
            .method("POST")
            .uri(format!("/api/admin/kill/{sub}"))
            .header("origin", "https://portal.apps.example.local")
            .header("x-auth-subject", "11111111-1111-1111-1111-111111111111")
            .header("x-auth-username", "labadmin")
            .header("x-auth-groups", "OpenBerat-Admins")
            .header("cookie", session("labadmin", "valid"));
        router(shared.clone())
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap()
    };

    // A session the index never saw is one the kill switch reports zero for and
    // does not cut. The portal does not go through /decide, so a freshly
    // signed-in user who has not opened an application yet is recorded here
    // instead — measured on the lab, where before this a portal-only session
    // survived its own kill (`docs/07`).
    index.forget(LABUSER_SUB).await.unwrap();
    assert_eq!(
        call("GET", "/api/me", identity("OpenBerat-Finance"))
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        index.sessions(LABUSER_SUB).await.unwrap(),
        vec!["_oauth2_proxy-portal"],
        "the portal call recorded the session"
    );
    // And one whose session key cannot be derived is refused rather than served
    // unkillably — the same answer /decide gives.
    let no_cookie: Vec<(&str, String)> = identity("OpenBerat-Finance")
        .into_iter()
        .filter(|(name, _)| *name != "cookie")
        .collect();
    assert_eq!(
        call("GET", "/api/me", no_cookie).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );

    // From a known state: the sections above left this user several index
    // entries whose sessions never existed in Redis.
    index.forget(LABUSER_SUB).await.unwrap();
    killed.lock().unwrap().clear();
    let doomed = "_oauth2_proxy-doomed";
    seed(doomed).await;
    calls.store(0, Ordering::SeqCst);
    let cookie = session("doomed", "valid-revocable");
    assert_eq!(
        ask(shared.clone(), full("/reports/q1", &cookie))
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        ask(shared.clone(), full("/reports/q2", &cookie))
            .await
            .status(),
        StatusCode::OK,
        "and the second is a hit"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "one authentication, two requests"
    );
    assert_eq!(index.sessions(LABUSER_SUB).await.unwrap(), vec![doomed]);
    while queue.try_recv().is_ok() {}

    let response = kill(LABUSER_SUB).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap()["sessions"],
        1
    );

    // Each of the four steps, in the order ADR-0019 fixes: without step 1 the
    // browser is sent back to a Keycloak that still holds a live SSO session,
    // and without step 2 the cache refills from a session that is still there.
    assert_eq!(killed.lock().unwrap().as_slice(), [LABUSER_SUB]);
    assert!(!exists(doomed).await, "the oauth2-proxy session is gone");
    assert!(
        index.sessions(LABUSER_SUB).await.unwrap().is_empty(),
        "and so is the index entry"
    );

    // Access is cut, and the cache does not refill: the request is a miss (it
    // reached oauth2-proxy again) and oauth2-proxy cannot load a session whose
    // key the kill switch deleted.
    assert_eq!(
        ask(shared.clone(), full("/reports/q1", &cookie))
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "the entry really left the cache"
    );

    // The counters of the entries it dropped land in the audit channel. A kill
    // switch that took the record of the user it killed with it would erase
    // exactly the evidence the incident is about (docs/05).
    let mut dropped = Vec::new();
    while let Ok(event) = queue.try_recv() {
        dropped.push(event);
    }
    let allow = dropped
        .iter()
        .find(|e| e.decision == openberat::policy::Decision::Allow)
        .expect("the killed entry wrote its summary");
    assert_eq!((allow.count, allow.distinct_path), (2, 2));

    // A first step that fails stops the other three rather than reporting a
    // success it did not get — and leaves the index entry behind, so the same
    // call can be made again once Keycloak answers.
    let survivor = "_oauth2_proxy-survivor";
    seed(survivor).await;
    // A sub nobody has and a Keycloak that is down are different answers: the
    // first cannot be retried into working, and an operator mid-incident reads
    // 503 as "the system is broken" and goes looking at a Keycloak that is fine.
    for (sub, expected) in [
        (
            "00000000-0000-0000-0000-00000000ffff",
            StatusCode::NOT_FOUND,
        ),
        (
            "00000000-0000-0000-0000-00000000eeee",
            StatusCode::SERVICE_UNAVAILABLE,
        ),
    ] {
        index.record(sub, survivor).await.unwrap();
        assert_eq!(kill(sub).await.status(), expected, "sub {sub}");
        assert!(exists(survivor).await, "step 2 did not run for {sub}");
        assert_eq!(
            index.sessions(sub).await.unwrap(),
            vec![survivor],
            "and neither did step 4, so the kill can be retried"
        );
        index.forget(sub).await.unwrap();
    }
    redis::cmd("DEL")
        .arg(survivor)
        .exec_async(&mut redis.clone())
        .await
        .unwrap();

    // The sub is interpolated into a Keycloak admin URL. Anything that is not a
    // user id is refused before it gets there, and a traversal attempt is not
    // "no such user" — it never reaches Keycloak at all.
    let before = killed.lock().unwrap().len();
    for sub in [
        "..",
        "%2e%2e",
        "not-a-uuid",
        "cae7c116-24a0-42b8-ac6e-9961b34f5d6",
    ] {
        assert_eq!(
            kill(sub).await.status(),
            StatusCode::BAD_REQUEST,
            "sub {sub:?}"
        );
    }
    assert_eq!(
        killed.lock().unwrap().len(),
        before,
        "none of them reached Keycloak"
    );

    // --- logout (docs/02, "Logout") ---
    // The caller's own kill switch, and the one step of the three only the
    // backend can take. `/oauth2/sign_out` clears the cookie and drops the
    // oauth2-proxy session; it cannot reach the decision cache, so a cookie
    // captured before the sign-out still answers from a cache entry for up to
    // one TTL. That is what this endpoint closes.
    let mine = "_oauth2_proxy-mine";
    seed(mine).await;
    let cookie = session("mine", "valid-revocable");
    let signed_in = |origin: &str| {
        let mut headers = vec![
            ("x-auth-subject", LABUSER_SUB.to_string()),
            ("x-auth-username", "labuser".to_string()),
            ("x-auth-groups", "OpenBerat-Finance".to_string()),
            ("cookie", cookie.clone()),
        ];
        if !origin.is_empty() {
            headers.push(("origin", origin.to_string()));
        }
        headers
    };
    assert_eq!(
        ask(shared.clone(), full("/reports/q1", &cookie))
            .await
            .status(),
        StatusCode::OK
    );
    calls.store(0, Ordering::SeqCst);
    assert_eq!(
        ask(shared.clone(), full("/reports/q2", &cookie))
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0, "the entry is cached");
    // The same user signed in somewhere else. Logging out of one browser must
    // not take the other one's index entry with it: a session in no index is
    // one the kill switch cannot find (ADR-0019).
    let elsewhere = "_oauth2_proxy-elsewhere";
    index.record(LABUSER_SUB, elsewhere).await.unwrap();

    // Origin, for the same reason the admin endpoints check it: the portal and
    // the applications are same-site (ADR-0015), and a compromised application
    // logging everybody out at will is a denial of service.
    signed_out.lock().unwrap().clear();
    for origin in ["", "https://sample.apps.example.local"] {
        assert_eq!(
            call("POST", "/api/logout", signed_in(origin))
                .await
                .status(),
            StatusCode::FORBIDDEN,
            "origin {origin:?}"
        );
    }
    assert!(exists(mine).await, "a refused logout cut nothing");
    assert!(
        signed_out.lock().unwrap().is_empty(),
        "and did not reach oauth2-proxy either"
    );
    // And an unauthenticated caller has no session to end.
    assert_eq!(
        call(
            "POST",
            "/api/logout",
            vec![("origin", "https://portal.apps.example.local".to_string())]
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );

    let response = call(
        "POST",
        "/api/logout",
        signed_in("https://portal.apps.example.local"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    // Step 1, and it has to be first: oauth2-proxy performs the RP-initiated
    // logout out of the id_token inside the session it is being asked to
    // destroy, so a backend that deleted the session key before asking leaves
    // it nothing to log out with — and the IdP session survives the logout
    // (measured, docs/07).
    assert_eq!(
        signed_out.lock().unwrap().as_slice(),
        std::slice::from_ref(&cookie),
        "the sign-out was called, with the caller's own cookie"
    );
    assert!(!exists(mine).await, "the oauth2-proxy session is gone");
    assert_eq!(
        index.sessions(LABUSER_SUB).await.unwrap(),
        vec![elsewhere],
        "only this browser left the index"
    );
    // The cache entry is gone with it, which is the whole point: the replayed
    // cookie is a miss now, and oauth2-proxy cannot load a session whose key
    // has been deleted.
    calls.store(0, Ordering::SeqCst);
    assert_eq!(
        ask(shared.clone(), full("/reports/q1", &cookie))
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1, "it really was a miss");
    index.forget(LABUSER_SUB).await.unwrap();
}
