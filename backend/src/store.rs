// Postgres access (sqlx). application / entitlement / audit_event queries.
// Schema: migrations/0001_init.sql, model: docs/02-architecture.md

use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use std::time::Duration;

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
