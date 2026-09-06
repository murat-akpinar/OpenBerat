// Entry point. Reads configuration from the environment, applies the schema and
// serves /decide on the core network — see TODO.md.

use openberat::api::{self, Ctx};
use openberat::cache::Cache;
use openberat::store;
use std::sync::Arc;
use std::time::Duration;

const LISTEN: &str = "0.0.0.0:8081";
/// Summaries waiting to be written. Deep enough that a slow insert does not
/// start dropping rows, shallow enough that the backlog is bounded memory.
const AUDIT_QUEUE: usize = 1024;
/// Entries do not expire by being looked at, so something has to walk them.
const SWEEP_INTERVAL: Duration = Duration::from_secs(5);
/// How long shutdown waits for the audit queue to reach Postgres.
const SHUTDOWN_DRAIN: Duration = Duration::from_secs(5);

fn fatal(message: &str) -> ! {
    tracing::error!("{message}");
    std::process::exit(1)
}

fn required(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| fatal(&format!("{name} is not set")))
}

/// Both signals, because `docker stop` sends SIGTERM and a terminal sends
/// SIGINT — and the cache flush below only runs if one of them is caught.
async fn shutdown() {
    let ctrl_c = async { tokio::signal::ctrl_c().await.ok() };
    let mut term = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(term) => term,
        Err(e) => fatal(&format!("cannot listen for SIGTERM: {e}")),
    };
    tokio::select! {
        _ = ctrl_c => {}
        _ = term.recv() => {}
    }
    tracing::info!("shutting down");
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let pool = match store::connect(&required("DATABASE_URL")).await {
        Ok(pool) => pool,
        Err(e) => fatal(&format!(
            "cannot connect or apply migrations, refusing to start: {e}"
        )),
    };

    let (audit, queue) = store::audit_channel(AUDIT_QUEUE);
    let writer = tokio::spawn(store::write_audit(pool.clone(), queue));
    let cache = Arc::new(Cache::new(audit.clone()));
    let sweeper = tokio::spawn({
        let cache = cache.clone();
        async move {
            let mut tick = tokio::time::interval(SWEEP_INTERVAL);
            loop {
                tick.tick().await;
                cache.sweep();
            }
        }
    });

    let ctx = Arc::new(Ctx {
        pool,
        http: reqwest::Client::new(),
        oauth2_proxy: required("OAUTH2_PROXY_URL")
            .trim_end_matches('/')
            .to_string(),
        cache: cache.clone(),
        audit: audit.clone(),
    });

    let listener = match tokio::net::TcpListener::bind(LISTEN).await {
        Ok(listener) => listener,
        Err(e) => fatal(&format!("cannot listen on {LISTEN}: {e}")),
    };
    tracing::info!("schema is up to date, listening on {LISTEN}");
    if let Err(e) = axum::serve(listener, api::router(ctx.clone()))
        .with_graceful_shutdown(shutdown())
        .await
    {
        fatal(&format!("server stopped: {e}"));
    }

    // --- Feature Start ---
    // Order matters, and the sweeper is part of it. The counters live in the
    // cache, so they are flushed into the channel first; then every holder of an
    // audit sender lets go — including the sweeper task, which holds an Arc of
    // the cache and would otherwise keep the writer waiting on a sender that
    // never drops, hanging shutdown until Docker's SIGKILL arrives and takes the
    // queue with it. Only then is the writer waited on. Exit before all of this
    // and up to one TTL of audit summaries goes with the process (docs/02).
    // --- Feature End ---
    sweeper.abort();
    cache.flush_all();
    drop(ctx);
    drop(cache);
    drop(audit);
    match tokio::time::timeout(SHUTDOWN_DRAIN, writer).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::error!(error = %e, "audit writer did not finish"),
        Err(_) => tracing::error!("audit queue did not drain in {SHUTDOWN_DRAIN:?}"),
    }
}
