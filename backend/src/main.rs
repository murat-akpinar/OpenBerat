// SPDX-FileCopyrightText: 2026 OpenBerat contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// Entry point. Reads configuration from the environment, applies the schema and
// serves /decide on the core network — see TODO.md.

use openberat::admin;
use openberat::api::{self, Ctx};
use openberat::cache::Cache;
use openberat::keycloak::Keycloak;
use openberat::session::Index;
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
/// Audit partitions are created a month ahead and expire a month at a time, so
/// there is nothing a run more often than daily could find to do.
const RETENTION_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
/// The retention nobody configured. Long enough to cover an annual audit, and
/// deliberately not longer: the log is personal data (ADR-0022).
const RETENTION_MONTHS: u32 = 12;

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

    let index = match Index::connect(&required("REDIS_URL")).await {
        Ok(index) => index,
        Err(e) => fatal(&format!("cannot reach Redis, refusing to start: {e}")),
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

    // --- Feature Start ---
    // The retention job, and the reason a bad value is fatal rather than
    // defaulted: this is the one background task that deletes, and a typo in an
    // environment variable must not be able to shorten how long the audit log
    // survives. The first tick fires immediately, so a fresh install has its
    // partitions before the first decision is written (ADR-0022).
    // --- Feature End ---
    // Empty is unset, not zero: compose substitutes an empty string for a
    // variable left out of .env (.env.example), and the default belongs in one
    // place — here, rather than repeated in the compose file.
    let months = match std::env::var("AUDIT_RETENTION_MONTHS")
        .ok()
        .filter(|value| !value.trim().is_empty())
    {
        Some(value) => value
            .trim()
            .parse::<u32>()
            .ok()
            .filter(|months| *months > 0)
            .unwrap_or_else(|| {
                fatal("AUDIT_RETENTION_MONTHS must be a whole number of months, 1 or more")
            }),
        None => RETENTION_MONTHS,
    };
    tokio::spawn({
        let pool = pool.clone();
        async move {
            let mut tick = tokio::time::interval(RETENTION_INTERVAL);
            loop {
                tick.tick().await;
                if let Err(e) = store::maintain_audit(&pool, months).await {
                    tracing::error!(error = %e, "audit retention did not finish");
                }
            }
        }
    });

    // Neither hop this client makes redirects — oauth2-proxy's /oauth2/auth
    // answers 202 or 401, Keycloak's Admin API answers 200 or 204 — except
    // /oauth2/sign_out, whose 302 is the answer rather than something to
    // follow. Chasing it would report the status of whatever it points at.
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build the HTTP client");
    let ctx = Arc::new(Ctx {
        pool,
        http: http.clone(),
        oauth2_proxy: required("OAUTH2_PROXY_URL")
            .trim_end_matches('/')
            .to_string(),
        cache: cache.clone(),
        audit: audit.clone(),
        index,
        // The realm and the client id are our own realm export's, so they have
        // defaults; the secret cannot have one (ADR-0019 step 1).
        keycloak: Keycloak::new(
            &http,
            required("KEYCLOAK_URL").trim_end_matches('/'),
            &std::env::var("KEYCLOAK_REALM").unwrap_or_else(|_| "openberat".into()),
            &std::env::var("KEYCLOAK_CLIENT_ID").unwrap_or_else(|_| "openberat-backend".into()),
            &required("KEYCLOAK_CLIENT_SECRET"),
        ),
        // ADR-0008's default, overridable for a customer with a fixed AD naming
        // policy. It is the one grant that cannot come from the database.
        admin_group: std::env::var("ADMIN_GROUP").unwrap_or_else(|_| "OpenBerat-Admins".into()),
        // No default: every deployment has a different portal hostname, and a
        // default here would be a check that passes for the wrong origin.
        portal_origin: required("PORTAL_ORIGIN").trim_end_matches('/').to_string(),
        nginx_conf_dir: std::env::var("NGINX_CONF_DIR").ok(),
    });

    // --- Feature Start ---
    // The generated application blocks are rendered at startup and not only
    // when a row changes: they are a pure function of the table (ADR-0011), and
    // a database restored into an empty volume would otherwise leave every
    // application 404 until an admin edited one (INSTALL.md §9). Not fatal —
    // this writes a file for nginx, it does not decide anything.
    // --- Feature End ---
    if let Some(dir) = &ctx.nginx_conf_dir
        && let Err(e) = admin::publish_conf(&ctx.pool, dir, &ctx.portal_origin).await
    {
        tracing::error!("generating nginx configuration at startup failed: {e}");
    }

    let listener = match tokio::net::TcpListener::bind(LISTEN).await {
        Ok(listener) => listener,
        Err(e) => fatal(&format!("cannot listen on {LISTEN}: {e}")),
    };
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        "schema is up to date, listening on {LISTEN}"
    );
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
