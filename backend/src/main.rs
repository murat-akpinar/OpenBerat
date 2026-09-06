// Entry point. Reads configuration from the environment, applies the schema and
// serves /decide on the core network — see TODO.md.

use openberat::api::{self, Ctx};
use std::sync::Arc;

const LISTEN: &str = "0.0.0.0:8081";

fn fatal(message: &str) -> ! {
    tracing::error!("{message}");
    std::process::exit(1)
}

fn required(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| fatal(&format!("{name} is not set")))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let pool = match openberat::store::connect(&required("DATABASE_URL")).await {
        Ok(pool) => pool,
        Err(e) => fatal(&format!(
            "cannot connect or apply migrations, refusing to start: {e}"
        )),
    };
    let ctx = Arc::new(Ctx {
        pool,
        http: reqwest::Client::new(),
        oauth2_proxy: required("OAUTH2_PROXY_URL")
            .trim_end_matches('/')
            .to_string(),
    });

    let listener = match tokio::net::TcpListener::bind(LISTEN).await {
        Ok(listener) => listener,
        Err(e) => fatal(&format!("cannot listen on {LISTEN}: {e}")),
    };
    tracing::info!("schema is up to date, listening on {LISTEN}");
    if let Err(e) = axum::serve(listener, api::router(ctx)).await {
        fatal(&format!("server stopped: {e}"));
    }
}
