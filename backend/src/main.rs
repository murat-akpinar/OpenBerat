// Entry point. Reads configuration from the environment, applies the schema and
// (from Phase 3) serves /decide — see TODO.md.

fn fatal(message: &str) -> ! {
    tracing::error!("{message}");
    std::process::exit(1)
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let url = std::env::var("DATABASE_URL").unwrap_or_else(|_| fatal("DATABASE_URL is not set"));
    match openberat::store::connect(&url).await {
        Ok(_pool) => tracing::info!("schema is up to date"),
        Err(e) => fatal(&format!(
            "cannot connect or apply migrations, refusing to start: {e}"
        )),
    }

    // No listener until Phase 3, so this returns and the container restarts.
}
