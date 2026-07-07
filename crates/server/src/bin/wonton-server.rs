//! Standalone `wonton-server` binary: boots the blind blob+ref store as a real HTTP process.
//!
//! Configuration is via environment variables (with sensible local-dev defaults), matching how
//! most small services expect to be configured in a container/systemd unit rather than via
//! positional CLI args:
//! - `WONTON_DATABASE_URL` — an sqlx SQLite URL. Defaults to `sqlite://wonton.db?mode=rwc` in
//!   the current directory (created if missing).
//! - `WONTON_PORT` — the TCP port to bind on `0.0.0.0`. Defaults to `8080`.

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let database_url = std::env::var("WONTON_DATABASE_URL")
        .unwrap_or_else(|_| "sqlite://wonton.db?mode=rwc".to_string());
    let port: u16 = std::env::var("WONTON_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    let pool = wonton_server::connect(&database_url).await?;
    let router = wonton_server::build_router(pool);
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await?;
    tracing::info!(%database_url, %port, "wonton-server listening");
    axum::serve(listener, router).await?;
    Ok(())
}
