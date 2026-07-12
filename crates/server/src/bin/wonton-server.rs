//! Standalone `wonton-server` binary: boots the blind blob+ref store as a real HTTP process.
//!
//! Configuration is via environment variables (with sensible local-dev defaults), matching how
//! most small services expect to be configured in a container/systemd unit rather than via
//! positional CLI args:
//! - `WONTON_DATABASE_URL` — an sqlx SQLite URL. Defaults to `sqlite://wonton.db?mode=rwc` in
//!   the current directory (created if missing).
//! - `WONTON_PORT` — the TCP port to bind on `0.0.0.0`. Defaults to `8080`.
//! - `WONTON_GOOGLE_CLIENT_ID` / `WONTON_GOOGLE_CLIENT_SECRET` / `WONTON_GOOGLE_REDIRECT_URI` —
//!   enable the Google OAuth registration gate (see `oauth` module docs). All three unset =
//!   registration stays open/unverified, exactly as before Part 1.
//! - `WONTON_DASHBOARD_DIST` — path to the dashboard's built static files (`dashboard/dist`,
//!   from `npm run build`). If set and the directory exists, this binary serves the dashboard
//!   itself (single-binary self-hosting) with an SPA fallback to `index.html` for client-side
//!   routes; every other route is still the API, checked first. Unset = API-only, exactly as
//!   before Part 4 — serving the dashboard from elsewhere is equally valid and needs no server
//!   changes beyond CORS (a deploy-time choice, not built here).

use tower_http::services::{ServeDir, ServeFile};

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

    let mut oauth = wonton_server::OAuthProviders::none();
    if let Some(google) = wonton_server::GoogleProvider::from_env() {
        tracing::info!("google OAuth registration gate enabled");
        oauth = oauth.register(google);
    } else {
        tracing::info!(
            "google OAuth not configured (set WONTON_GOOGLE_CLIENT_ID / \
             WONTON_GOOGLE_CLIENT_SECRET / WONTON_GOOGLE_REDIRECT_URI to enable) — \
             registration stays open/unverified"
        );
    }
    let mut router = wonton_server::build_router_with_oauth(pool, oauth);

    if let Ok(dist) = std::env::var("WONTON_DASHBOARD_DIST") {
        let dist_path = std::path::Path::new(&dist);
        if dist_path.is_dir() {
            tracing::info!(%dist, "serving the dashboard's static build");
            let index = dist_path.join("index.html");
            let serve_dir = ServeDir::new(dist_path).not_found_service(ServeFile::new(index));
            // API routes are matched first (axum tries the explicit routes above before falling
            // back), so this only ever serves the dashboard's own static assets / SPA shell.
            router = router.fallback_service(serve_dir);
        } else {
            tracing::warn!(%dist, "WONTON_DASHBOARD_DIST is set but is not a directory; API-only");
        }
    }

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await?;
    tracing::info!(%database_url, %port, "wonton-server listening");
    axum::serve(listener, router).await?;
    Ok(())
}
