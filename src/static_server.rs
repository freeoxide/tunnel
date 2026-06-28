//! Static file server.
//!
//! Serves the contents of a directory over HTTP on the loopback interface
//! using [`tower_http::services::ServeDir`], with a [`TraceLayer`] for
//! request tracing. Only `127.0.0.1` is ever bound — the server is never
//! exposed publicly; the public surface is provided by the cloudflared
//! tunnel.

use std::path::PathBuf;

use anyhow::Context;
use axum::Router;
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;

/// Build an axum [`Router`] that serves `dir` at `/` with HTTP tracing.
///
/// The directory contents are mapped directly onto the root path, so a
/// request to `/foo.html` resolves to `dir/foo.html`.
pub fn router(dir: PathBuf) -> Router {
    Router::new()
        .nest_service("/", ServeDir::new(dir))
        .layer(TraceLayer::new_for_http())
}

/// Bind `router` to `127.0.0.1:port` and serve until shut down.
///
/// Binding is restricted to the loopback interface on purpose: only the
/// local cloudflared tunnel process should be able to reach this server.
pub async fn serve(router: Router, port: u16) -> crate::error::Result<()> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .with_context(|| format!("failed to bind 127.0.0.1:{port}"))?;
    axum::serve(listener, router).await?;
    Ok(())
}
