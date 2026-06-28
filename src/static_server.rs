//! Static file server.
//!
//! Serves the contents of a directory over HTTP on the loopback interface
//! using [`tower_http::services::ServeDir`], with a [`TraceLayer`] for
//! request tracing. Only `127.0.0.1` is ever bound — the server is never
//! exposed publicly; the public surface is provided by the cloudflared
//! tunnel.

use std::future::Future;
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
    // axum 0.8 removed `nest_service("/")` ("nesting at the root is no longer
    // supported"). Serving the directory as the fallback service covers every
    // path: `index.html` at `/` and the matching file beneath it elsewhere,
    // with a 404 for anything missing.
    Router::new()
        .fallback_service(ServeDir::new(dir))
        .layer(TraceLayer::new_for_http())
}

/// Bind `router` to `127.0.0.1:port` and serve until interrupted by Ctrl-C.
///
/// Binding is restricted to the loopback interface on purpose: only the
/// local cloudflared tunnel process should be able to reach this server.
/// Shutdown is graceful: on Ctrl-C, axum stops accepting and drains in-flight
/// requests before returning.
pub async fn serve(router: Router, port: u16) -> crate::error::Result<()> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .with_context(|| format!("failed to bind 127.0.0.1:{port}"))?;
    serve_on(router, listener, async {
        // A Ctrl-C here is observed by the caller's own ctrl_c() await; this
        // future only drives axum's graceful shutdown and never aborts in-flight
        // requests on its own.
        let _ = tokio::signal::ctrl_c().await;
    })
    .await
}

/// Serve on an already-bound listener. Lets the caller bind (and fail fast on a
/// port conflict) before committing to spawning the tunnel. When the `shutdown`
/// future completes, axum stops accepting new connections and drains the
/// in-flight ones before returning — requests are never dropped mid-flight.
pub async fn serve_on(
    router: Router,
    listener: tokio::net::TcpListener,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> crate::error::Result<()> {
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown)
        .await?;
    Ok(())
}
