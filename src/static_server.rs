//! Static file server.
//!
//! Serves the contents of a directory over HTTP on the loopback interface
//! using [`tower_http::services::ServeDir`], with a [`TraceLayer`] for
//! request tracing. Only `127.0.0.1` is ever bound — the server is never
//! exposed publicly; the public surface is provided by the cloudflared
//! tunnel.

use std::future::Future;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use axum::Router;
use axum::http::{HeaderValue, StatusCode, header};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::services::ServeDir;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

/// Hard upper bound on any single request. Because cloudflared proxies the
/// public internet to this loopback server, a slow/stalled client could
/// otherwise pin a connection (and, via the unbounded graceful-drain, hang a
/// worker shutdown). The timeout bounds both the request and the drain.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// The static server only answers `GET`/`HEAD` and never reads a body, so cap
/// any request body at a token 1 KiB to stop an abusive public client from
/// streaming gigabytes into hyper before ServeDir short-circuits the response.
const MAX_REQUEST_BODY: usize = 1024;

/// Build an axum [`Router`] that serves `dir` at `/` with HTTP tracing.
///
/// The directory contents are mapped directly onto the root path, so a
/// request to `/foo.html` resolves to `dir/foo.html`.
pub fn router(dir: PathBuf) -> Router {
    // axum 0.8 removed `nest_service("/")` ("nesting at the root is no longer
    // supported"). Serving the directory as the fallback service covers every
    // path: `index.html` at `/` and the matching file beneath it elsewhere,
    // with a 404 for anything missing.
    //
    // Layers are applied innermost-first, so the LAST `.layer()` is the
    // outermost: TimeoutLayer wraps everything (bounding slow clients and the
    // graceful-drain), RequestBodyLimitLayer caps the body before ServeDir
    // runs, SetResponseHeaderLayer stamps `nosniff` on every response, and
    // TraceLayer is the innermost so it observes the finalised response.
    Router::new()
        .fallback_service(ServeDir::new(dir))
        .layer(TraceLayer::new_for_http())
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(RequestBodyLimitLayer::new(MAX_REQUEST_BODY))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT, // 408 — client took too long
            REQUEST_TIMEOUT,
        ))
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
    // Enforce the "loopback-only" invariant on the type, not just by
    // convention: a future caller passing a 0.0.0.0 listener would otherwise
    // publish the served tree directly, bypassing the cloudflared-only surface.
    let addr = listener
        .local_addr()
        .context("reading the bound listener address")?;
    anyhow::ensure!(
        addr.ip().is_loopback(),
        "refusing to serve on non-loopback address {addr}; the static server \
         must stay behind the cloudflared tunnel"
    );
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown)
        .await?;
    Ok(())
}
