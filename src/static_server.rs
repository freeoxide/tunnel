//! Static file server.
//!
//! Serves the contents of a directory over HTTP on the loopback interface
//! using [`tower_http::services::ServeDir`], fronted by a confinement guard
//! and a [`TraceLayer`]. Only `127.0.0.1` is ever bound — the server is never
//! exposed publicly; the public surface is provided by the cloudflared
//! tunnel.
//!
//! # Confinement
//!
//! Because cloudflared publishes whatever this server returns to the public
//! internet, the served tree must be exactly what the operator intended. The
//! [`confine`] guard (run before ServeDir) enforces three rules:
//!
//! - **dotfiles are denied** — any path segment beginning with `.` (`.env`,
//!   `.git/config`, `.ssh/...`, `.`, `..`) returns 404 by default, so the most
//!   common accidental exposures of a public static host are off by default.
//! - **symlink escape is blocked** — each request's resolved path is
//!   canonicalised and must remain under the canonical root, so a symlink
//!   inside the tree that points at `/etc/passwd` or `~/.ssh` is refused
//!   rather than followed out of the tree. (Symlinks that resolve *inside* the
//!   root are still served.)
//! - **`..` traversal is rejected** — belt-and-suspenders alongside the same
//!   check tower-http ServeDir already performs.

use std::future::Future;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use axum::Router;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::{Next, from_fn_with_state};
use axum::response::{IntoResponse, Response};
use percent_encoding::percent_decode;
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
/// request to `/foo.html` resolves to `dir/foo.html`. The root is canonicalised
/// (symlinks resolved) so the confinement guard has a stable base to confine
/// against.
///
/// Layers are applied innermost-first, so the LAST `.layer()` is the
/// outermost: TimeoutLayer wraps everything (bounding slow clients and the
/// graceful-drain), RequestBodyLimitLayer caps the body before ServeDir runs,
/// SetResponseHeaderLayer stamps `nosniff` on every response, TraceLayer
/// observes the finalised response, and the [`confine`] guard is the
/// innermost layer — it runs just before ServeDir.
pub fn router(dir: PathBuf) -> Router {
    // Canonicalise the root so (a) symlinked roots resolve to their real target
    // and (b) the confinement guard compares against a stable, absolute base.
    let root = std::fs::canonicalize(&dir).unwrap_or(dir);
    // axum 0.8 removed `nest_service("/")` ("nesting at the root is no longer
    // supported"). Serving the directory as the fallback service covers every
    // path: `index.html` at `/` and the matching file beneath it elsewhere,
    // with a 404 for anything missing.
    Router::new()
        .fallback_service(ServeDir::new(root.clone()))
        .layer(from_fn_with_state(root, confine))
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

/// Confinement guard: deny dotfiles, reject `..` traversal, and refuse any
/// path whose canonicalised target escapes the served root (symlink escape).
///
/// We reconstruct the candidate path the same way `ServeDir` does (percent-
/// decode, drop leading `/`, split on `/`, skip empty segments) and then
/// canonicalise it. `canonicalize` follows symlinks all the way to the real
/// target, so a symlink pointing outside the root resolves to a path that no
/// longer `starts_with(root)` and is refused with 404. Non-existent paths also
/// fail canonicalize and fall to 404 (ServeDir would 404 them too).
///
/// Note: there is a TOCTOU window between this canonicalise and ServeDir's own
/// open. Closing it fully requires replacing ServeDir with a hand-written
/// handler; for a dev tunneling tool the guard defeats the realistic threat
/// (symlinks already present in the served tree) and keeps ServeDir's HTTP
/// semantics (ranges, ETag, index.html).
async fn confine(State(root): State<PathBuf>, request: Request, next: Next) -> Response {
    let raw = request.uri().path();
    let decoded = match percent_decode(raw.as_bytes()).decode_utf8() {
        Ok(s) => s,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    let mut candidate = root.clone();
    for seg in decoded.trim_start_matches('/').split('/') {
        if seg.is_empty() {
            continue;
        }
        // Any segment starting with '.' is refused: dotfiles/dot-dirs (.env,
        // .git, .ssh, ...), self ('.'), and parent ('..'). ServeDir already
        // blocks '..' traversal; we block it earlier here for defense in depth
        // and add the dotfile default that ServeDir does not provide.
        if seg.starts_with('.') {
            return StatusCode::NOT_FOUND.into_response();
        }
        candidate.push(seg);
    }
    // Symlink confinement: resolve the candidate for real and require it to
    // stay beneath the canonical root. Escaping symlinks resolve outside `root`
    // and are refused; missing paths fail canonicalize and 404.
    match std::fs::canonicalize(&candidate) {
        Ok(resolved) if resolved.starts_with(&root) => next.run(request).await,
        _ => StatusCode::NOT_FOUND.into_response(),
    }
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

#[cfg(test)]
mod confinement_tests {
    //! Logic-only checks for the path decisions inside `confine`. Full HTTP
    //! confinement (symlink escape, dotfiles, traversal) is exercised in
    //! `tests/static_server_security.rs`.
    use std::path::Path;

    #[test]
    fn split_segments_drops_dotfiles_and_dots() {
        // Mirrors the decision logic: any '.'-prefixed segment is a refusal.
        fn allowed(decoded: &str) -> bool {
            decoded
                .trim_start_matches('/')
                .split('/')
                .all(|s| !s.starts_with('.'))
        }
        assert!(allowed("index.html"));
        assert!(!allowed(".env"));
        assert!(!allowed(".git/config"));
        assert!(!allowed("a/../b"));
        assert!(!allowed("../etc/passwd"));
        // A literal '.html' filename segment does NOT start with '.', so it is
        // fine (only a leading dot of the *segment* is refused).
        assert!(allowed("foo.html"));
    }

    #[test]
    fn root_is_under_itself() {
        // Sanity for the starts_with confinement predicate.
        let root = Path::new("/tmp/srv");
        assert!(root.join("a").starts_with(root));
        assert!(!Path::new("/etc/passwd").starts_with(root));
    }
}

#[cfg(test)]
mod http_confinement_tests {
    //! End-to-end confinement checks driving the real Router with tower::oneshot.
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    fn req(uri: &str) -> Request<Body> {
        Request::builder()
            .method("GET")
            .uri(uri)
            .body(Body::empty())
            .expect("build request")
    }

    #[tokio::test]
    async fn serves_normal_files_and_index() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("index.html"), "hello").expect("write");
        std::fs::create_dir_all(dir.path().join("sub")).expect("mkdir");
        std::fs::write(dir.path().join("sub").join("f.html"), "x").expect("write");

        let r = router(dir.path().to_path_buf());
        assert_eq!(r.oneshot(req("/")).await.unwrap().status(), StatusCode::OK);

        let r = router(dir.path().to_path_buf());
        assert_eq!(
            r.oneshot(req("/sub/f.html")).await.unwrap().status(),
            StatusCode::OK
        );

        let r = router(dir.path().to_path_buf());
        assert_eq!(
            r.oneshot(req("/missing.html")).await.unwrap().status(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn dotfiles_and_dotdirs_are_denied() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(".env"), "SECRET=1").expect("write");
        std::fs::create_dir_all(dir.path().join(".git")).expect("mkdir");
        std::fs::write(dir.path().join(".git").join("config"), "x").expect("write");

        let r = router(dir.path().to_path_buf());
        assert_eq!(
            r.oneshot(req("/.env")).await.unwrap().status(),
            StatusCode::NOT_FOUND
        );
        let r = router(dir.path().to_path_buf());
        assert_eq!(
            r.oneshot(req("/.git/config")).await.unwrap().status(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn parent_dir_traversal_is_denied() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("index.html"), "hi").expect("write");

        let r = router(dir.path().to_path_buf());
        // ServeDir already blocks '..'; the confine guard blocks it earlier.
        assert_eq!(
            r.oneshot(req("/../etc/passwd")).await.unwrap().status(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn symlink_escape_outside_root_is_blocked() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().expect("tempdir");
        // A file OUTSIDE the served root.
        let outside = tempfile::tempdir().expect("outside tempdir");
        std::fs::write(outside.path().join("secret"), "TOPSECRET").expect("write");
        std::fs::write(dir.path().join("index.html"), "ok").expect("write");
        symlink(
            outside.path().join("secret"),
            dir.path().join("link"),
        )
        .expect("symlink");

        let r = router(dir.path().to_path_buf());
        assert_eq!(
            r.oneshot(req("/link")).await.unwrap().status(),
            StatusCode::NOT_FOUND,
            "a symlink escaping the root must not be served"
        );
    }

    #[tokio::test]
    async fn x_content_type_options_nosniff_is_set() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("index.html"), "hi").expect("write");
        let r = router(dir.path().to_path_buf());
        let resp = r.oneshot(req("/")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("x-content-type-options").unwrap(),
            "nosniff"
        );
    }
}
