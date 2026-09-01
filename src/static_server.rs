//! Static file server.
//!
//! Serves the contents of a directory over HTTP on the loopback interface
//! using [`tower_http::services::ServeDir`], fronted by a confinement guard
//! and a [`TraceLayer`]. Only `127.0.0.1` is ever bound — the server is never
//! exposed publicly; the public surface is provided by the cloudflared
//! tunnel. A directory that has no `index.html` of its own is answered with a
//! generated HTML listing (see [`serve_or_list`]) instead of a 404.
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
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;
use axum::Router;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::{Next, from_fn_with_state};
use axum::response::{Html, IntoResponse, Response};
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
/// observes the finalised response, the [`confine`] guard runs next, and the
/// [`serve_or_list`] listing middleware is the innermost layer — it sits just
/// in front of the `ServeDir` fallback and either answers a directory with a
/// listing or hands the request over untouched.
pub fn router(dir: PathBuf) -> Router {
    // Canonicalise the root so (a) symlinked roots resolve to their real target
    // and (b) the confinement guard compares against a stable, absolute base.
    let root = std::fs::canonicalize(&dir).unwrap_or(dir);
    // axum 0.8 removed `nest_service("/")` ("nesting at the root is no longer
    // supported"). Serving the directory as the fallback service covers every
    // path: `index.html` at `/`, the matching file beneath it elsewhere, and a
    // 404 for anything missing. The serve_or_list middleware layered in front
    // of it additionally renders a directory listing for a directory that has
    // no `index.html` (see [`serve_or_list`]).
    Router::new()
        .fallback_service(ServeDir::new(root.clone()))
        .layer(from_fn_with_state(root.clone(), serve_or_list))
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

/// Listing middleware, layered between the [`confine`] guard and the
/// `ServeDir` fallback: serve the request through `ServeDir` as usual, except
/// when the request resolves to a directory that has no `index.html` — in
/// that case answer with an HTML listing of the directory instead of letting
/// ServeDir 404.
///
/// The listing honours the same confinement rules as file serving: the request
/// has already passed the [`confine`] guard by the time it reaches us, and the
/// listing itself hides entries the guard would refuse to serve — dotfiles,
/// symlinks that escape the root, and broken symlinks. The filesystem reads
/// for the listing happen in `spawn_blocking`, consistent with the guard's
/// realpath/stat calls.
async fn serve_or_list(State(root): State<PathBuf>, request: Request, next: Next) -> Response {
    // Listings apply to GET/HEAD only; anything else defers to ServeDir,
    // which answers non-GET/HEAD uniformly with 405, so a directory listing
    // behaves exactly like a file would under the same method.
    let method = request.method();
    if method != Method::GET && method != Method::HEAD {
        return next.run(request).await;
    }
    let is_head = method == Method::HEAD;
    let raw = request.uri().path();
    // Percent-decode and rebuild the candidate path exactly like the guard
    // (and, ultimately, ServeDir) so the listing decision is made on the same
    // path everyone else resolves.
    let decoded = match percent_decode(raw.as_bytes()).decode_utf8() {
        Ok(s) => s,
        // Undecodable paths are refused by `confine` first; if one reaches us
        // anyway, let ServeDir decide its fate.
        Err(_) => return next.run(request).await,
    };
    let mut candidate = root.clone();
    for seg in decoded.trim_start_matches('/').split('/') {
        if !seg.is_empty() {
            candidate.push(seg);
        }
    }

    let listing = tokio::task::spawn_blocking(move || render_listing(&candidate, &root))
        .await
        .unwrap_or(None);
    match listing {
        Some(html) => {
            // A HEAD mirrors the GET representation's headers — including a
            // truthful Content-Length — but carries no body, like ServeDir's
            // HEAD answers on files.
            let len = html.len();
            let mut response = Html(html).into_response();
            if is_head {
                response
                    .headers_mut()
                    .insert(header::CONTENT_LENGTH, HeaderValue::from(len));
                response.map(|_| axum::body::Body::empty())
            } else {
                response
            }
        }
        // Not a listable directory (a file, a directory with an index.html, or
        // a missing path): defer to ServeDir's semantics — redirects, ranges,
        // ETag, index.html serving, and the final 404.
        None => next.run(request).await,
    }
}

/// Blocking half of [`serve_or_list`]: if `candidate` is a directory under
/// `root` with no `index.html`, return a rendered HTML listing of it;
/// otherwise return `None` so the request falls through to `ServeDir`.
/// Runs inside `spawn_blocking`; every syscall the listing needs (realpath,
/// stat, read_dir) happens here, off the async worker threads.
fn render_listing(candidate: &Path, root: &Path) -> Option<String> {
    // Canonicalize fails on missing paths — those belong to ServeDir's 404.
    let resolved = std::fs::canonicalize(candidate).ok()?;
    if !resolved.starts_with(root) || !resolved.is_dir() {
        return None;
    }
    // An explicit index.html always wins over a generated listing.
    if resolved.join("index.html").exists() {
        return None;
    }

    let mut entries: Vec<(String, bool)> = Vec::new(); // (name, is_dir)
    for entry in std::fs::read_dir(&resolved).ok()?.flatten() {
        // Non-UTF-8 filenames render lossily (U+FFFD) and their hrefs will
        // 404 on fetch; tolerated in a dev-facing listing rather than
        // threading raw OsStr bytes through the HTML layer.
        let name = entry.file_name().to_string_lossy().into_owned();
        // Hide dotfiles: confine refuses to serve them, so listing them would
        // only advertise links that 404 (and leak names such as `.env`).
        if name.starts_with('.') {
            continue;
        }
        // Resolve each entry through symlinks (and junctions) once. A target
        // outside the root is hidden — the guard would 404 the link anyway —
        // and so is an unresolvable one (a broken symlink is a dead link).
        // The resolution also gives the entry's real kind: a symlink to a
        // directory inside the tree is listed as a directory, not a file.
        let target = match std::fs::canonicalize(entry.path()) {
            Ok(target) if target.starts_with(root) => target,
            _ => continue,
        };
        entries.push((name, target.is_dir()));
    }
    // Directories first, each group alphabetical.
    entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    // The title interpolates a filesystem-derived path into markup, so it is
    // escaped exactly like the entry labels — a directory named `x<h1 …`
    // must not inject.
    let title = escape_html(&decoded_title(candidate, root));
    // Entry hrefs are rooted at `/` rather than `./`-relative so they resolve
    // identically whether the listing was reached as `/dir/` or `/dir` (for
    // files ServeDir answers the latter with a trailing-slash redirect; for
    // listings both forms are rendered directly).
    let base = href_base(candidate, root);
    let mut html = format!(
        "<!DOCTYPE html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n\
         <title>Index of {title}</title>\n\
         <style>body{{font-family:system-ui,sans-serif;max-width:42em;margin:2em auto;padding:0 1em}}\
         h1{{font-size:1.3em}}li{{list-style:none;padding:.15em 0}}\
         .dir{{font-weight:600}}</style>\n</head>\n<body>\n\
         <h1>Index of {title}</h1>\n<hr>\n<ul>\n"
    );
    if candidate != root {
        // Absolute parent href: a relative `../` resolves against the
        // listing's URL, which misses a level when the listing was reached
        // without its trailing slash (/a/b -> / instead of /a/).
        let parent = href_base(candidate.parent().unwrap_or(root), root);
        html.push_str(&format!("<li><a href=\"{parent}\">../</a></li>\n"));
    }
    for (name, is_dir) in &entries {
        let kind = if *is_dir { "dir" } else { "file" };
        let slash = if *is_dir { "/" } else { "" };
        let href = encode_href(name);
        let label = escape_html(name);
        html.push_str(&format!(
            "<li><a class=\"{kind}\" href=\"{base}{href}{slash}\">{label}{slash}</a></li>\n"
        ));
    }
    html.push_str("</ul>\n<hr>\n</body>\n</html>\n");
    Some(html)
}

/// Title text for the listing, before HTML escaping: the request path, or `/`
/// for the root. `candidate` is always `root` plus pushed segments, so the
/// strip cannot actually fail — the `unwrap_or` only keeps the function total
/// without panicking.
fn decoded_title(candidate: &Path, root: &Path) -> String {
    let rel = candidate.strip_prefix(root).unwrap_or(Path::new(""));
    if rel.as_os_str().is_empty() {
        return "/".to_string();
    }
    let title = format!("/{}", rel.to_string_lossy());
    // Windows separates path components with `\`; the title must show the
    // `/` the hrefs use. On Unix a `\` is an ordinary filename character and
    // must be left alone.
    #[cfg(windows)]
    let title = title.replace('\\', "/");
    title
}

/// Prefix for the listing's entry hrefs: the requested directory as an
/// absolute path with every segment percent-encoded and a trailing `/`
/// (just `/` for the root listing).
fn href_base(candidate: &Path, root: &Path) -> String {
    let mut base = String::from("/");
    if let Ok(rel) = candidate.strip_prefix(root) {
        for seg in rel {
            base.push_str(&encode_href(&seg.to_string_lossy()));
            base.push('/');
        }
    }
    base
}

/// Percent-encode a name for use in an href: keep the unreserved set plus the
/// `/` separator, encode everything else (spaces, `?`, `#`, `%`, `&`, `<`,
/// `:`, `[`, non-ASCII, ...).
fn encode_href(name: &str) -> String {
    const FRAGMENT: &percent_encoding::AsciiSet = &percent_encoding::CONTROLS
        .add(b' ')
        .add(b'"')
        .add(b'#')
        .add(b'%')
        .add(b'&')
        .add(b'\'')
        .add(b';')
        .add(b'=')
        .add(b'?')
        .add(b'`')
        .add(b'{')
        .add(b'}')
        .add(b'[')
        .add(b']')
        .add(b'<')
        .add(b'>')
        .add(b'\\')
        .add(b'^')
        .add(b'|')
        .add(b':')
        .add(b'@');
    percent_encoding::utf8_percent_encode(name, FRAGMENT).to_string()
}

/// Minimal HTML text escaping for names inside the listing markup.
fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
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
/// All filesystem syscalls (`canonicalize`, `exists`, `is_dir`) are run inside
/// [`tokio::task::spawn_blocking`]: `confine` is on the hot path proxied from
/// the public internet, and those are blocking realpath/stat calls that would
/// otherwise stall the tokio worker thread (the documented std::fs-in-async
/// anti-pattern), serialising request handling and making a slow/NFS-backed
/// served tree worse.
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
    // and are refused; missing paths fail canonicalize and 404. Run all of the
    // blocking fs work (candidate canonicalize, is_dir, and the index.html
    // confinement check) in one spawn_blocking so no realpath/stat touches the
    // runtime worker thread.
    let confined = tokio::task::spawn_blocking(move || confine_blocking(&candidate, &root))
        .await
        .unwrap_or(false);
    if !confined {
        return StatusCode::NOT_FOUND.into_response();
    }
    next.run(request).await
}

/// Blocking half of [`confine`]: resolves `candidate`, requires it to stay
/// under `root`, and — when it is a directory — confines the `index.html`
/// ServeDir resolves on its own. Returns `true` if the request is safe to
/// forward to ServeDir, `false` to 404. Designed to run inside
/// `spawn_blocking`; performs the realpath/stat syscalls the guard needs.
fn confine_blocking(candidate: &Path, root: &Path) -> bool {
    let resolved = match std::fs::canonicalize(candidate) {
        Ok(r) => r,
        Err(_) => return false,
    };
    if !resolved.starts_with(root) {
        return false;
    }
    // ServeDir serves `<dir>/index.html` for directory requests (its directory-
    // index feature), and that index.html may itself be a symlink escaping the
    // root — a vector confine must close, not just the directory itself. So when
    // the candidate is a directory, also confine its index.html.
    if resolved.is_dir() && escapes_root(&resolved.join("index.html"), root) {
        return false;
    }
    true
}

/// True if `path` exists and canonicalises to a target outside `root`. Used to
/// confine the directory-index file (`index.html`) that ServeDir resolves on
/// its own, in addition to the request path itself.
fn escapes_root(path: &Path, root: &Path) -> bool {
    if !path.exists() {
        return false;
    }
    match std::fs::canonicalize(path) {
        Ok(r) => !r.starts_with(root),
        // Exists but unresolvable (e.g. a broken symlink): treat as escaping.
        Err(_) => true,
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
    //! confinement (symlink escape, dotfiles, traversal, junction) is exercised
    //! inline in `http_confinement_tests` below.
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

    #[cfg(unix)]
    #[tokio::test]
    async fn symlink_escape_outside_root_is_blocked() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().expect("tempdir");
        // A file OUTSIDE the served root.
        let outside = tempfile::tempdir().expect("outside tempdir");
        std::fs::write(outside.path().join("secret"), "TOPSECRET").expect("write");
        std::fs::write(dir.path().join("index.html"), "ok").expect("write");
        symlink(outside.path().join("secret"), dir.path().join("link")).expect("symlink");

        let r = router(dir.path().to_path_buf());
        assert_eq!(
            r.oneshot(req("/link")).await.unwrap().status(),
            StatusCode::NOT_FOUND,
            "a symlink escaping the root must not be served"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlink_escape_via_directory_index_is_blocked() {
        // ServeDir serves <dir>/index.html for directory requests; an escaping
        // symlink placed there must be confined too (regression for the C1
        // index.html bypass).
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().expect("tempdir");
        let outside = tempfile::tempdir().expect("outside");
        std::fs::write(outside.path().join("secret"), "TOPSECRET").expect("write");
        std::fs::create_dir_all(dir.path().join("sub")).expect("mkdir");
        symlink(
            outside.path().join("secret"),
            dir.path().join("sub").join("index.html"),
        )
        .expect("symlink");

        for uri in ["/sub/", "/sub", "/sub/index.html"] {
            let r = router(dir.path().to_path_buf());
            assert_eq!(
                r.oneshot(req(uri)).await.unwrap().status(),
                StatusCode::NOT_FOUND,
                "{uri} should be confined (index.html is an escaping symlink)"
            );
        }
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

    /// Windows: a directory junction (a reparse point) pointing outside the
    /// served root must be confined just like a Unix symlink. `std::fs::canonicalize`
    /// resolves junctions, so `confine`'s canonicalize-then-`starts_with` rejects
    /// the escape. (Runs only on the Windows CI matrix, where `mklink /J` exists.)
    #[cfg(windows)]
    #[tokio::test]
    async fn junction_escape_outside_root_is_blocked() {
        let dir = tempfile::tempdir().expect("tempdir");
        let outside = tempfile::tempdir().expect("outside tempdir");
        std::fs::write(outside.path().join("secret"), "TOPSECRET").expect("write");
        std::fs::write(dir.path().join("index.html"), "ok").expect("write");

        // Create a junction `dir/link -> outside` via cmd (no admin needed for /J).
        let status = std::process::Command::new("cmd")
            .args([
                "/c",
                "mklink",
                "/J",
                &dir.path().join("link").to_string_lossy(),
                &outside.path().to_string_lossy(),
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("run mklink");
        // If mklink is unavailable in some environment, skip rather than fail.
        if !status.success() {
            eprintln!("skipping: mklink /J failed");
            return;
        }

        let r = router(dir.path().to_path_buf());
        assert_eq!(
            r.oneshot(req("/link")).await.unwrap().status(),
            StatusCode::NOT_FOUND,
            "a junction escaping the root must not be served"
        );
    }
}

#[cfg(test)]
mod listing_tests {
    //! Directory-listing fallback: rendering and ordering, `index.html`
    //! precedence, dotfile hiding, HTML/percent-encoding of names, href
    //! fetchability, and HEAD behaviour.
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    fn req(method: &str, uri: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .expect("build request")
    }

    async fn body_of(resp: Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("read body");
        String::from_utf8(bytes.to_vec()).expect("body is utf-8")
    }

    #[tokio::test]
    async fn root_without_index_renders_a_listing() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("alpha.txt"), "a").expect("write");
        std::fs::write(dir.path().join("zeta.txt"), "z").expect("write");
        std::fs::create_dir(dir.path().join("beta")).expect("mkdir");
        std::fs::write(dir.path().join("beta").join("inner.html"), "i").expect("write");

        let resp = router(dir.path().to_path_buf())
            .oneshot(req("GET", "/"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/html; charset=utf-8"
        );
        let html = body_of(resp).await;
        assert!(html.contains("Index of /"), "title names the root: {html}");
        // Directories first with a trailing '/' in href and label, then files
        // alphabetically.
        assert!(html.contains("href=\"/beta/\""), "{html}");
        let beta = html.find("beta/").expect("beta listed");
        let alpha = html.find("alpha.txt").expect("alpha listed");
        let zeta = html.find("zeta.txt").expect("zeta listed");
        assert!(beta < alpha, "directories must be listed before files");
        assert!(alpha < zeta, "files must be alphabetical");
        // The root listing has no parent link.
        assert!(!html.contains("../"), "{html}");
    }

    #[tokio::test]
    async fn index_html_takes_precedence_over_listings() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("index.html"), "<h1>root index</h1>").expect("write");
        std::fs::create_dir(dir.path().join("sub")).expect("mkdir");
        std::fs::write(
            dir.path().join("sub").join("index.html"),
            "<h1>sub index</h1>",
        )
        .expect("write");
        std::fs::create_dir(dir.path().join("bare")).expect("mkdir");

        // Root: the real index.html is served, not a listing.
        let resp = router(dir.path().to_path_buf())
            .oneshot(req("GET", "/"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_of(resp).await, "<h1>root index</h1>");

        // A subdirectory with its own index.html serves it too...
        let resp = router(dir.path().to_path_buf())
            .oneshot(req("GET", "/sub/"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_of(resp).await, "<h1>sub index</h1>");

        // ...while a sibling directory without one still gets a listing,
        // including the ../ parent link.
        let resp = router(dir.path().to_path_buf())
            .oneshot(req("GET", "/bare/"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_of(resp).await;
        assert!(html.contains("Index of /bare"), "{html}");
        assert!(html.contains("<li><a href=\"/\">../</a></li>"), "{html}");
    }

    #[tokio::test]
    async fn dotfiles_are_hidden_from_listings() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(".env"), "SECRET=1").expect("write");
        std::fs::create_dir(dir.path().join(".git")).expect("mkdir");
        std::fs::write(dir.path().join(".git").join("config"), "x").expect("write");
        std::fs::write(dir.path().join("ok.txt"), "fine").expect("write");

        let resp = router(dir.path().to_path_buf())
            .oneshot(req("GET", "/"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_of(resp).await;
        assert!(html.contains("ok.txt"), "regular files are listed: {html}");
        assert!(
            !html.contains(".env"),
            "dotfiles must not be listed: {html}"
        );
        assert!(
            !html.contains(".git"),
            "dot-dirs must not be listed: {html}"
        );
    }

    #[tokio::test]
    async fn names_with_spaces_and_markup_are_escaped_and_encoded() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("a b.txt"), "spaced").expect("write");
        std::fs::write(dir.path().join("amp&and.txt"), "ampered").expect("write");
        std::fs::write(dir.path().join("eq=semi;.txt"), "eqsemi").expect("write");
        std::fs::create_dir(dir.path().join("sub dir")).expect("mkdir");
        std::fs::write(dir.path().join("sub dir").join("inner.txt"), "i").expect("write");

        let resp = router(dir.path().to_path_buf())
            .oneshot(req("GET", "/"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_of(resp).await;
        // Visible names are HTML-escaped where significant...
        assert!(html.contains(">a b.txt</a>"), "{html}");
        assert!(html.contains(">amp&amp;and.txt</a>"), "{html}");
        assert!(html.contains(">sub dir/</a>"), "{html}");
        // ...and hrefs are percent-encoded, directory segments included.
        assert!(html.contains("href=\"/a%20b.txt\""), "{html}");
        assert!(html.contains("href=\"/amp%26and.txt\""), "{html}");
        assert!(html.contains("href=\"/eq%3Dsemi%3B.txt\""), "{html}");
        assert!(html.contains("href=\"/sub%20dir/\""), "{html}");

        // A subdirectory listing reached through its encoded href keeps
        // encoding its own path and shows the parent link.
        let resp = router(dir.path().to_path_buf())
            .oneshot(req("GET", "/sub%20dir/"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_of(resp).await;
        assert!(html.contains("Index of /sub dir"), "{html}");
        assert!(html.contains("href=\"/sub%20dir/inner.txt\""), "{html}");
        assert!(html.contains("<li><a href=\"/\">../</a></li>"), "{html}");
    }

    /// `<` and `>` are HTML-significant but illegal in Windows filenames, so
    /// the angle-bracket case is exercised on Unix only.
    #[cfg(unix)]
    #[tokio::test]
    async fn names_with_angle_brackets_are_escaped_and_encoded() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("lt<gt>.txt"), "angled").expect("write");

        let resp = router(dir.path().to_path_buf())
            .oneshot(req("GET", "/"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_of(resp).await;
        assert!(html.contains(">lt&lt;gt&gt;.txt</a>"), "{html}");
        assert!(html.contains("href=\"/lt%3Cgt%3E.txt\""), "{html}");
    }

    #[tokio::test]
    async fn listed_files_stay_fetchable_through_their_encoded_hrefs() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("a b.txt"), "spaced").expect("write");
        std::fs::write(dir.path().join("amp&and.txt"), "ampered").expect("write");

        // The hrefs the listing advertises must round-trip as real requests.
        for (uri, want) in [("/a%20b.txt", "spaced"), ("/amp%26and.txt", "ampered")] {
            let resp = router(dir.path().to_path_buf())
                .oneshot(req("GET", uri))
                .await
                .expect("oneshot");
            assert_eq!(resp.status(), StatusCode::OK, "{uri} should be fetchable");
            assert_eq!(body_of(resp).await, want);
        }
    }

    #[tokio::test]
    async fn head_requests_answer_with_headers_but_no_body() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("f.txt"), "x").expect("write");

        // The listing's GET representation, for the Content-Length check.
        let resp = router(dir.path().to_path_buf())
            .oneshot(req("GET", "/"))
            .await
            .expect("oneshot");
        let page = body_of(resp).await;

        // Listing path: same status/type, the GET representation's true
        // Content-Length, and an empty body.
        let resp = router(dir.path().to_path_buf())
            .oneshot(req("HEAD", "/"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/html; charset=utf-8"
        );
        assert_eq!(
            resp.headers().get(header::CONTENT_LENGTH).unwrap(),
            page.len().to_string().as_str(),
            "HEAD must report the GET representation's true length"
        );
        assert!(body_of(resp).await.is_empty());

        // File path (ServeDir) still answers HEAD headers-only.
        let resp = router(dir.path().to_path_buf())
            .oneshot(req("HEAD", "/f.txt"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(body_of(resp).await.is_empty());
    }

    /// A directory name carrying markup must not inject into the listing:
    /// the title/h1 are escaped just like the entry labels. (Unix-gated:
    /// `<` and `>` are illegal in Windows filenames.)
    #[cfg(unix)]
    #[tokio::test]
    async fn listing_title_escapes_markup_in_directory_names() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(dir.path().join("x<h1 onx=y")).expect("mkdir");

        // The root listing escapes the entry's label...
        let resp = router(dir.path().to_path_buf())
            .oneshot(req("GET", "/"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_of(resp).await;
        assert!(html.contains(">x&lt;h1 onx=y/</a>"), "{html}");

        // ...and the directory's own listing escapes the title/h1 built from
        // its name.
        let resp = router(dir.path().to_path_buf())
            .oneshot(req("GET", "/x%3Ch1%20onx%3Dy/"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_of(resp).await;
        assert!(
            html.contains("Index of /x&lt;h1 onx=y"),
            "title must be escaped: {html}"
        );
        assert!(
            !html.contains("x<h1"),
            "raw markup must not survive: {html}"
        );
        assert!(!html.contains("<h1 onx=y"), "{html}");
    }

    #[tokio::test]
    async fn parent_link_targets_the_immediate_parent_even_without_trailing_slash() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("a").join("b")).expect("mkdir");
        std::fs::write(dir.path().join("a").join("b").join("f.txt"), "f").expect("write");

        // The regression case first: the listing reached WITHOUT its trailing
        // slash. A relative ../ would resolve against `/a/b` and land on `/`;
        // the absolute href must name the immediate parent `/a/` in both
        // forms.
        for uri in ["/a/b", "/a/b/"] {
            let resp = router(dir.path().to_path_buf())
                .oneshot(req("GET", uri))
                .await
                .expect("oneshot");
            assert_eq!(resp.status(), StatusCode::OK);
            let html = body_of(resp).await;
            assert!(
                html.contains("<li><a href=\"/a/\">../</a></li>"),
                "parent of {uri} must be /a/: {html}"
            );
            assert!(!html.contains("href=\"../\""), "{html}");
        }
    }

    /// A symlink whose target escapes the served root is hidden from
    /// listings: the guard 404s it, so listing it would only advertise a dead
    /// link — and leak a name from outside the tree.
    #[cfg(unix)]
    #[tokio::test]
    async fn escaping_symlinks_are_hidden_from_listings() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().expect("tempdir");
        let outside = tempfile::tempdir().expect("outside tempdir");
        std::fs::write(outside.path().join("secret"), "TOPSECRET").expect("write");
        std::fs::write(dir.path().join("ok.txt"), "fine").expect("write");
        symlink(outside.path().join("secret"), dir.path().join("leak")).expect("symlink");

        let resp = router(dir.path().to_path_buf())
            .oneshot(req("GET", "/"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_of(resp).await;
        assert!(html.contains("ok.txt"), "{html}");
        assert!(
            !html.contains("leak"),
            "escaping symlink must not be listed: {html}"
        );
    }

    #[tokio::test]
    async fn non_get_head_requests_to_a_listing_are_method_not_allowed() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("f.txt"), "x").expect("write");

        // ServeDir answers non-GET/HEAD with 405; the listing must not turn
        // a POST to a directory into a 200.
        let resp = router(dir.path().to_path_buf())
            .oneshot(req("POST", "/"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    /// A symlink to a directory INSIDE the root is a directory as far as the
    /// listing is concerned: class="dir", trailing '/' in href and label, and
    /// a place in the directory group.
    #[cfg(unix)]
    #[tokio::test]
    async fn symlink_to_an_inner_directory_is_listed_as_a_directory() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(dir.path().join("real")).expect("mkdir");
        std::fs::write(dir.path().join("real").join("inner.txt"), "x").expect("write");
        std::fs::write(dir.path().join("zfile.txt"), "z").expect("write");
        symlink("real", dir.path().join("alias")).expect("symlink");

        let resp = router(dir.path().to_path_buf())
            .oneshot(req("GET", "/"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_of(resp).await;
        assert!(
            html.contains("<li><a class=\"dir\" href=\"/alias/\">alias/</a></li>"),
            "{html}"
        );
        // It sorts into the directory group, before files.
        let alias = html.find("alias/").expect("alias listed");
        let zfile = html.find("zfile.txt").expect("zfile listed");
        assert!(
            alias < zfile,
            "a symlinked directory must sort with directories: {html}"
        );

        // And the link is real: its own listing renders through the alias.
        let resp = router(dir.path().to_path_buf())
            .oneshot(req("GET", "/alias/"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_of(resp).await;
        assert!(html.contains("Index of /alias"), "{html}");
        assert!(html.contains("href=\"/alias/inner.txt\""), "{html}");
    }

    /// Windows counterpart of the symlink test above: a junction to a
    /// directory inside the root resolves through canonicalize and must be
    /// listed as a directory too. (Runs only on the Windows CI matrix, where
    /// `mklink /J` exists.)
    #[cfg(windows)]
    #[tokio::test]
    async fn junction_to_an_inner_directory_is_listed_as_a_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(dir.path().join("real")).expect("mkdir");
        std::fs::write(dir.path().join("real").join("inner.txt"), "x").expect("write");
        std::fs::write(dir.path().join("zfile.txt"), "z").expect("write");

        let status = std::process::Command::new("cmd")
            .args([
                "/c",
                "mklink",
                "/J",
                &dir.path().join("alias").to_string_lossy(),
                &dir.path().join("real").to_string_lossy(),
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("run mklink");
        // If mklink is unavailable in some environment, skip rather than fail.
        if !status.success() {
            eprintln!("skipping: mklink /J failed");
            return;
        }

        let resp = router(dir.path().to_path_buf())
            .oneshot(req("GET", "/"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_of(resp).await;
        assert!(
            html.contains("<li><a class=\"dir\" href=\"/alias/\">alias/</a></li>"),
            "{html}"
        );
    }

    /// A broken symlink advertises a link that 404s — same rationale as the
    /// escaping-symlink filter, so it is hidden as well.
    #[cfg(unix)]
    #[tokio::test]
    async fn broken_symlinks_are_hidden_from_listings() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("ok.txt"), "fine").expect("write");
        symlink("no-such-target", dir.path().join("dangling")).expect("symlink");

        let resp = router(dir.path().to_path_buf())
            .oneshot(req("GET", "/"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_of(resp).await;
        assert!(html.contains("ok.txt"), "{html}");
        assert!(
            !html.contains("dangling"),
            "a broken symlink must not be listed: {html}"
        );
    }
}
