//! Static file server: a directory served over HTTP on loopback only — the
//! public surface is the cloudflared tunnel. An index-less directory gets a
//! generated HTML listing ([`serve_or_list`]). [`confine`] — shared verbatim
//! with the drop bucket's GET side — denies dotfile segments, `..` traversal,
//! and symlink escape; the per-flag layer-order rationale lives at
//! [`router_with`] and the guards themselves.

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

/// Bounds both the request and the graceful drain — a stalled public client
/// must not hang a worker shutdown.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// The server never reads a body; the cap stops an abusive client streaming
/// one into hyper before ServeDir short-circuits.
const MAX_REQUEST_BODY: usize = 1024;

/// Serve `dir` at `/` under the given flags (persisted on the registry
/// entry, so the worker re-applies them); the layer order is load-bearing.
pub fn router_with(dir: PathBuf, flags: crate::model::StaticFlags) -> Router {
    let root = std::fs::canonicalize(&dir).unwrap_or(dir);
    let crate::model::StaticFlags { spa, cors, token } = flags;
    // axum 0.8 removed `nest_service("/")`; the directory as the fallback
    // service covers every path.
    let mut router = Router::new()
        .fallback_service(ServeDir::new(root.clone()))
        .layer(from_fn_with_state(root.clone(), serve_or_list))
        .layer(from_fn_with_state(root.clone(), confine));
    // SPA sits OUTSIDE confine: confine 404s missing paths itself, so a
    // fallback inside the guard would never observe the 404s it rewrites.
    if spa {
        router = router.layer(from_fn_with_state(root.clone(), spa_fallback));
    }
    router = router.layer(TraceLayer::new_for_http());
    // Auth before confinement: an unauthenticated 404-scanner cannot use the
    // 404/200 distinction to probe which paths exist.
    if let Some(expected) = token {
        router = router.layer(from_fn_with_state(expected, require_token));
    }
    // Above the token guard so 401s carry the headers. Preflight stays
    // unanswered (405): with --token cross-origin Bearer can never work.
    if cors {
        router = router
            .layer(SetResponseHeaderLayer::overriding(
                header::ACCESS_CONTROL_ALLOW_ORIGIN,
                HeaderValue::from_static("*"),
            ))
            .layer(SetResponseHeaderLayer::overriding(
                header::ACCESS_CONTROL_ALLOW_METHODS,
                HeaderValue::from_static("GET, HEAD, OPTIONS"),
            ))
            // Wildcard request headers: safe — an `*` origin never allows
            // credentials.
            .layer(SetResponseHeaderLayer::overriding(
                header::ACCESS_CONTROL_ALLOW_HEADERS,
                HeaderValue::from_static("*"),
            ));
    }
    router
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(RequestBodyLimitLayer::new(MAX_REQUEST_BODY))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            REQUEST_TIMEOUT,
        ))
}

/// Listing middleware: an index-less directory answers with an HTML listing
/// (which hides entries the guard would refuse) instead of ServeDir's 404.
async fn serve_or_list(State(root): State<PathBuf>, request: Request, next: Next) -> Response {
    let method = request.method();
    if method != Method::GET && method != Method::HEAD {
        return next.run(request).await;
    }
    let is_head = method == Method::HEAD;
    let raw = request.uri().path();
    let decoded = match percent_decode(raw.as_bytes()).decode_utf8() {
        Ok(s) => s,
        // Undecodable paths are confine's to refuse; let ServeDir decide.
        Err(_) => return next.run(request).await,
    };
    let candidate = candidate_path(&root, &decoded);

    let listing = tokio::task::spawn_blocking(move || render_listing(&candidate, &root))
        .await
        .unwrap_or(None);
    match listing {
        Some(html) => {
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
        None => next.run(request).await,
    }
}

/// Blocking half of [`serve_or_list`]: render the listing, or `None` to fall
/// through to `ServeDir`.
fn render_listing(candidate: &Path, root: &Path) -> Option<String> {
    // Canonicalize fails on missing paths — those belong to ServeDir's 404.
    let resolved = std::fs::canonicalize(candidate).ok()?;
    if !resolved.starts_with(root) || !resolved.is_dir() {
        return None;
    }
    if resolved.join("index.html").exists() {
        return None;
    }

    let mut entries: Vec<(String, bool)> = Vec::new(); // (name, is_dir)
    for entry in std::fs::read_dir(&resolved).ok()?.flatten() {
        // Non-UTF-8 names render lossily (their hrefs 404) — tolerated here.
        let name = entry.file_name().to_string_lossy().into_owned();
        // Hide dotfiles: confine refuses to serve them, so listing them
        // would only advertise 404 links (and leak names such as `.env`).
        if name.starts_with('.') {
            continue;
        }
        // Resolve once: escaping or dead links are hidden (the guard 404s
        // them), and the target's real kind classifies the entry.
        let target = match std::fs::canonicalize(entry.path()) {
            Ok(target) if target.starts_with(root) => target,
            _ => continue,
        };
        entries.push((name, target.is_dir()));
    }
    entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    // The title is fs-derived — escaped like the labels.
    let title = escape_html(&format!("Index of {}", decoded_title(candidate, root)));
    // `/`-rooted hrefs resolve identically via `/dir/` and `/dir`.
    let base = href_base(candidate, root);
    let mut body = String::from("<ul>\n");
    if candidate != root {
        // Absolute parent href: a relative `../` misses a level when the
        // listing was reached without its trailing slash (/a/b -> /).
        let parent = href_base(candidate.parent().unwrap_or(root), root);
        body.push_str(&format!("<li><a href=\"{parent}\">../</a></li>\n"));
    }
    for (name, is_dir) in &entries {
        let kind = if *is_dir { "dir" } else { "file" };
        let slash = if *is_dir { "/" } else { "" };
        let href = encode_href(name);
        let label = escape_html(name);
        body.push_str(&format!(
            "<li><a class=\"{kind}\" href=\"{base}{href}{slash}\">{label}{slash}</a></li>\n"
        ));
    }
    body.push_str("</ul>\n<hr>\n");
    Some(html_page(&title, &body))
}

/// Shared scaffold for the ft-owned origins' generated pages. Inputs must be
/// pre-escaped — the scaffold interpolates them raw.
pub(crate) fn html_page(escaped_title: &str, escaped_body: &str) -> String {
    format!(
        "<!DOCTYPE html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n\
         <title>{escaped_title}</title>\n\
         <style>body{{font-family:system-ui,sans-serif;max-width:42em;margin:2em auto;padding:0 1em}}\
         h1{{font-size:1.3em}}li{{list-style:none;padding:.15em 0}}\
         .dir{{font-weight:600}}</style>\n</head>\n<body>\n\
         <h1>{escaped_title}</h1>\n<hr>\n{escaped_body}</body>\n</html>\n"
    )
}

/// Title text for the listing, before HTML escaping: the request path, or `/`
/// for the root.
fn decoded_title(candidate: &Path, root: &Path) -> String {
    let rel = candidate.strip_prefix(root).unwrap_or(Path::new(""));
    if rel.as_os_str().is_empty() {
        return "/".to_string();
    }
    let title = format!("/{}", rel.to_string_lossy());
    // Windows separates with `\`; the title must show the `/` the hrefs use.
    #[cfg(windows)]
    let title = title.replace('\\', "/");
    title
}

/// Entry-href prefix: the directory as an absolute percent-encoded path with
/// a trailing `/`.
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

/// Percent-encode a name for an href (unreserved set plus `/`); shared with
/// `drop_server`'s listing.
pub(crate) fn encode_href(name: &str) -> String {
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

/// Minimal HTML text escaping; shared with `hook_server`'s inspector — all
/// external text passes through here before markup.
pub(crate) fn escape_html(s: &str) -> String {
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

/// Any decoded segment starting with `.` — refused EARLIER than ServeDir's
/// own `..` check; shared by [`confine`] and [`spa_fallback`] (no drift).
fn has_dot_segment(decoded: &str) -> bool {
    decoded
        .trim_start_matches('/')
        .split('/')
        .any(|seg| seg.starts_with('.'))
}

/// Rebuild the target under `root` exactly the way ServeDir resolves it;
/// one shared builder so every guard decides on the same candidate.
fn candidate_path(root: &Path, decoded: &str) -> PathBuf {
    let mut candidate = root.to_owned();
    for seg in decoded.trim_start_matches('/').split('/') {
        if !seg.is_empty() {
            candidate.push(seg);
        }
    }
    candidate
}

/// Confinement guard (normative site — `drop_server` shares it verbatim):
/// any dot segment 404s, and the canonicalised target must stay under the
/// root (`canonicalize` follows symlinks, so an escaping link no longer
/// `starts_with(root)`; missing paths fail canonicalize and 404 too). A
/// TOCTOU window remains before ServeDir's own open — closing it fully would
/// mean replacing ServeDir.
pub(crate) async fn confine(State(root): State<PathBuf>, request: Request, next: Next) -> Response {
    let raw = request.uri().path();
    let decoded = match percent_decode(raw.as_bytes()).decode_utf8() {
        Ok(s) => s,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    if has_dot_segment(&decoded) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let candidate = candidate_path(&root, &decoded);
    // All fs work in one spawn_blocking: confine is on the public-internet
    // hot path — no realpath/stat may block the runtime thread.
    let confined = tokio::task::spawn_blocking(move || confine_blocking(&candidate, &root))
        .await
        .unwrap_or(false);
    if !confined {
        return StatusCode::NOT_FOUND.into_response();
    }
    next.run(request).await
}

/// Blocking half of [`confine`] — also confines a directory's `index.html`
/// (it may itself be an escaping symlink).
fn confine_blocking(candidate: &Path, root: &Path) -> bool {
    let resolved = match std::fs::canonicalize(candidate) {
        Ok(r) => r,
        Err(_) => return false,
    };
    if !resolved.starts_with(root) {
        return false;
    }
    if resolved.is_dir() && escapes_root(&resolved.join("index.html"), root) {
        return false;
    }
    true
}

/// True if `path` exists and canonicalises to a target outside `root` —
/// confines the directory-index file in addition to the request path.
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

/// SPA fallback (`--spa`): rewrite a 404 for a genuinely non-existent,
/// dot-free path to the root `index.html` (client-side router deep links).
/// Sits OUTSIDE [`confine`] (see [`router_with`]) and re-checks: only
/// "nothing exists there" is rewritten — refusal 404s keep their meaning (no
/// escaping symlink laundered into a 200).
async fn spa_fallback(State(root): State<PathBuf>, request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let raw = request.uri().path().to_owned();
    let response = next.run(request).await;
    if response.status() != StatusCode::NOT_FOUND
        || (method != Method::GET && method != Method::HEAD)
    {
        return response;
    }
    let decoded = match percent_decode(raw.as_bytes()).decode_utf8() {
        Ok(s) => s,
        // Undecodable paths were refused by confine; never rewrite them.
        Err(_) => return response,
    };
    if has_dot_segment(&decoded) {
        return response;
    }
    let candidate = candidate_path(&root, &decoded);
    let shell = tokio::task::spawn_blocking(move || {
        // Resolves to something: its 404 was deliberate, not a miss to
        // paper over.
        if std::fs::canonicalize(&candidate).is_ok() {
            return None;
        }
        std::fs::read(root.join("index.html")).ok()
    })
    .await
    .unwrap_or(None);
    let Some(bytes) = shell else {
        return response;
    };
    let len = bytes.len();
    if method == Method::HEAD {
        let mut response = (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        )
            .into_response();
        response
            .headers_mut()
            .insert(header::CONTENT_LENGTH, HeaderValue::from(len));
        return response;
    }
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        bytes,
    )
        .into_response()
}

/// Token guard (`--token`): 401 for EVERY request (the origin's whole value
/// is its content) unless `Authorization: Bearer <secret>` or
/// `?token=<secret>` matches, constant-time; layered before confinement so a
/// 404-scanner cannot probe which paths exist.
async fn require_token(State(expected): State<String>, request: Request, next: Next) -> Response {
    let header_token = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(bearer_token)
        .map(str::to_owned);
    let query_token = request.uri().query().and_then(|q| query_param(q, "token"));
    let ok = header_token
        .or(query_token)
        .is_some_and(|t| tokens_match(&t, &expected));
    if !ok {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            "this static origin requires the access token (Authorization: Bearer or ?token=)\n",
        )
            .into_response();
    }
    next.run(request).await
}

/// Case-insensitive `Bearer` scheme match (RFC 7235). Byte-in-sync twin of
/// `drop_server::bearer_token`; keep the two in sync.
fn bearer_token(value: &str) -> Option<&str> {
    let (scheme, credentials) = value.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then_some(credentials)
}

/// First value of `key`, percent-decoded (a literal `+` stays a plus).
/// Byte-in-sync twin of `drop_server::query_param`; keep the two in sync.
fn query_param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        if k != key {
            return None;
        }
        percent_decode(v.as_bytes())
            .decode_utf8()
            .ok()
            .map(|d| d.into_owned())
    })
}

/// Constant-time compare (length folded in, no early return; empty expected
/// matches nothing). Twin of `drop_server::tokens_match`; keep in sync.
fn tokens_match(provided: &str, expected: &str) -> bool {
    if expected.is_empty() {
        return false;
    }
    let (a, b) = (provided.as_bytes(), expected.as_bytes());
    let mut diff = a.len() ^ b.len();
    for i in 0..a.len().max(b.len()) {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        diff |= usize::from(x ^ y);
    }
    diff == 0
}

/// Bind `127.0.0.1:port` and serve until Ctrl-C (graceful drain);
/// loopback-only — only the local cloudflared process should reach it.
pub async fn serve(router: Router, port: u16) -> crate::error::Result<()> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .with_context(|| format!("failed to bind 127.0.0.1:{port}"))?;
    serve_on(router, listener, async {
        // Also observed by the caller's ctrl_c(); this future only drives
        // axum's graceful shutdown.
        let _ = tokio::signal::ctrl_c().await;
    })
    .await
}

/// Serve on a pre-bound listener (the caller fails fast on a port conflict);
/// shutdown drains in-flight requests.
pub async fn serve_on(
    router: Router,
    listener: tokio::net::TcpListener,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> crate::error::Result<()> {
    // Loopback enforced on the type: a 0.0.0.0 listener would publish the
    // tree directly, bypassing the tunnel.
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
fn plain_router(dir: PathBuf) -> Router {
    router_with(dir, crate::model::StaticFlags::default())
}

#[cfg(test)]
mod confinement_tests {
    //! Logic-only checks; the full HTTP confinement lives in
    //! `http_confinement_tests`.
    use super::has_dot_segment;
    use std::path::Path;

    #[test]
    fn split_segments_drops_dotfiles_and_dots() {
        assert!(!has_dot_segment("index.html"));
        assert!(has_dot_segment(".env"));
        assert!(has_dot_segment(".git/config"));
        assert!(has_dot_segment("a/../b"));
        assert!(has_dot_segment("../etc/passwd"));
        assert!(!has_dot_segment("foo.html"));
    }

    #[test]
    fn root_is_under_itself() {
        let root = Path::new("/tmp/srv");
        assert!(root.join("a").starts_with(root));
        assert!(!Path::new("/etc/passwd").starts_with(root));
    }
}

#[cfg(test)]
mod http_confinement_tests {
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

        let r = plain_router(dir.path().to_path_buf());
        assert_eq!(r.oneshot(req("/")).await.unwrap().status(), StatusCode::OK);

        let r = plain_router(dir.path().to_path_buf());
        assert_eq!(
            r.oneshot(req("/sub/f.html")).await.unwrap().status(),
            StatusCode::OK
        );

        let r = plain_router(dir.path().to_path_buf());
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

        let r = plain_router(dir.path().to_path_buf());
        assert_eq!(
            r.oneshot(req("/.env")).await.unwrap().status(),
            StatusCode::NOT_FOUND
        );
        let r = plain_router(dir.path().to_path_buf());
        assert_eq!(
            r.oneshot(req("/.git/config")).await.unwrap().status(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn parent_dir_traversal_is_denied() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("index.html"), "hi").expect("write");

        let r = plain_router(dir.path().to_path_buf());
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
        let outside = tempfile::tempdir().expect("outside tempdir");
        std::fs::write(outside.path().join("secret"), "TOPSECRET").expect("write");
        std::fs::write(dir.path().join("index.html"), "ok").expect("write");
        symlink(outside.path().join("secret"), dir.path().join("link")).expect("symlink");

        let r = plain_router(dir.path().to_path_buf());
        assert_eq!(
            r.oneshot(req("/link")).await.unwrap().status(),
            StatusCode::NOT_FOUND,
            "a symlink escaping the root must not be served"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlink_escape_via_directory_index_is_blocked() {
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
            let r = plain_router(dir.path().to_path_buf());
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
        let r = plain_router(dir.path().to_path_buf());
        let resp = r.oneshot(req("/")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("x-content-type-options").unwrap(),
            "nosniff"
        );
    }

    /// Junctions are Windows' symlink analogue (canonicalize resolves them).
    #[cfg(windows)]
    #[tokio::test]
    async fn junction_escape_outside_root_is_blocked() {
        let dir = tempfile::tempdir().expect("tempdir");
        let outside = tempfile::tempdir().expect("outside tempdir");
        std::fs::write(outside.path().join("secret"), "TOPSECRET").expect("write");
        std::fs::write(dir.path().join("index.html"), "ok").expect("write");

        // Junction via cmd /J (no admin needed).
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

        let r = plain_router(dir.path().to_path_buf());
        assert_eq!(
            r.oneshot(req("/link")).await.unwrap().status(),
            StatusCode::NOT_FOUND,
            "a junction escaping the root must not be served"
        );
    }
}

#[cfg(test)]
mod listing_tests {
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

        let resp = plain_router(dir.path().to_path_buf())
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
        assert!(html.contains("href=\"/beta/\""), "{html}");
        let beta = html.find("beta/").expect("beta listed");
        let alpha = html.find("alpha.txt").expect("alpha listed");
        let zeta = html.find("zeta.txt").expect("zeta listed");
        assert!(beta < alpha, "directories must be listed before files");
        assert!(alpha < zeta, "files must be alphabetical");
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

        let resp = plain_router(dir.path().to_path_buf())
            .oneshot(req("GET", "/"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_of(resp).await, "<h1>root index</h1>");

        let resp = plain_router(dir.path().to_path_buf())
            .oneshot(req("GET", "/sub/"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_of(resp).await, "<h1>sub index</h1>");

        let resp = plain_router(dir.path().to_path_buf())
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

        let resp = plain_router(dir.path().to_path_buf())
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

        let resp = plain_router(dir.path().to_path_buf())
            .oneshot(req("GET", "/"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_of(resp).await;
        assert!(html.contains(">a b.txt</a>"), "{html}");
        assert!(html.contains(">amp&amp;and.txt</a>"), "{html}");
        assert!(html.contains(">sub dir/</a>"), "{html}");
        assert!(html.contains("href=\"/a%20b.txt\""), "{html}");
        assert!(html.contains("href=\"/amp%26and.txt\""), "{html}");
        assert!(html.contains("href=\"/eq%3Dsemi%3B.txt\""), "{html}");
        assert!(html.contains("href=\"/sub%20dir/\""), "{html}");

        let resp = plain_router(dir.path().to_path_buf())
            .oneshot(req("GET", "/sub%20dir/"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_of(resp).await;
        assert!(html.contains("Index of /sub dir"), "{html}");
        assert!(html.contains("href=\"/sub%20dir/inner.txt\""), "{html}");
        assert!(html.contains("<li><a href=\"/\">../</a></li>"), "{html}");
    }

    /// `<`/`>` are illegal in Windows filenames — Unix-only case.
    #[cfg(unix)]
    #[tokio::test]
    async fn names_with_angle_brackets_are_escaped_and_encoded() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("lt<gt>.txt"), "angled").expect("write");

        let resp = plain_router(dir.path().to_path_buf())
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

        for (uri, want) in [("/a%20b.txt", "spaced"), ("/amp%26and.txt", "ampered")] {
            let resp = plain_router(dir.path().to_path_buf())
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

        let resp = plain_router(dir.path().to_path_buf())
            .oneshot(req("GET", "/"))
            .await
            .expect("oneshot");
        let page = body_of(resp).await;

        let resp = plain_router(dir.path().to_path_buf())
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

        let resp = plain_router(dir.path().to_path_buf())
            .oneshot(req("HEAD", "/f.txt"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(body_of(resp).await.is_empty());
    }

    /// Unix-gated: `<`/`>` are illegal in Windows filenames.
    #[cfg(unix)]
    #[tokio::test]
    async fn listing_title_escapes_markup_in_directory_names() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(dir.path().join("x<h1 onx=y")).expect("mkdir");

        let resp = plain_router(dir.path().to_path_buf())
            .oneshot(req("GET", "/"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_of(resp).await;
        assert!(html.contains(">x&lt;h1 onx=y/</a>"), "{html}");

        let resp = plain_router(dir.path().to_path_buf())
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

        // Without the trailing slash a relative `../` would land on `/`.
        for uri in ["/a/b", "/a/b/"] {
            let resp = plain_router(dir.path().to_path_buf())
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

    #[cfg(unix)]
    #[tokio::test]
    async fn escaping_symlinks_are_hidden_from_listings() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().expect("tempdir");
        let outside = tempfile::tempdir().expect("outside tempdir");
        std::fs::write(outside.path().join("secret"), "TOPSECRET").expect("write");
        std::fs::write(dir.path().join("ok.txt"), "fine").expect("write");
        symlink(outside.path().join("secret"), dir.path().join("leak")).expect("symlink");

        let resp = plain_router(dir.path().to_path_buf())
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

        let resp = plain_router(dir.path().to_path_buf())
            .oneshot(req("POST", "/"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlink_to_an_inner_directory_is_listed_as_a_directory() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(dir.path().join("real")).expect("mkdir");
        std::fs::write(dir.path().join("real").join("inner.txt"), "x").expect("write");
        std::fs::write(dir.path().join("zfile.txt"), "z").expect("write");
        symlink("real", dir.path().join("alias")).expect("symlink");

        let resp = plain_router(dir.path().to_path_buf())
            .oneshot(req("GET", "/"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_of(resp).await;
        assert!(
            html.contains("<li><a class=\"dir\" href=\"/alias/\">alias/</a></li>"),
            "{html}"
        );
        let alias = html.find("alias/").expect("alias listed");
        let zfile = html.find("zfile.txt").expect("zfile listed");
        assert!(
            alias < zfile,
            "a symlinked directory must sort with directories: {html}"
        );

        let resp = plain_router(dir.path().to_path_buf())
            .oneshot(req("GET", "/alias/"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_of(resp).await;
        assert!(html.contains("Index of /alias"), "{html}");
        assert!(html.contains("href=\"/alias/inner.txt\""), "{html}");
    }

    /// Windows counterpart of the inner-directory junction/symlink case.
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

        let resp = plain_router(dir.path().to_path_buf())
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

    #[cfg(unix)]
    #[tokio::test]
    async fn broken_symlinks_are_hidden_from_listings() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("ok.txt"), "fine").expect("write");
        symlink("no-such-target", dir.path().join("dangling")).expect("symlink");

        let resp = plain_router(dir.path().to_path_buf())
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

#[cfg(test)]
mod origin_flags_tests {
    use super::*;
    use crate::model::StaticFlags;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    /// Mirrors what the worker builds from the persisted registry entry.
    fn flagged_router(dir: &Path, spa: bool, cors: bool, token: Option<&str>) -> Router {
        router_with(
            dir.to_path_buf(),
            StaticFlags {
                spa,
                cors,
                token: token.map(str::to_owned),
            },
        )
    }

    fn req(method: &str, uri: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .expect("build request")
    }

    fn req_with(method: &str, uri: &str, headers: &[(&str, &str)]) -> Request<Body> {
        let mut builder = Request::builder().method(method).uri(uri);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(Body::empty()).expect("build request")
    }

    async fn body_of(resp: Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("read body");
        String::from_utf8(bytes.to_vec()).expect("body is utf-8")
    }

    fn spa_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("index.html"), "SHELL").expect("write shell");
        std::fs::write(dir.path().join("asset.js"), "console.log(1)").expect("write asset");
        std::fs::create_dir(dir.path().join("posts")).expect("mkdir");
        std::fs::write(dir.path().join("posts").join("a.txt"), "a").expect("write post");
        dir
    }

    // --- --spa ----------------------------------------------------------------

    #[tokio::test]
    async fn spa_serves_the_shell_for_a_deep_link_and_keeps_real_files() {
        let dir = spa_dir();
        let app = flagged_router(dir.path(), true, false, None);

        let resp = app
            .clone()
            .oneshot(req("GET", "/settings/profile"))
            .await
            .expect("deep link");
        assert_eq!(resp.status(), StatusCode::OK, "deep link gets the shell");
        assert_eq!(body_of(resp).await, "SHELL");

        let resp = app
            .clone()
            .oneshot(req("GET", "/asset.js"))
            .await
            .expect("real asset");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_of(resp).await, "console.log(1)", "no rewrite");

        let resp = app
            .oneshot(req("HEAD", "/settings/profile"))
            .await
            .expect("HEAD deep link");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CONTENT_LENGTH).unwrap(),
            &HeaderValue::from("SHELL".len())
        );
        assert!(body_of(resp).await.is_empty());
    }

    #[tokio::test]
    async fn spa_without_a_root_index_keeps_the_404() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("real.txt"), "x").expect("write");
        let resp = flagged_router(dir.path(), true, false, None)
            .oneshot(req("GET", "/missing"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn spa_keeps_dotfiles_traversal_and_the_listing() {
        let dir = spa_dir();
        std::fs::write(dir.path().join(".env"), "SECRET=1").expect("plant dotfile");
        let app = flagged_router(dir.path(), true, false, None);

        for uri in ["/.env", "/posts/../.env", "/a/../b"] {
            let resp = app.clone().oneshot(req("GET", uri)).await.expect("oneshot");
            assert_eq!(
                resp.status(),
                StatusCode::NOT_FOUND,
                "{uri} must stay 404 under --spa"
            );
            assert_ne!(
                body_of(resp).await,
                "SHELL",
                "{uri} must never be answered with the shell"
            );
        }

        let resp = app
            .clone()
            .oneshot(req("GET", "/posts/"))
            .await
            .expect("listing");
        assert_eq!(resp.status(), StatusCode::OK, "listings still render");
        assert!(body_of(resp).await.contains("Index of /posts"));

        let resp = app
            .oneshot(req("GET", "/posts/a.txt"))
            .await
            .expect("nested file");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_of(resp).await, "a");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn spa_never_launders_an_escaping_symlink_into_the_shell() {
        use std::os::unix::fs::symlink;
        let dir = spa_dir();
        let outside = tempfile::tempdir().expect("outside");
        std::fs::write(outside.path().join("secret"), "TOPSECRET").expect("write");
        symlink(outside.path().join("secret"), dir.path().join("leak")).expect("symlink");

        let resp = flagged_router(dir.path(), true, false, None)
            .oneshot(req("GET", "/leak"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_ne!(body_of(resp).await, "SHELL");
    }

    // --- --cors ---------------------------------------------------------------

    #[tokio::test]
    async fn cors_headers_are_stamped_when_on_and_absent_when_off() {
        let dir = spa_dir();
        let on = flagged_router(dir.path(), false, true, None)
            .oneshot(req("GET", "/"))
            .await
            .expect("oneshot");
        assert_eq!(
            on.headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "*"
        );
        assert_eq!(
            on.headers()
                .get(header::ACCESS_CONTROL_ALLOW_METHODS)
                .unwrap(),
            "GET, HEAD, OPTIONS"
        );
        assert_eq!(
            on.headers()
                .get(header::ACCESS_CONTROL_ALLOW_HEADERS)
                .unwrap(),
            "*"
        );

        let off = flagged_router(dir.path(), false, false, None)
            .oneshot(req("GET", "/"))
            .await
            .expect("oneshot");
        assert!(
            !off.headers()
                .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN),
            "no CORS headers without --cors"
        );
    }

    #[tokio::test]
    async fn cors_stamps_error_responses_and_preflights_stay_unanswered() {
        let dir = spa_dir();
        let app = flagged_router(dir.path(), false, true, None);

        let resp = app
            .clone()
            .oneshot(req("GET", "/missing"))
            .await
            .expect("404");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            resp.headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "*",
            "errors carry the CORS headers too"
        );

        let resp = app.oneshot(req("OPTIONS", "/")).await.expect("OPTIONS");
        assert_eq!(
            resp.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "a preflight is not specially answered"
        );
        assert_eq!(
            resp.headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "*"
        );
    }

    // --- --token --------------------------------------------------------------

    #[tokio::test]
    async fn token_is_required_by_header_or_query_and_401s_otherwise() {
        let dir = spa_dir();
        let app = flagged_router(dir.path(), false, false, Some("sekrit"));

        for method in ["GET", "HEAD", "POST", "OPTIONS"] {
            let resp = app
                .clone()
                .oneshot(req(method, "/asset.js"))
                .await
                .expect("no token");
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{method} ungated");
            assert_eq!(
                resp.headers().get(header::WWW_AUTHENTICATE).unwrap(),
                "Bearer"
            );
        }

        let resp = app
            .clone()
            .oneshot(req_with(
                "GET",
                "/asset.js",
                &[("authorization", "Bearer sekrit")],
            ))
            .await
            .expect("bearer");
        assert_eq!(resp.status(), StatusCode::OK, "valid Bearer passes");

        let resp = app
            .clone()
            .oneshot(req("GET", "/asset.js?token=sekrit"))
            .await
            .expect("query token");
        assert_eq!(resp.status(), StatusCode::OK, "valid ?token= passes");

        let resp = app
            .clone()
            .oneshot(req_with(
                "GET",
                "/asset.js",
                &[("authorization", "Bearer wrong")],
            ))
            .await
            .expect("wrong bearer");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "wrong Bearer");

        let resp = app
            .oneshot(req("GET", "/asset.js?token=wrong"))
            .await
            .expect("wrong query token");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "wrong ?token=");
    }

    #[tokio::test]
    async fn bearer_scheme_matches_case_insensitively_per_rfc_7235() {
        let dir = spa_dir();
        let app = flagged_router(dir.path(), false, false, Some("sekrit"));
        for scheme in ["bearer", "BEARER", "BeArEr"] {
            let resp = app
                .clone()
                .oneshot(req_with(
                    "GET",
                    "/asset.js",
                    &[("authorization", &format!("{scheme} sekrit"))],
                ))
                .await
                .expect("oneshot");
            assert_eq!(resp.status(), StatusCode::OK, "scheme {scheme} must pass");
        }
        let resp = app
            .clone()
            .oneshot(req_with(
                "GET",
                "/asset.js",
                &[("authorization", "BEARER SEKRIT")],
            ))
            .await
            .expect("oneshot");
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "the credentials stay case-sensitive"
        );
        let resp = app
            .oneshot(req_with(
                "GET",
                "/asset.js",
                &[("authorization", "basic sekrit")],
            ))
            .await
            .expect("oneshot");
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "a different scheme never carries the token"
        );
    }

    #[tokio::test]
    async fn token_gates_before_confinement_so_the_tree_cannot_be_probed() {
        let dir = spa_dir();
        std::fs::write(dir.path().join(".env"), "SECRET=1").expect("plant dotfile");
        let app = flagged_router(dir.path(), true, false, Some("sekrit"));

        let resp = app
            .clone()
            .oneshot(req("GET", "/.env"))
            .await
            .expect("unauthenticated probe");
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "a dotfile probe without the token must 401, not 404"
        );

        let resp = app
            .clone()
            .oneshot(req_with(
                "GET",
                "/.env",
                &[("authorization", "Bearer sekrit")],
            ))
            .await
            .expect("authenticated probe");
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "confinement still denies the dotfile for a valid bearer"
        );

        let resp = app
            .clone()
            .oneshot(req("GET", "/settings/profile?token=sekrit"))
            .await
            .expect("spa + query token");
        assert_eq!(resp.status(), StatusCode::OK, "deep link with ?token=");
        assert_eq!(body_of(resp).await, "SHELL");

        let resp = app
            .oneshot(req("GET", "/settings/profile"))
            .await
            .expect("spa without token");
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "the shell itself is gated too"
        );
    }

    #[test]
    fn tokens_match_is_exact_and_constant_time_shaped() {
        let m = |p: &str, e: &str| super::tokens_match(p, e);
        assert!(m("sekrit", "sekrit"));
        assert!(!m("sekriT", "sekrit"), "one differing byte is enough");
        assert!(!m("sekri", "sekrit"), "shorter never matches");
        assert!(!m("sekritlonger", "sekrit"), "longer never matches");
        assert!(!m("", "sekrit"), "nothing provided never matches");
        assert!(!m("sekrit", ""), "an unconfigured token matches nothing");
    }
}
