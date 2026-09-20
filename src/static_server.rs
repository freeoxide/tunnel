//! Static file server.
//!
//! Serves the contents of a directory over HTTP on the loopback interface
//! using [`tower_http::services::ServeDir`], fronted by a confinement guard
//! and a [`TraceLayer`]. Only `127.0.0.1` is ever bound — the public surface
//! is the cloudflared tunnel. A directory with no `index.html` of its own is
//! answered with a generated HTML listing (see [`serve_or_list`]) instead of
//! a 404.
//!
//! # Confinement
//!
//! Because cloudflared publishes whatever this server returns to the public
//! internet, the [`confine`] guard (run before ServeDir) enforces three
//! rules:
//!
//! - **dotfiles are denied** — any path segment beginning with `.` (`.env`,
//!   `.git/config`, `.`, `..`) 404s by default.
//! - **symlink escape is blocked** — each request's resolved path is
//!   canonicalised and must remain under the canonical root (symlinks that
//!   resolve *inside* the root are still served).
//! - **`..` traversal is rejected** — belt-and-suspenders alongside the same
//!   check ServeDir already performs.
//!
//! # Static-origin flags (`--spa` / `--cors` / `--token`)
//!
//! [`router_with`] takes a [`crate::model::StaticFlags`] value (persisted on
//! the registry entry, so the detached worker re-applies it):
//!
//! - **`--spa`** — the [`spa_fallback`] middleware rewrites a 404 to the root
//!   `index.html` (client-side router deep links). It sits OUTSIDE `confine`
//!   (a missing path is itself confined to a 404, so a fallback inside the
//!   guard could never see one) and re-checks the path itself: only a
//!   genuinely non-existent, dot-free path becomes the app shell — refusal
//!   404s keep their meaning, and a root without an `index.html` keeps the
//!   honest 404.
//! - **`--cors`** — permissive CORS headers (`Access-Control-Allow-Origin: *`,
//!   methods GET/HEAD/OPTIONS, wildcard request headers) stamped on every
//!   response, errors included. Preflight OPTIONS is deliberately NOT
//!   answered with a success status: only a CORS-simple request skips the
//!   preflight, while a GET/HEAD carrying a non-safelisted header (e.g.
//!   `Authorization`) DOES preflight — and this origin 405s every OPTIONS,
//!   so the browser never fires that request. With `--token`, cross-origin
//!   Bearer auth therefore can never work; the unanswered preflight is
//!   preferred to faking an allowance.
//! - **`--token`** — the [`require_token`] guard answers 401 for EVERY
//!   request (GET/HEAD included — the static origin's whole value is its
//!   content, so there is no safe unauthenticated subset) unless
//!   `Authorization: Bearer <secret>` or `?token=<secret>` matches, compared
//!   in constant time. It layers OUTSIDE `confine` so a 404-scanner learns
//!   nothing about the tree without the token. The Bearer header is the
//!   safer transport (query strings leak into shell history and client
//!   logs); the query value is percent-decoded, so a secret containing `%`
//!   or `+` authenticates via the header in exactly its written form.

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

/// Build an axum [`Router`] that serves `dir` at `/` with HTTP tracing and the
/// given static-origin flags applied. The directory contents map directly
/// onto the root path; the root is canonicalised so the confinement guard has
/// a stable base.
///
/// Layers are applied innermost-first (the LAST `.layer()` is the outermost):
/// serve_or_list in front of the ServeDir fallback, then confine, then the
/// optional spa_fallback (outside confine — it must see missing-path 404s),
/// TraceLayer, the optional [`require_token`] guard (outside confinement, so
/// a 404-scanner cannot probe the tree), the optional CORS stamping (above
/// the token guard so even a 401 carries the headers), nosniff, the body
/// limit, and TimeoutLayer bounding slow clients and the graceful drain.
pub fn router_with(dir: PathBuf, flags: crate::model::StaticFlags) -> Router {
    let root = std::fs::canonicalize(&dir).unwrap_or(dir);
    let crate::model::StaticFlags { spa, cors, token } = flags;
    // axum 0.8 removed `nest_service("/")`; the directory as the fallback
    // service covers every path (index.html at `/`, files beneath it, 404 for
    // the rest), with serve_or_list rendering listings for index-less
    // directories.
    let mut router = Router::new()
        .fallback_service(ServeDir::new(root.clone()))
        .layer(from_fn_with_state(root.clone(), serve_or_list))
        .layer(from_fn_with_state(root.clone(), confine));
    // SPA sits OUTSIDE confine: confine 404s non-existent paths itself (its
    // canonicalize fails on them), so a fallback inside the guard would never
    // observe the deep-link 404s it exists to rewrite.
    if spa {
        router = router.layer(from_fn_with_state(root.clone(), spa_fallback));
    }
    router = router.layer(TraceLayer::new_for_http());
    // Auth before confinement: an unauthenticated 404-scanner cannot use the
    // 404/200 distinction to probe which paths exist.
    if let Some(expected) = token {
        router = router.layer(from_fn_with_state(expected, require_token));
    }
    // Layered ABOVE the token guard so every response — 200s, 404s, 401s
    // alike — carries the headers.
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
            // Wildcard request headers (no credentials are ever allowed with
            // an `*` origin, so the wildcard is safe).
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
            StatusCode::REQUEST_TIMEOUT, // 408 — client took too long
            REQUEST_TIMEOUT,
        ))
}

/// Listing middleware, layered between the [`confine`] guard and the
/// `ServeDir` fallback: when the request resolves to a directory with no
/// `index.html`, answer with an HTML listing instead of letting ServeDir 404.
/// The listing hides entries the guard would refuse to serve (dotfiles,
/// escaping/broken symlinks), and its filesystem reads run in
/// `spawn_blocking`.
async fn serve_or_list(State(root): State<PathBuf>, request: Request, next: Next) -> Response {
    // GET/HEAD only: anything else defers to ServeDir's uniform 405, so a
    // listing behaves like a file under the same method.
    let method = request.method();
    if method != Method::GET && method != Method::HEAD {
        return next.run(request).await;
    }
    let is_head = method == Method::HEAD;
    let raw = request.uri().path();
    // Decode and rebuild the candidate through the guard's shared
    // [`candidate_path`] helper so the listing decision is made on the same
    // path everyone else resolves.
    let decoded = match percent_decode(raw.as_bytes()).decode_utf8() {
        Ok(s) => s,
        // Undecodable paths are refused by `confine` first; if one reaches us
        // anyway, let ServeDir decide its fate.
        Err(_) => return next.run(request).await,
    };
    let candidate = candidate_path(&root, &decoded);

    let listing = tokio::task::spawn_blocking(move || render_listing(&candidate, &root))
        .await
        .unwrap_or(None);
    match listing {
        Some(html) => {
            // A HEAD mirrors the GET representation's headers (truthful
            // Content-Length) but carries no body, like ServeDir's.
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
        // Not a listable directory (a file, a directory with an index.html,
        // or a missing path): defer to ServeDir's semantics.
        None => next.run(request).await,
    }
}

/// Blocking half of [`serve_or_list`]: if `candidate` is a directory under
/// `root` with no `index.html`, return a rendered HTML listing of it; else
/// `None` so the request falls through to `ServeDir`. Runs inside
/// `spawn_blocking` — every syscall (realpath, stat, read_dir) happens off
/// the async worker threads.
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
        // Non-UTF-8 filenames render lossily and their hrefs 404 on fetch;
        // tolerated in a dev-facing listing.
        let name = entry.file_name().to_string_lossy().into_owned();
        // Hide dotfiles: confine refuses to serve them, so listing them
        // would only advertise 404 links (and leak names such as `.env`).
        if name.starts_with('.') {
            continue;
        }
        // Resolve through symlinks once: a target outside the root is hidden
        // (the guard 404s it anyway), so is an unresolvable one (a dead
        // link); the resolution also gives the entry's real kind (a symlink
        // to an inner directory is listed as a directory).
        let target = match std::fs::canonicalize(entry.path()) {
            Ok(target) if target.starts_with(root) => target,
            _ => continue,
        };
        entries.push((name, target.is_dir()));
    }
    // Directories first, each group alphabetical.
    entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    // The title is filesystem-derived, so it is escaped exactly like the
    // entry labels (the `Index of ` prefix carries no markup).
    let title = escape_html(&format!("Index of {}", decoded_title(candidate, root)));
    // Hrefs are `/`-rooted rather than `./`-relative so they resolve the
    // same whether the listing was reached as `/dir/` or `/dir`.
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

/// The shared HTML page scaffold behind the ft-owned origins' generated views
/// (the static directory listing, the hook inspector). One wrapper so every
/// generated page keeps the same styling.
///
/// `escaped_title` and `escaped_body` must already be HTML-escaped by the
/// caller: the scaffold interpolates them raw, so the escaping responsibility
/// stays with the code deriving text from filesystem/request data — a
/// double-escape bug is visible, a missed escape would be an injection.
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
    // Windows separates components with `\`; the title must show the `/` the
    // hrefs use (on Unix a `\` is an ordinary filename character).
    #[cfg(windows)]
    let title = title.replace('\\', "/");
    title
}

/// Prefix for the listing's entry hrefs: the requested directory as an
/// absolute, percent-encoded path with a trailing `/` (just `/` for the
/// root).
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

/// Percent-encode a name for use in an href: keep the unreserved set plus
/// `/`, encode everything else. Shared with [`crate::drop_server`], whose
/// listing renders upload names into the same scaffold.
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

/// Minimal HTML text escaping for markup. Shared with
/// [`crate::hook_server`], whose inspector renders request-derived text —
/// any text from outside must pass through here before touching markup.
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

/// True when any percent-decoded path segment begins with `.`: dotfiles,
/// dot-directories, self (`.`), and parent (`..`). ServeDir already blocks
/// `..`; the guard blocks every dot segment EARLIER (defense in depth) and
/// adds the dotfile default ServeDir lacks. Shared by [`confine`] and the
/// SPA fallback so the refusal policy cannot drift.
fn has_dot_segment(decoded: &str) -> bool {
    decoded
        .trim_start_matches('/')
        .split('/')
        .any(|seg| seg.starts_with('.'))
}

/// Rebuild the request's target under `root` exactly the way ServeDir
/// resolves it (percent-decode, drop the leading `/`, split on `/`, push
/// every non-empty segment). One shared builder guarantees [`confine`],
/// [`serve_or_list`], and [`spa_fallback`] decide on literally the same
/// candidate.
fn candidate_path(root: &Path, decoded: &str) -> PathBuf {
    let mut candidate = root.to_owned();
    for seg in decoded.trim_start_matches('/').split('/') {
        if !seg.is_empty() {
            candidate.push(seg);
        }
    }
    candidate
}

/// Confinement guard: deny dotfiles, reject `..` traversal, and refuse any
/// path whose canonicalised target escapes the served root (symlink escape —
/// `canonicalize` follows symlinks to the real target, so an escaping link no
/// longer `starts_with(root)`; missing paths also fail canonicalize and 404,
/// as ServeDir would).
///
/// Shared verbatim with [`crate::drop_server`]: the drop bucket's GET side
/// must behave exactly like the static server's.
///
/// All filesystem syscalls run inside [`tokio::task::spawn_blocking`]:
/// `confine` is on the hot path proxied from the public internet, and
/// blocking realpath/stat calls on the runtime thread are the documented
/// std::fs-in-async anti-pattern.
///
/// Note: a TOCTOU window remains between this canonicalise and ServeDir's own
/// open; closing it fully would mean replacing ServeDir. For a dev tunneling
/// tool the guard defeats the realistic threat (symlinks already present in
/// the tree) and keeps ServeDir's HTTP semantics (ranges, ETag, index.html).
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
    // One spawn_blocking for all the fs work (candidate canonicalize, is_dir,
    // and the index.html confinement check) — no realpath/stat touches the
    // runtime thread.
    let confined = tokio::task::spawn_blocking(move || confine_blocking(&candidate, &root))
        .await
        .unwrap_or(false);
    if !confined {
        return StatusCode::NOT_FOUND.into_response();
    }
    next.run(request).await
}

/// Blocking half of [`confine`]: resolves `candidate`, requires it to stay
/// under `root`, and — when it is a directory — also confines the
/// `index.html` ServeDir resolves on its own (that index may itself be an
/// escaping symlink). `true` = safe to forward, `false` = 404.
fn confine_blocking(candidate: &Path, root: &Path) -> bool {
    let resolved = match std::fs::canonicalize(candidate) {
        Ok(r) => r,
        Err(_) => return false,
    };
    if !resolved.starts_with(root) {
        return false;
    }
    // ServeDir serves `<dir>/index.html` for directory requests; that index
    // may itself be a symlink escaping the root — confine it too.
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
/// dot-free path to the root `index.html`, so client-side router deep links
/// (`/settings/profile`) get the app shell instead of a 404.
///
/// Layered OUTSIDE [`confine`] (which 404s missing paths itself — a fallback
/// inside the guard could never see them) and therefore re-checking the path
/// so the guard's refusals keep their meaning: dot segments keep their 404
/// (never a dotfile-detection oracle), a path that canonicalises to SOMETHING
/// keeps its 404 (only "nothing exists there" is rewritten — an escaping
/// symlink must not be laundered into a 200), and a root without an
/// `index.html` keeps the honest 404 (never a 500). GET/HEAD-only; HEAD
/// mirrors the GET headers with an empty body. Fs syscalls run in one
/// `spawn_blocking`.
async fn spa_fallback(State(root): State<PathBuf>, request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let raw = request.uri().path().to_owned();
    let response = next.run(request).await;
    if response.status() != StatusCode::NOT_FOUND
        || (method != Method::GET && method != Method::HEAD)
    {
        return response;
    }
    // Rebuild the candidate through the guard's shared helpers so the
    // fallback decides on the same path confine and ServeDir resolved.
    let decoded = match percent_decode(raw.as_bytes()).decode_utf8() {
        Ok(s) => s,
        // Undecodable paths were refused by confine; never rewrite them.
        Err(_) => return response,
    };
    // Same rule as the guard: a dot segment is a refusal, and a refusal must
    // not turn into the app shell.
    if has_dot_segment(&decoded) {
        return response;
    }
    let candidate = candidate_path(&root, &decoded);
    let shell = tokio::task::spawn_blocking(move || {
        // The path resolves to something (inside or outside the root): its
        // 404 was a deliberate confinement/ServeDir answer, not a miss to
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

/// Token guard (`--token`): answer 401 for EVERY request that does not carry
/// the configured secret — `Authorization: Bearer <secret>` or
/// `?token=<secret>`, constant-time compared — before the request reaches
/// confinement, the listing, or ServeDir. All methods (unlike the drop
/// bucket's mutation-only gate) because the static origin's whole value is
/// its content; before confinement so a 404-scanner cannot use the 404/200
/// distinction to learn which paths exist.
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

/// Extract the credentials after a case-insensitive `Bearer` scheme match
/// (RFC 7235: auth schemes are case-insensitive; the credentials are not).
/// Byte-in-sync twin of `drop_server::bearer_token`; keep the two in sync.
fn bearer_token(value: &str) -> Option<&str> {
    let (scheme, credentials) = value.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then_some(credentials)
}

/// Extract the first value of `key` from a raw query string, percent-decoded
/// (a literal `+` stays a plus — no form-encoding convention). Byte-in-sync
/// twin of `drop_server::query_param`; keep the two in sync.
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

/// Constant-time token comparison: XOR-folds every byte AND the length
/// difference into one accumulator, so there is no early return on a
/// mismatching byte or a length mismatch. Work still scales with the longer
/// input, so a length *class* leaks, as with any looped compare. An empty
/// configured token matches nothing (an empty secret must never open the
/// origin). Byte-in-sync twin of `drop_server::tokens_match`; keep the two
/// in sync.
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

/// Bind `router` to `127.0.0.1:port` and serve until Ctrl-C; shutdown is
/// graceful (drain in-flight requests). Loopback-only on purpose: only the
/// local cloudflared process should reach this server.
pub async fn serve(router: Router, port: u16) -> crate::error::Result<()> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .with_context(|| format!("failed to bind 127.0.0.1:{port}"))?;
    serve_on(router, listener, async {
        // A Ctrl-C here is also observed by the caller's own ctrl_c() await;
        // this future only drives axum's graceful shutdown.
        let _ = tokio::signal::ctrl_c().await;
    })
    .await
}

/// Serve on an already-bound listener (the caller binds and fails fast on a
/// port conflict before spawning the tunnel). On shutdown, axum stops
/// accepting and drains in-flight requests — none are dropped mid-flight.
pub async fn serve_on(
    router: Router,
    listener: tokio::net::TcpListener,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> crate::error::Result<()> {
    // Enforce loopback-only on the type, not by convention: a 0.0.0.0 listener
    // would publish the served tree directly, bypassing the tunnel-only
    // surface.
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

/// The no-flags router the bulk of the HTTP tests exercise — [`router_with`]
/// under its default arm, kept under a short local name since the production
/// entry point now always carries the flags.
#[cfg(test)]
fn plain_router(dir: PathBuf) -> Router {
    router_with(dir, crate::model::StaticFlags::default())
}

#[cfg(test)]
mod confinement_tests {
    //! Logic-only checks for the path decisions inside `confine`. Full HTTP
    //! confinement (symlink escape, dotfiles, traversal, junction) is exercised
    //! inline in `http_confinement_tests` below.
    use super::has_dot_segment;
    use std::path::Path;

    #[test]
    fn split_segments_drops_dotfiles_and_dots() {
        // The refusal predicate itself, not a mirror of it: any '.'-prefixed
        // segment is a refusal.
        assert!(!has_dot_segment("index.html"));
        assert!(has_dot_segment(".env"));
        assert!(has_dot_segment(".git/config"));
        assert!(has_dot_segment("a/../b"));
        assert!(has_dot_segment("../etc/passwd"));
        // A literal '.html' filename segment does NOT start with '.', so it is
        // fine (only a leading dot of the *segment* is refused).
        assert!(!has_dot_segment("foo.html"));
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

    /// Windows: a directory junction pointing outside the served root is
    /// confined like a Unix symlink (canonicalize resolves junctions).
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
        let resp = plain_router(dir.path().to_path_buf())
            .oneshot(req("GET", "/"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_of(resp).await, "<h1>root index</h1>");

        // A subdirectory with its own index.html serves it too...
        let resp = plain_router(dir.path().to_path_buf())
            .oneshot(req("GET", "/sub/"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_of(resp).await, "<h1>sub index</h1>");

        // ...while a sibling directory without one still gets a listing,
        // including the ../ parent link.
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

    /// `<` and `>` are HTML-significant but illegal in Windows filenames, so
    /// the angle-bracket case is exercised on Unix only.
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

        // The hrefs the listing advertises must round-trip as real requests.
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

        // The listing's GET representation, for the Content-Length check.
        let resp = plain_router(dir.path().to_path_buf())
            .oneshot(req("GET", "/"))
            .await
            .expect("oneshot");
        let page = body_of(resp).await;

        // Listing path: same status/type, the GET representation's true
        // Content-Length, and an empty body.
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

        // File path (ServeDir) still answers HEAD headers-only.
        let resp = plain_router(dir.path().to_path_buf())
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
        let resp = plain_router(dir.path().to_path_buf())
            .oneshot(req("GET", "/"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_of(resp).await;
        assert!(html.contains(">x&lt;h1 onx=y/</a>"), "{html}");

        // ...and the directory's own listing escapes the title/h1 built from
        // its name.
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

        // The regression case: WITHOUT the trailing slash, a relative ../
        // would land on `/`; the absolute href must name `/a/` in both forms.
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

        // ServeDir answers non-GET/HEAD with 405; the listing must not turn
        // a POST to a directory into a 200.
        let resp = plain_router(dir.path().to_path_buf())
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
        // It sorts into the directory group, before files.
        let alias = html.find("alias/").expect("alias listed");
        let zfile = html.find("zfile.txt").expect("zfile listed");
        assert!(
            alias < zfile,
            "a symlinked directory must sort with directories: {html}"
        );

        // And the link is real: its own listing renders through the alias.
        let resp = plain_router(dir.path().to_path_buf())
            .oneshot(req("GET", "/alias/"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_of(resp).await;
        assert!(html.contains("Index of /alias"), "{html}");
        assert!(html.contains("href=\"/alias/inner.txt\""), "{html}");
    }

    /// Windows counterpart: a junction to an inner directory is listed as a
    /// directory too.
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

    /// A broken symlink advertises a link that 404s — same rationale as the
    /// escaping-symlink filter, so it is hidden as well.
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
    //! The `--spa` / `--cors` / `--token` static-origin flags, driven through
    //! the real `router_with` with tower::oneshot (the established
    //! no-cloudflared HTTP-layer pattern).
    use super::*;
    use crate::model::StaticFlags;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    /// A router over `dir` with the given flags, mirroring what the worker
    /// builds from the persisted registry entry.
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

    /// A served tree with an SPA-style app: a root `index.html` shell, a real
    /// asset, and a subdirectory (no index of its own → listing territory).
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
        // The SPA contract: unmatched paths fall back to the root index.html;
        // real files are served untouched.
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

        // HEAD mirrors the GET representation headers-only (the listing's
        // HEAD discipline).
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
        // No index.html: the honest 404 — never a 500, never a rewrite to a
        // non-existent file.
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
        // The rewrite must not break the disciplines: dotfiles and `..` stay
        // 404 (never the shell), and index-less directories still render the
        // listing instead of being swallowed by the fallback.
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

        // An existing real file inside a nested dir is still served (not
        // rewritten, not listing-redirected).
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
        // The adversarial case for "canonicalize succeeded → keep the 404":
        // the fallback must not turn a confinement refusal into a 200 shell.
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
        // The documented choice: OPTIONS reaches ServeDir's uniform 405, and
        // the headers ride even that 405 and 404s — a uniform cross-origin
        // story rather than a fake-2xx preflight.
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
        // The auth contract: every method is gated; the token passes via
        // `Authorization: Bearer` OR `?token=`; wrong and missing both 401
        // with the WWW-Authenticate scheme advertised.
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
        // RFC 7235: the auth SCHEME is case-insensitive (`bearer <secret>`
        // must pass); the credentials themselves stay case-sensitive.
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
        // Without a token even a dotfile path reads 401 (no 404-scanning
        // oracle); with one, confinement refusals keep their meaning and
        // --spa deep links still work for the bearer.
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
        // No early return on a mismatching byte or length difference (the
        // accumulator folds both); an empty configured token matches nothing.
        let m = |p: &str, e: &str| super::tokens_match(p, e);
        assert!(m("sekrit", "sekrit"));
        assert!(!m("sekriT", "sekrit"), "one differing byte is enough");
        assert!(!m("sekri", "sekrit"), "shorter never matches");
        assert!(!m("sekritlonger", "sekrit"), "longer never matches");
        assert!(!m("", "sekrit"), "nothing provided never matches");
        assert!(!m("sekrit", ""), "an unconfigured token matches nothing");
    }
}
