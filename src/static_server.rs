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
//!
//! # Static-origin flags (`--spa` / `--cors` / `--token`)
//!
//! [`router_with`] takes a [`crate::model::StaticFlags`] value (persisted on
//! the registry entry, so the detached worker re-applies what the operator
//! asked for):
//!
//! - **`--spa`** — the [`spa_fallback`] middleware rewrites a 404 to the root
//!   `index.html` (client-side router deep links). It sits OUTSIDE `confine`
//!   (a missing path is itself confined to a 404, so a fallback inside the
//!   guard could never see one) and re-checks the path itself before
//!   rewriting: only a genuinely non-existent, dot-free path becomes the app
//!   shell. Dotfiles/`..` keep their 404, symlink escapes keep their 404, an
//!   existing-but-refused path keeps its 404, and a root without an
//!   `index.html` keeps the honest 404 instead of erroring.
//! - **`--cors`** — permissive CORS headers (`Access-Control-Allow-Origin: *`,
//!   methods GET/HEAD/OPTIONS, wildcard request headers) stamped on every
//!   response via `SetResponseHeaderLayer`, errors included. Preflight OPTIONS
//!   is deliberately NOT answered with a success status. The trade-off, stated
//!   exactly: only a CORS-simple request skips the preflight — a GET/HEAD whose
//!   headers are all CORS-safelisted — while a GET/HEAD carrying a
//!   non-safelisted header (e.g. `Authorization`) DOES preflight, and since
//!   this origin 405s every OPTIONS like any non-GET/HEAD, the browser never
//!   fires that authenticated request. So with `--token` (below), cross-origin
//!   Bearer auth can never work; the unanswered preflight is preferred to
//!   faking an allowance.
//! - **`--token`** — the [`require_token`] guard answers 401 for EVERY request
//!   (GET/HEAD included — unlike the drop bucket's mutation-only gate, the
//!   static origin's whole value is its content, so there is no safe
//!   unauthenticated subset) unless `Authorization: Bearer <secret>` or
//!   `?token=<secret>` matches, compared in constant time. It layers OUTSIDE
//!   `confine` so a 404-scanner learns nothing about the tree (not even which
//!   paths 404) without the token; `WWW-Authenticate: Bearer` advertises the
//!   scheme. The Bearer header is the safer transport (query strings leak into
//!   shell history and client logs), and because the query value is
//!   percent-decoded, a secret containing `%` or `+` authenticates via the
//!   header in exactly its written form — prefer the header for such secrets.

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
/// given static-origin flags (`--spa`/`--cors`/`--token`) applied.
///
/// The directory contents are mapped directly onto the root path, so a
/// request to `/foo.html` resolves to `dir/foo.html`. The root is canonicalised
/// (symlinks resolved) so the confinement guard has a stable base to confine
/// against.
///
/// Layers are applied innermost-first, so the LAST `.layer()` is the
/// outermost: TimeoutLayer wraps everything (bounding slow clients and the
/// graceful-drain), RequestBodyLimitLayer caps the body before ServeDir runs,
/// SetResponseHeaderLayer stamps `nosniff` on every response, the optional
/// CORS stamping sits above the token guard so even a 401 carries the CORS
/// headers, the optional [`require_token`] guard runs next (outside
/// confinement — see the module docs for why), TraceLayer observes the
/// response, the optional [`spa_fallback`] rewrite sits outside `confine`,
/// the [`confine`] guard runs next, and the [`serve_or_list`] listing
/// middleware is the innermost layer — it sits just in front of the
/// `ServeDir` fallback and either answers a directory with a listing or hands
/// the request over untouched.
pub fn router_with(dir: PathBuf, flags: crate::model::StaticFlags) -> Router {
    // Canonicalise the root so (a) symlinked roots resolve to their real target
    // and (b) the confinement guard compares against a stable, absolute base.
    let root = std::fs::canonicalize(&dir).unwrap_or(dir);
    let crate::model::StaticFlags { spa, cors, token } = flags;
    // axum 0.8 removed `nest_service("/")` ("nesting at the root is no longer
    // supported"). Serving the directory as the fallback service covers every
    // path: `index.html` at `/`, the matching file beneath it elsewhere, and a
    // 404 for anything missing. The serve_or_list middleware layered in front
    // of it additionally renders a directory listing for a directory that has
    // no `index.html` (see [`serve_or_list`]).
    let mut router = Router::new()
        .fallback_service(ServeDir::new(root.clone()))
        .layer(from_fn_with_state(root.clone(), serve_or_list))
        .layer(from_fn_with_state(root.clone(), confine));
    // SPA sits OUTSIDE confine: confine itself 404s non-existent paths (its
    // canonicalize fails on them), so a fallback layered inside the guard
    // would never observe the deep-link 404s it exists to rewrite. The
    // fallback re-checks the path itself before rewriting (see spa_fallback).
    if spa {
        router = router.layer(from_fn_with_state(root.clone(), spa_fallback));
    }
    router = router.layer(TraceLayer::new_for_http());
    // The token guard sits beside — and outside — the confinement middleware:
    // auth before confinement means an unauthenticated 404-scanner cannot use
    // the 404/200 distinction to probe which paths exist.
    if let Some(expected) = token {
        router = router.layer(from_fn_with_state(expected, require_token));
    }
    // CORS stamping is layered ABOVE the token guard (later layer = outer) so
    // every response of the origin — 200s, 404s, and 401s alike — carries the
    // headers, keeping the origin's cross-origin story uniform.
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
    // must not inject. The literal `Index of ` prefix carries no markup and
    // is prepended after escaping.
    let title = escape_html(&format!("Index of {}", decoded_title(candidate, root)));
    // Entry hrefs are rooted at `/` rather than `./`-relative so they resolve
    // identically whether the listing was reached as `/dir/` or `/dir` (for
    // files ServeDir answers the latter with a trailing-slash redirect; for
    // listings both forms are rendered directly).
    let base = href_base(candidate, root);
    let mut body = String::from("<ul>\n");
    if candidate != root {
        // Absolute parent href: a relative `../` resolves against the
        // listing's URL, which misses a level when the listing was reached
        // without its trailing slash (/a/b -> / instead of /a/).
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
/// (the static directory listing here, and the hook inspector in
/// [`crate::hook_server`]). One wrapper so every generated page keeps the
/// exact same styling — the body/max-width/h1/li rules are the visual
/// contract shared by all of them.
///
/// `escaped_title` (rendered into both `<title>` and `<h1>`) and
/// `escaped_body` (everything between the `<hr>` and `</body>`) must already
/// be HTML-escaped by the caller: the scaffold interpolates them raw, so the
/// escaping responsibility stays with the code that derives text from
/// filesystem or request data (that is also why this takes pre-escaped input
/// rather than escaping internally — a double-escape bug is visible, while a
/// missed escape would be an injection).
pub(crate) fn html_page(escaped_title: &str, escaped_body: &str) -> String {
    format!(
        "<!DOCTYPE html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n\
         <title>{title}</title>\n\
         <style>body{{font-family:system-ui,sans-serif;max-width:42em;margin:2em auto;padding:0 1em}}\
         h1{{font-size:1.3em}}li{{list-style:none;padding:.15em 0}}\
         .dir{{font-weight:600}}</style>\n</head>\n<body>\n\
         <h1>{title}</h1>\n<hr>\n{body}</body>\n</html>\n",
        title = escaped_title,
        body = escaped_body,
    )
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
/// `:`, `[`, non-ASCII, ...). Shared with [`crate::drop_server`], whose
/// listing renders upload names into the same page scaffold with the same
/// encoding rules.
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

/// Minimal HTML text escaping for names inside the listing markup. Shared
/// with [`crate::hook_server`], whose inspector renders request-derived text
/// (paths, header names/values, bodies) into the same page scaffold — any
/// text that came from outside must pass through here before it touches
/// markup.
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

/// Confinement guard: deny dotfiles, reject `..` traversal, and refuse any
/// path whose canonicalised target escapes the served root (symlink escape).
///
/// Shared verbatim with [`crate::drop_server`] (visibility only, zero
/// behaviour change — see the shared-helper rule in the module docs): the
/// drop bucket's GET side must behave exactly like the static server's, so it
/// layers this same middleware in front of the same `ServeDir` semantics.
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
pub(crate) async fn confine(State(root): State<PathBuf>, request: Request, next: Next) -> Response {
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

/// SPA fallback (`--spa`): rewrite a 404 for a genuinely non-existent,
/// dot-free path to the root `index.html`, so client-side router deep links
/// (`/settings/profile`) get the app shell instead of a 404.
///
/// Deliberately layered OUTSIDE [`confine`] (which is what makes it able to
/// see missing-path 404s at all — confine 404s those itself), and therefore
/// re-checking the path itself before rewriting, so the guard's refusals keep
/// their meaning:
///
/// - any `.`-prefixed segment (dotfiles, `.git/...`, `.`, `..`) keeps its 404;
///   the app shell must never become a dotfile-detection oracle either;
/// - a path that canonicalises to SOMETHING (existing inside the root, or a
///   symlink escaping it — both are cases confine/ServeDir answered
///   deliberately) keeps its 404: only "nothing exists there" is rewritten;
/// - a root without an `index.html` keeps the honest 404 (never a 500).
///
/// The rewrite is GET/HEAD-only (the shell is a representation, like the
/// listing); HEAD mirrors the GET headers with an empty body, matching the
/// listing's HEAD discipline. All filesystem syscalls run in one
/// `spawn_blocking`, per the guard's blocking-I/O discipline.
async fn spa_fallback(State(root): State<PathBuf>, request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let raw = request.uri().path().to_owned();
    let response = next.run(request).await;
    if response.status() != StatusCode::NOT_FOUND
        || (method != Method::GET && method != Method::HEAD)
    {
        return response;
    }
    // Rebuild the candidate exactly like `confine` does (percent-decode, drop
    // the leading `/`, split on `/`) so the fallback decides on the same path
    // everyone else resolved.
    let decoded = match percent_decode(raw.as_bytes()).decode_utf8() {
        Ok(s) => s,
        // Undecodable paths were refused by confine; never rewrite them.
        Err(_) => return response,
    };
    let mut candidate = root.clone();
    for seg in decoded.trim_start_matches('/').split('/') {
        if seg.is_empty() {
            continue;
        }
        // Same rule, same place in the pipeline as the guard: a dot segment is
        // a refusal, and a refusal must not turn into the app shell.
        if seg.starts_with('.') {
            return response;
        }
        candidate.push(seg);
    }
    let shell = tokio::task::spawn_blocking(move || {
        // The path resolves to something (inside or outside the root): its 404
        // was a deliberate confinement/ServeDir answer, not a miss to paper
        // over — most importantly an escaping symlink must never be laundered
        // into a 200 by the fallback.
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
/// the configured secret — via `Authorization: Bearer <secret>` or
/// `?token=<secret>`, compared in constant time — before the request reaches
/// confinement, the listing, or ServeDir. Gating all methods (unlike the drop
/// bucket's mutation-only gate) is deliberate: the static origin's entire
/// value is its content, so reads are exactly what needs protecting, and
/// gating before confinement means a 404-scanner without the token cannot use
/// the 404/200 distinction to learn which paths exist.
async fn require_token(State(expected): State<String>, request: Request, next: Next) -> Response {
    let header_token = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
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

/// Extract the first value of `key` from a raw query string, percent-decoded.
/// Byte-for-byte twin of the private `drop_server::query_param` (same `+`
/// policy: a literal plus means a plus, the form-encoding convention is not
/// applied) — the two must stay in sync if either changes.
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

/// Constant-time token comparison for the operator-chosen static secret: the
/// decision folds XOR over every byte AND the length difference into one
/// accumulator, so it never early-returns on the first mismatching byte — or
/// on a length mismatch (the drop bucket's `tokens_match` folds the length the
/// same way now that its token may be an arbitrary operator `--token` too;
/// keep the two twins in sync). The total work still scales with the longer
/// input, so a length *class* is inferable from timing, as with any looped
/// compare. An empty configured token matches nothing (the CLI refuses one,
/// and an empty secret must never open the origin).
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

        // The regression case first: the listing reached WITHOUT its trailing
        // slash. A relative ../ would resolve against `/a/b` and land on `/`;
        // the absolute href must name the immediate parent `/a/` in both
        // forms.
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
        // The SPA contract: a path matching no file falls back to the root
        // index.html, while paths matching real files (and the root itself)
        // are served untouched.
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
        // A root with no index.html must keep the honest 404 for missing
        // paths — never a 500 for the unreadable fallback target, and never a
        // rewrite to a file that does not exist.
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
        // The rewrite must not break the security or listing disciplines:
        // dotfiles stay 404 (and never become the shell, which would leak a
        // dotfile oracle the other way), `..` traversal stays 404, and a
        // directory without an index.html still renders the generated listing
        // instead of being swallowed by the fallback.
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
        // The adversarial case for the "canonicalize succeeded → keep the
        // 404" rule: a symlink escaping the root is confined to a 404, and the
        // SPA fallback must not turn that refusal into a 200 shell (which
        // would make the tunnel answer poisoned routes with app content).
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
        // The documented preflight choice: OPTIONS reaches ServeDir's uniform
        // 405 (the origin is GET/HEAD-only, both CORS-simple), and the stamped
        // headers ride even that 405 — and on 404s — so the origin's
        // cross-origin story is uniform rather than faking an allowance with a
        // fake-2xx preflight.
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
    async fn token_gates_before_confinement_so_the_tree_cannot_be_probed() {
        // The layering reason the guard sits OUTSIDE confine: without a valid
        // token even a dotfile path reads 401 (indistinguishable from any
        // other path — no 404-scanning oracle), while WITH a valid token the
        // confinement refusals keep their exact meaning (dotfile → 404, not
        // the shell), and --spa deep links still work for the bearer.
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
        // The compare must never early-return on a mismatching byte or on a
        // length difference (the accumulator folds both), an empty configured
        // token matches nothing, and only the exact secret passes.
        let m = |p: &str, e: &str| super::tokens_match(p, e);
        assert!(m("sekrit", "sekrit"));
        assert!(!m("sekriT", "sekrit"), "one differing byte is enough");
        assert!(!m("sekri", "sekrit"), "shorter never matches");
        assert!(!m("sekritlonger", "sekrit"), "longer never matches");
        assert!(!m("", "sekrit"), "nothing provided never matches");
        assert!(!m("sekrit", ""), "an unconfigured token matches nothing");
    }
}
