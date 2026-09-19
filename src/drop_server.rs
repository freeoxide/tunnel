//! Upload-receiver origin ("drop bucket") for `ft drop <dir>`: a
//! loopback-only origin behind cloudflared that stores uploads into a local
//! directory and serves the stored files back.
//!
//! - `POST`/`PUT /<name>` or `POST /?filename=<name>` — store the RAW body
//!   (multipart is never parsed; it stores as opaque bytes, like the hook
//!   origin). Names are percent-decoded; `+` is a literal plus. Giving the
//!   name in both the path and `?filename=` is a 400.
//! - `GET`/`HEAD /<name>` — serve a stored file; reads are PUBLIC (the token
//!   gates mutations only, the static origin's model). `GET /` lists the
//!   bucket. Other methods hit ServeDir's 405 — there is no delete/move API.
//! - Non-GET/HEAD requests must present the token (`Authorization: Bearer` or
//!   `?token=`) BEFORE the body is read, else 401; the compare is
//!   constant-time ([`tokens_match`]).
//! - Caps: per-upload `--max-size` (the limit layer 413s a declared oversize;
//!   the handler's bounded read 413s a chunked one), a fixed 1 GiB total
//!   ([`MAX_TOTAL_STORE`], 507), and a fixed file count ([`MAX_FILE_COUNT`],
//!   409) — all counted from a startup walk; manual deletions need a restart
//!   to be credited.
//! - Names are REJECTED, never mangled ([`sanitize_filename`], a 400 naming
//!   the rule); a collision with an existing name is a 409.
//! - Reads go through [`crate::static_server::confine`] verbatim in front of
//!   the same ServeDir, so GET behaves like `ft <dir>`. Writes only create
//!   regular files: bytes land in a private, dot-prefixed, token-scoped temp
//!   (`.name.part-<tag8>`, invisible to the API from both sides), published
//!   with a collision-checked `hard_link` + unlink — a create that fails
//!   rather than overwrites, cross-process. A pre-existing entry (even a
//!   symlink) is a 409, so an upload never follows a link out of the bucket.
//!   The store lock serializes uploads and makes the total-cap's
//!   check-then-write atomic; `cmd::drop` additionally refuses two drop
//!   services on one directory. Hard-link-less filesystems (FAT/exFAT)
//!   surface as a loud 500, never a silent no-clobber weakening. No
//!   TraceLayer: drop workers get no server.log sink.

use std::fmt::Write as _;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

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

use crate::static_server::{confine, encode_href, escape_html, html_page};

/// Hard upper bound on any single request: bounds stalled public clients and
/// the worker's graceful drain alike.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(300);

/// Default per-upload cap (`--max-size` when omitted).
pub(crate) const DEFAULT_MAX_SIZE: u64 = 64 * 1024 * 1024;

/// Fixed total cap on stored content under the bucket (per service): the
/// "strict caps" promise keeps exactly one knob, so the worst-case disk
/// footprint is a documented constant.
pub(crate) const MAX_TOTAL_STORE: u64 = 1024 * 1024 * 1024;

/// Fixed cap on stored FILE count under the byte cap: 0-byte uploads never
/// fill the byte cap, and the public `GET /` listing is O(entries).
pub(crate) const MAX_FILE_COUNT: u64 = 10_000;

/// Bytes the temp-name scheme (`.{name}.part-<tag8>`) adds around the name
/// (see [`DropStore::temp_path`]).
const TEMP_NAME_OVERHEAD: usize = 1 + ".part-".len() + 8;

/// Longest upload name accepted. A BUDGET, not NAME_MAX: names are stored as
/// the longer dot-prefixed temp FIRST, so capping at 255 minus the exact temp
/// overhead means every accepted name stores cleanly on 255-byte-NAME_MAX
/// filesystems (the publish path itself never fails).
const MAX_NAME_BYTES: usize = 255 - TEMP_NAME_OVERHEAD;

/// Name of the 0600 file (inside the service's state dir) holding the drop
/// origin's access token, shown by `ft detail`.
const TOKEN_FILENAME: &str = "drop-token";

/// Hard bound on a token-file read: minted tokens are 65 bytes; anything this
/// large is not a token (see [`read_token`]).
const TOKEN_READ_BOUND: u64 = 4096;

/// Mint an access token: 32 OS-CSPRNG bytes as 64 lowercase hex chars. No
/// weak fallback — the token is the only guard between the public tunnel and
/// arbitrary writes, so an unavailable entropy source must fail the start.
pub(crate) fn generate_token() -> std::io::Result<String> {
    let mut bytes = [0u8; 32];
    fill_random(&mut bytes)?;
    let mut token = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(token, "{b:02x}");
    }
    Ok(token)
}

/// Fill `buf` from the OS CSPRNG: /dev/urandom on Unix,
/// BCryptGenRandom (system-preferred RNG) on Windows.
fn fill_random(buf: &mut [u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Read;
        std::fs::File::open("/dev/urandom")?.read_exact(buf)
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Security::Cryptography::{
            BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
        };
        // BCRYPTGENRANDOM_FLAGS is a plain u32 alias in windows-sys 0.59;
        // the algorithm handle is unused with the system-preferred flag.
        let status = unsafe {
            BCryptGenRandom(
                std::ptr::null_mut(),
                buf.as_mut_ptr(),
                buf.len() as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        // NTSTATUS 0 is STATUS_SUCCESS.
        if status == 0 {
            Ok(())
        } else {
            Err(std::io::Error::other(format!(
                "BCryptGenRandom failed: NTSTATUS {status:#010x}"
            )))
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = buf;
        Err(std::io::Error::other(
            "no OS random source on this platform",
        ))
    }
}

/// Constant-time token comparison: folds XOR over every byte AND the length
/// difference into one accumulator — no early return on a mismatch, length
/// included (an operator `--token`'s length is worth not advertising; only a
/// length CLASS leaks, as with any looped compare). Byte-in-sync twin of
/// `static_server::tokens_match` — keep the two in sync. An empty expected
/// token matches nothing: the server-side backstop for a hand-built store.
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

/// Store `token` in `dir` (the service's state dir) with private permissions:
/// this file is the token's durable home — the worker reads it at startup and
/// `ft detail` reads it to show what was minted. The trailing newline keeps
/// `cat` output paste-safe; readers trim.
pub(crate) fn store_token(dir: &Path, token: &str) -> std::io::Result<PathBuf> {
    let path = dir.join(TOKEN_FILENAME);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    crate::fsutil::apply_private_mode(&mut opts);
    let mut file = opts.open(&path)?;
    file.write_all(token.as_bytes())?;
    file.write_all(b"\n")?;
    Ok(path)
}

/// Read the token back, bounded at [`TOKEN_READ_BOUND`] so a stray huge file
/// at the token path cannot be slurped into memory. `Ok(None)` = no token
/// file; `Err` = a real read error (or an over-bound/undecodable file),
/// which callers must not swallow as "no token".
pub(crate) fn read_token(dir: &Path) -> std::io::Result<Option<String>> {
    use std::io::Read as _;
    let file = match std::fs::File::open(dir.join(TOKEN_FILENAME)) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut bytes = Vec::new();
    file.take(TOKEN_READ_BOUND + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > TOKEN_READ_BOUND {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "the drop token file is implausibly large",
        ));
    }
    let text = String::from_utf8(bytes).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "the drop token file is not valid UTF-8",
        )
    })?;
    Ok(Some(text.trim().to_string()))
}

/// Validate an upload name. Returns the unchanged name on success — the
/// policy is REJECT, never mangle — or the rule the name broke, for the 400.
fn sanitize_filename(raw: &str) -> Result<String, String> {
    if raw.is_empty() {
        return Err("the name is empty".to_string());
    }
    if raw.len() > MAX_NAME_BYTES {
        return Err(format!("longer than {MAX_NAME_BYTES} bytes"));
    }
    if raw.contains('/') || raw.contains('\\') {
        return Err("path separators are not allowed (one flat file per upload)".to_string());
    }
    if raw.starts_with('.') {
        return Err("dotfiles (and any name starting with '.') are not allowed".to_string());
    }
    if raw.chars().any(char::is_control) {
        return Err("control characters are not allowed".to_string());
    }
    // ':' is NTFS alternate-data-stream syntax and illegal in Windows
    // filenames — refused under the same portability contract as the devices.
    if raw.contains(':') {
        return Err("colons are not allowed (Windows filenames cannot contain them)".to_string());
    }
    if raw.ends_with('.') || raw.ends_with(' ') {
        return Err("trailing dots/spaces are not allowed (Windows strips them)".to_string());
    }
    // Windows refuses files whose STEM is a device name, with or without an
    // extension; refuse them everywhere so a bucket stays portable.
    let stem = raw.split('.').next().unwrap_or("").to_ascii_uppercase();
    const DEVICES: &[&str] = &[
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    if DEVICES.contains(&stem.as_str()) {
        return Err(format!("'{stem}' is a reserved Windows device name"));
    }
    Ok(raw.to_string())
}

/// Running usage under `root`, guarded by the same lock that serializes
/// uploads (so both caps' check-then-write is atomic). Starts from a startup
/// walk and only grows.
#[derive(Default)]
struct Usage {
    bytes: u64,
    files: u64,
}

/// Shared drop state: canonical upload root, token, per-upload cap, and the
/// running usage (guarded by the same lock that serializes uploads, so the
/// caps' check-then-write is atomic).
pub(crate) struct DropStore {
    /// Canonicalised upload target — the confinement base and the only
    /// directory uploads ever write into.
    root: PathBuf,
    token: String,
    /// Per-upload body cap (also the router's pre-handler limit-layer bound).
    max_upload: usize,
    /// Total stored-bytes cap (`MAX_TOTAL_STORE` in production).
    total_cap: u64,
    /// Stored-file count cap (`MAX_FILE_COUNT` in production).
    file_cap: u64,
    /// Usage currently counted under `root`; upload-serialized. Starts from a
    /// startup walk (see [`DropStore::open`]) and only grows.
    used: Mutex<Usage>,
}

impl DropStore {
    /// Open (not create) `root` as an upload bucket: canonicalise it (the
    /// confinement base must be the REAL path), then measure existing content
    /// so it counts against the caps from the first upload.
    pub(crate) fn open(
        root: &Path,
        token: String,
        max_upload: u64,
        total_cap: u64,
    ) -> std::io::Result<Arc<Self>> {
        Self::open_all(root, token, max_upload, total_cap, MAX_FILE_COUNT)
    }

    /// [`DropStore::open`] with an explicit file-count cap, so the count-cap
    /// refusal is testable without ten thousand uploads.
    #[cfg(test)]
    fn open_with_file_cap(
        root: &Path,
        token: String,
        max_upload: u64,
        total_cap: u64,
        file_cap: u64,
    ) -> std::io::Result<Arc<Self>> {
        Self::open_all(root, token, max_upload, total_cap, file_cap)
    }

    fn open_all(
        root: &Path,
        token: String,
        max_upload: u64,
        total_cap: u64,
        file_cap: u64,
    ) -> std::io::Result<Arc<Self>> {
        let root = std::fs::canonicalize(root)?;
        let used = measure_dir(&root);
        let max_upload = usize::try_from(max_upload).unwrap_or(usize::MAX);
        Ok(Arc::new(Self {
            root,
            token,
            max_upload,
            total_cap,
            file_cap,
            used: Mutex::new(used),
        }))
    }

    /// This service's temp-file path for `name`. Token-scoped so two services
    /// on one directory never share a temp (defense in depth beyond the CLI's
    /// one-bucket-one-owner pre-flight); dot-prefixed so both API sides
    /// (sanitize rejects leading-dot uploads, confine denies dotfile GETs)
    /// keep it unreachable.
    fn temp_path(&self, name: &str) -> PathBuf {
        let tag = token_tag(&self.token);
        self.root.join(format!(".{name}.part-{tag}"))
    }
}

/// First ≤ 8 bytes of `token`, cut at a char boundary: byte 8 can split a
/// multibyte char of an operator `--token`, and plain slicing would panic
/// inside spawn_blocking, 500-ing every upload. The cut never exceeds 8 bytes
/// (the [`TEMP_NAME_OVERHEAD`] budget holds) and stays prefix-based.
fn token_tag(token: &str) -> &str {
    let end = token.len().min(8);
    if token.is_char_boundary(end) {
        return &token[..end];
    }
    let mut end = end;
    while end > 0 && !token.is_char_boundary(end) {
        end -= 1;
    }
    &token[..end]
}

/// Sum the byte size of, and count, every regular file under `root`,
/// best-effort. Symlinks are skipped (`file_type()` does not follow them): no
/// cycles, and their targets consume no disk here.
fn measure_dir(root: &Path) -> Usage {
    let mut used = Usage::default();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_symlink() {
                continue;
            }
            let path = entry.path();
            if ft.is_dir() {
                stack.push(path);
            } else if ft.is_file() {
                used.bytes += entry.metadata().map(|m| m.len()).unwrap_or(0);
                used.files += 1;
            }
        }
    }
    used
}

/// Failure modes of a store write, mapped to responses by the caller.
enum StoreError {
    /// Past the total cap → 507.
    Full,
    /// Past the file-count cap → 409.
    FullCount,
    /// A directory entry with this name already exists → 409.
    Exists,
    /// Disk I/O failed → 500.
    Io(std::io::Error),
}

/// Build the drop origin's [`Router`] over an opened [`DropStore`]. Outermost
/// last: timeout → body limit (pre-rejects declared-oversize 413) → nosniff →
/// token guard (401s unauthenticated mutations) → upload middleware → the
/// static server's `confine` guard in front of ServeDir.
pub(crate) fn router(store: Arc<DropStore>) -> Router {
    Router::new()
        .fallback_service(ServeDir::new(store.root.clone()))
        .layer(from_fn_with_state(store.root.clone(), confine))
        .layer(from_fn_with_state(store.clone(), upload_or_list))
        .layer(from_fn_with_state(store.clone(), require_token))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(RequestBodyLimitLayer::new(store.max_upload))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT, // 408 — client took too long
            REQUEST_TIMEOUT,
        ))
}

/// Extract the first value of `key` from a raw query string, percent-decoded.
/// See the module docs for the `+` policy.
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

/// Extract the credentials after a case-insensitive `Bearer` scheme match
/// (RFC 7235: auth schemes are case-insensitive; the credentials are not).
/// Byte-in-sync twin of `static_server::bearer_token`; keep the two in sync.
fn bearer_token(value: &str) -> Option<&str> {
    let (scheme, credentials) = value.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then_some(credentials)
}

/// Token-check middleware: GET/HEAD pass (reads are public); every other
/// method must present the token, constant-time compared, BEFORE its body is
/// read (an unauthenticated client pays no bytes into us).
async fn require_token(
    State(store): State<Arc<DropStore>>,
    request: Request,
    next: Next,
) -> Response {
    let method = request.method();
    if method == Method::GET || method == Method::HEAD {
        return next.run(request).await;
    }
    let header_token = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(bearer_token);
    let ok = match header_token {
        Some(t) => tokens_match(t, &store.token),
        // Only the query arm needs an allocation (percent-decoding); the
        // Bearer value is compared straight from the header buffer.
        None => request
            .uri()
            .query()
            .and_then(|q| query_param(q, "token"))
            .is_some_and(|t| tokens_match(&t, &store.token)),
    };
    if !ok {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            "uploads require the access token (Authorization: Bearer or ?token=)\n",
        )
            .into_response();
    }
    next.run(request).await
}

/// Upload/list middleware: POST/PUT become uploads (never reaching ServeDir),
/// `GET /`/`HEAD /` render the listing, everything else falls through to the
/// confined static-style serving.
async fn upload_or_list(
    State(store): State<Arc<DropStore>>,
    request: Request,
    next: Next,
) -> Response {
    let method = request.method().clone();
    if method == Method::POST || method == Method::PUT {
        return upload(store, request).await;
    }
    if (method == Method::GET || method == Method::HEAD) && is_root_path(request.uri().path()) {
        return listing(store, method == Method::HEAD).await;
    }
    next.run(request).await
}

/// True for the bucket root paths the listing answers (`/`; tolerant of the
/// empty absolute-path form).
fn is_root_path(path: &str) -> bool {
    path == "/" || path.is_empty()
}

/// Resolve an upload's filename: the (single-segment, percent-decoded) path
/// for `POST /<name>`, or `?filename=` on the root path; both at once is a
/// 400. The `Err` is a (status, body) pair; the response is built in the
/// caller.
fn upload_name(request: &Request) -> Result<String, (StatusCode, String)> {
    let bad = |msg: &'static str| (StatusCode::BAD_REQUEST, format!("{msg}\n"));
    let path = request.uri().path();
    let in_query = request
        .uri()
        .query()
        .and_then(|q| query_param(q, "filename"));
    if is_root_path(path) {
        return in_query
            .ok_or_else(|| bad("no filename given: POST /<name> or POST /?filename=<name>"));
    }
    if in_query.is_some() {
        return Err(bad(
            "give the filename in the path or in ?filename=, not both",
        ));
    }
    let decoded = percent_decode(path.trim_start_matches('/').as_bytes())
        .decode_utf8()
        .map_err(|_| bad("the request path is not valid UTF-8"))?;
    Ok(decoded.into_owned())
}

/// Store an upload: resolve + sanitize the name, read the (capped) raw body,
/// then write it under the store lock. See the module docs for the write
/// discipline.
async fn upload(store: Arc<DropStore>, request: Request) -> Response {
    let name = match upload_name(&request) {
        Ok(n) => n,
        Err((status, body)) => return (status, body).into_response(),
    };
    let name = match sanitize_filename(&name) {
        Ok(n) => n,
        Err(reason) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("rejected filename {name:?}: {reason}\n"),
            )
                .into_response();
        }
    };
    // Second cap enforcement for chunked bodies (no Content-Length for the
    // limit layer to pre-reject): the read itself is bounded at the cap.
    let bytes = match axum::body::to_bytes(request.into_body(), store.max_upload).await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(%e, "upload body unreadable (over the cap or aborted)");
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                "upload over the size cap, not stored\n",
            )
                .into_response();
        }
    };
    // The name rides a clone into the blocking closure so the 201 body can
    // name what was stored without a borrow across the spawn boundary.
    let stored_name = name.clone();
    let written = tokio::task::spawn_blocking(move || store_write(&store, &name, &bytes)).await;
    match written {
        Ok(Ok(())) => (StatusCode::CREATED, format!("stored {stored_name}\n")).into_response(),
        Ok(Err(StoreError::Full)) => (
            StatusCode::INSUFFICIENT_STORAGE,
            "the drop bucket is full (total-store cap reached); nothing was stored\n",
        )
            .into_response(),
        Ok(Err(StoreError::FullCount)) => (
            StatusCode::CONFLICT,
            "the drop bucket is full (file-count cap reached); nothing was stored\n",
        )
            .into_response(),
        Ok(Err(StoreError::Exists)) => (
            StatusCode::CONFLICT,
            "a file with that name already exists; uploads never overwrite\n",
        )
            .into_response(),
        Ok(Err(StoreError::Io(e))) => {
            tracing::error!(%e, "failed to store the upload");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to store the upload\n",
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!(%e, "upload store task panicked");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to store the upload\n",
            )
                .into_response()
        }
    }
}

/// Blocking half of [`upload`]: under the upload lock, check the total cap,
/// write the temp file (private perms), publish with a collision-checked
/// hard-link + unlink, and only then grow the counter — a failed write never
/// charges bytes; a counted byte is always on disk.
fn store_write(store: &DropStore, name: &str, bytes: &[u8]) -> Result<(), StoreError> {
    let mut used = store
        .used
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if used.bytes + bytes.len() as u64 > store.total_cap {
        return Err(StoreError::Full);
    }
    if used.files >= store.file_cap {
        return Err(StoreError::FullCount);
    }
    let tmp = store.temp_path(name);
    // Unlink any stale temp BEFORE the truncate-open: a crash between the
    // hard_link below and its unlink leaves `tmp` hard-linked to the PUBLISHED
    // file, and truncating through that link would silently overwrite it.
    // A real unlink failure fails the upload loudly instead.
    if let Err(e) = std::fs::remove_file(&tmp)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        return Err(StoreError::Io(e));
    }
    let write = || -> std::io::Result<()> {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        crate::fsutil::apply_private_mode(&mut opts);
        let mut file = opts.open(&tmp)?;
        file.write_all(bytes)
    };
    if let Err(e) = write() {
        let _ = std::fs::remove_file(&tmp);
        return Err(StoreError::Io(e));
    }
    // Publish WITHOUT clobbering, atomically, across processes: link(2)/
    // CreateHardLinkW create `target` only if absent, so the never-overwrite
    // guarantee rests on no check-then-act race — and a pre-existing entry
    // (including a symlink; the link lands on the NAME, the target is never
    // followed) is a 409.
    let target = store.root.join(name);
    let linked = std::fs::hard_link(&tmp, &target);
    if let Err(e) = linked {
        let _ = std::fs::remove_file(&tmp);
        return Err(if e.kind() == std::io::ErrorKind::AlreadyExists {
            StoreError::Exists
        } else {
            StoreError::Io(e)
        });
    }
    match std::fs::remove_file(&tmp) {
        Ok(()) => {
            used.bytes += bytes.len() as u64;
            used.files += 1;
            Ok(())
        }
        // The upload IS stored; count it, log the stray temp (dot-prefixed,
        // invisible, over-counted at the next startup walk — conservative).
        Err(e) => {
            used.bytes += bytes.len() as u64;
            used.files += 1;
            tracing::warn!(%e, tmp = %tmp.display(), "stored the upload but could not remove the temp file");
            Ok(())
        }
    }
}

/// `GET /` (and HEAD): the HTML listing of the bucket via the shared page
/// scaffold. The curl hint uses a `<token>` PLACEHOLDER on purpose — the page
/// is public, so the real token must never be rendered into it.
async fn listing(store: Arc<DropStore>, is_head: bool) -> Response {
    let rendered = tokio::task::spawn_blocking(move || render_listing(&store)).await;
    let html = match rendered {
        Ok(html) => html,
        Err(e) => {
            tracing::error!(%e, "listing task panicked");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to render the listing\n",
            )
                .into_response();
        }
    };
    // HEAD mirrors the GET representation's headers — truthful
    // Content-Length — but carries no body.
    let len = html.len();
    let mut response = Html(html).into_response();
    if is_head {
        response
            .headers_mut()
            .insert(header::CONTENT_LENGTH, HeaderValue::from(len));
        response = response.map(|_| axum::body::Body::empty());
    }
    response
}

/// Blocking half of [`listing`]. Hides exactly what the GET side would refuse
/// (dotfiles, escaping/broken symlinks) so the page never advertises a link
/// that 404s.
fn render_listing(store: &DropStore) -> String {
    let mut entries: Vec<(String, bool, u64)> = Vec::new(); // (name, is_dir, size)
    if let Ok(read) = std::fs::read_dir(&store.root) {
        for entry in read.flatten() {
            // Non-UTF-8 names render lossily (their hrefs will not resolve) —
            // tolerated in a dev-facing listing, same trade as the static one.
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') {
                continue;
            }
            let resolved = match std::fs::canonicalize(entry.path()) {
                Ok(target) if target.starts_with(&store.root) => target,
                _ => continue,
            };
            let is_dir = resolved.is_dir();
            let size = if is_dir {
                0
            } else {
                entry.metadata().map(|m| m.len()).unwrap_or(0)
            };
            entries.push((name, is_dir, size));
        }
    }
    entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    let mut body = String::from(
        "<p>Upload (token required for POST/PUT; GET is public): \
         <code>curl -H \"Authorization: Bearer &lt;token&gt;\" --data-binary @file.txt \
         /file.txt</code> — the token is printed once at start and shown by \
         <code>ft detail</code>. Raw bodies only; multipart is stored as opaque bytes.</p>\n\
         <ul>\n",
    );
    if entries.is_empty() {
        body.push_str("<li>(nothing uploaded yet)</li>\n");
    }
    for (name, is_dir, size) in &entries {
        let kind = if *is_dir { "dir" } else { "file" };
        let slash = if *is_dir { "/" } else { "" };
        let href = encode_href(name);
        let label = escape_html(name);
        let size_note = if *is_dir {
            String::new()
        } else {
            format!(" <small>{size} B</small>")
        };
        body.push_str(&format!(
            "<li><a class=\"{kind}\" href=\"/{href}{slash}\">{label}{slash}</a>{size_note}</li>\n"
        ));
    }
    body.push_str("</ul>\n<hr>\n");
    html_page(&escape_html("Drop bucket — uploaded files"), &body)
}

#[cfg(test)]
mod tests {
    //! Pure rule units plus the full Router driven with tower::oneshot,
    //! including the adversarial cases the area brief calls for.

    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    /// A request builder shortcut: method + URI + optional headers + body.
    fn req(method: &str, uri: &str, headers: &[(&str, &str)], body: &[u8]) -> Request<Body> {
        let mut builder = Request::builder().method(method).uri(uri);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder
            .body(Body::from(body.to_vec()))
            .expect("build request")
    }

    async fn body_of(resp: Response) -> Vec<u8> {
        axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("read body")
            .to_vec()
    }

    /// A store over a fresh tempdir with the production token flow and a
    /// small default cap; `total_cap` is a parameter so the 507 path is
    /// testable without a gigabyte of disk.
    fn test_store(total_cap: u64) -> (tempfile::TempDir, Arc<DropStore>) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = DropStore::open(tmp.path(), "tok-abc123".to_string(), 1024, total_cap)
            .expect("open store");
        (tmp, store)
    }

    // --- pure rules ---------------------------------------------------------

    #[test]
    fn generate_token_is_hex_unique_and_64_chars() {
        let a = generate_token().expect("generate");
        let b = generate_token().expect("generate");
        assert_eq!(a.len(), 64);
        assert!(
            a.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        assert_ne!(a, b, "two tokens must differ");
    }

    #[test]
    fn sanitize_filename_accepts_ordinary_names() {
        for ok in ["a.txt", "data-2026.tar.gz", "my file (v2).csv", "a+b"] {
            assert_eq!(
                sanitize_filename(ok).expect(ok),
                ok,
                "{ok} must be accepted unchanged"
            );
        }
    }

    #[test]
    fn sanitize_filename_rejects_traversal_and_separators() {
        // Nothing that could escape the bucket root may pass.
        for bad in ["..", "../x", "a/..", "a/b", "a\\b", "/etc/passwd"] {
            assert!(sanitize_filename(bad).is_err(), "{bad} must be rejected");
        }
    }

    #[test]
    fn sanitize_filename_rejects_dotfiles() {
        // confine denies dotfile GETs; the write side must not create them
        // either (keeps the `.part` temp namespace collision-free too).
        for bad in [".env", ".", "..", "..hidden", ".part"] {
            assert!(sanitize_filename(bad).is_err(), "{bad} must be rejected");
        }
    }

    #[test]
    fn sanitize_filename_rejects_windows_hostile_names() {
        // Device names and trailing dot/space fail to store on Windows;
        // refusing them everywhere keeps the API portable.
        for bad in ["con", "NUL", "Com1.txt", "lpt9", "aux", "name.", "name "] {
            assert!(sanitize_filename(bad).is_err(), "{bad} must be rejected");
        }
    }

    #[test]
    fn sanitize_filename_rejects_colons() {
        // ':' is NTFS alternate-data-stream syntax and illegal in Windows
        // filenames — same Windows-portability contract as the device names.
        for bad in ["a:b", "2026-09-19T10:30:00.log", ":"] {
            assert!(sanitize_filename(bad).is_err(), "{bad} must be rejected");
        }
        let err = sanitize_filename("a:b").expect_err("colons must be rejected");
        assert!(err.contains("colons"), "the 400 must name the rule: {err}");
    }

    #[test]
    fn sanitize_filename_rejects_control_chars_and_oversize() {
        assert!(sanitize_filename("a\nb").is_err(), "control chars rejected");
        let long = "a".repeat(MAX_NAME_BYTES + 1);
        assert!(
            sanitize_filename(&long).is_err(),
            "over-long names rejected"
        );
        assert_eq!(
            sanitize_filename(&"a".repeat(MAX_NAME_BYTES)).expect("at the limit is ok"),
            "a".repeat(MAX_NAME_BYTES)
        );
    }

    #[test]
    fn token_tag_cuts_at_char_boundaries_and_stays_within_eight_bytes() {
        // Regression: byte-slicing `&token[..len.min(8)]` panicked on a
        // multibyte operator --token (500 for every upload). The tag must be
        // a valid prefix of at most 8 bytes for ANY token.
        assert_eq!(token_tag("tok-abc123"), "tok-abc1", "ASCII: first 8 bytes");
        assert_eq!(token_tag("ab"), "ab", "short tokens are used whole");
        assert_eq!(token_tag(""), "", "an empty token yields an empty tag");
        // 3-byte chars: byte 8 splits the third char, so the cut walks back
        // to the boundary at 6; 4-byte chars: byte 8 lands between chars.
        assert_eq!(token_tag("日本語テスト"), "日本");
        assert_eq!(token_tag("😀😀😀"), "😀😀");
        for token in ["aé🎉b", "🎉", "🎉🎉🎉🎉🎉", "日本", "x"] {
            let tag = token_tag(token);
            assert!(token.starts_with(tag), "prefix of {token:?}");
            assert!(
                token.is_char_boundary(tag.len()),
                "boundary cut of {token:?}"
            );
            assert!(tag.len() <= 8, "≤ 8 bytes for {token:?}");
        }
    }

    #[test]
    fn temp_names_for_maximal_names_stay_within_name_max() {
        // Any accepted name's temp (dot + name + ".part-" + ≤ 8-byte tag)
        // must fit the common 255-byte NAME_MAX, ASCII and multibyte alike.
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = DropStore::open(tmp.path(), "tok-abc123".to_string(), 1024, MAX_TOTAL_STORE)
            .expect("open store");
        let max_ascii = "a".repeat(MAX_NAME_BYTES);
        let max_multibyte = "é".repeat(MAX_NAME_BYTES / 2); // 2 bytes per char
        assert_eq!(max_multibyte.len(), MAX_NAME_BYTES, "byte budget met");
        for name in [max_ascii, max_multibyte] {
            assert!(
                sanitize_filename(&name).is_ok(),
                "a name at the budget must be accepted"
            );
            let file_name = store
                .temp_path(&name)
                .file_name()
                .expect("file name")
                .to_string_lossy()
                .into_owned();
            assert!(
                file_name.len() <= 255,
                "temp name must fit NAME_MAX: {} bytes for a {}-byte name",
                file_name.len(),
                name.len()
            );
        }
    }

    #[test]
    fn tokens_match_is_exact_never_length_leaky_and_empty_matches_nothing() {
        // The XOR fold covers the whole token and the length difference; an
        // empty secret must never open the bucket (not even vs an empty one).
        assert!(tokens_match("aaaa", "aaaa"));
        assert!(!tokens_match("aaab", "aaaa"));
        assert!(!tokens_match("aaa", "aaaa"));
        assert!(!tokens_match("", "aaaa"));
        assert!(!tokens_match("aaaa", ""));
        assert!(!tokens_match("", ""), "empty vs empty must match nothing");
    }

    // --- token file ----------------------------------------------------------

    #[test]
    fn token_file_round_trips_and_is_private() {
        // The token's durable home reads back exactly (trimmed) and is
        // owner-only — it is the write credential for the bucket.
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = store_token(tmp.path(), "deadbeef").expect("store");
        assert_eq!(path, tmp.path().join(TOKEN_FILENAME));
        let read = read_token(tmp.path()).expect("read").expect("present");
        assert_eq!(read, "deadbeef");
        #[cfg(unix)]
        {
            let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "token file must be owner-only");
        }
    }

    #[test]
    fn read_token_reports_missing_not_error() {
        let tmp = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            read_token(tmp.path()).expect("read"),
            None,
            "no token file is None, not Err"
        );
    }

    #[test]
    fn read_token_is_bounded_against_a_stray_huge_file() {
        // A stray huge file at the token path is an Err, not a slurp — the
        // same read-bound discipline as the registry/hook stores.
        let tmp = tempfile::tempdir().expect("tempdir");
        let huge = "x".repeat(TOKEN_READ_BOUND as usize + 1);
        std::fs::write(tmp.path().join(TOKEN_FILENAME), &huge).expect("plant huge token");
        assert!(
            read_token(tmp.path()).is_err(),
            "an over-bound token file must Err, not read"
        );
    }

    // --- the full Router, driven like the static/hook HTTP tests -------------

    #[tokio::test]
    async fn upload_with_bearer_token_stores_and_get_serves_back() {
        let (_tmp, store) = test_store(MAX_TOTAL_STORE);
        let app = router(store.clone());
        let resp = app
            .oneshot(req(
                "POST",
                "/hello.txt",
                &[("authorization", "Bearer tok-abc123")],
                b"hello world",
            ))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::CREATED);

        // GET needs no token (reads are public) and returns the exact bytes,
        // as an owner-only regular file on disk.
        let resp = router(store.clone())
            .oneshot(req("GET", "/hello.txt", &[], b""))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_of(resp).await, b"hello world".to_vec());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(store.root.join("hello.txt"))
                .expect("stored file")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "stored uploads must be owner-only");
        }
    }

    #[tokio::test]
    async fn bearer_scheme_matches_case_insensitively_per_rfc_7235() {
        // RFC 7235: the auth SCHEME is case-insensitive — `bearer <token>`
        // must authenticate a mutation (the credentials stay case-sensitive).
        let (_tmp, store) = test_store(MAX_TOTAL_STORE);
        let resp = router(store.clone())
            .oneshot(req(
                "POST",
                "/lower.txt",
                &[("authorization", "bearer tok-abc123")],
                b"lo",
            ))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::CREATED);
        assert_eq!(
            std::fs::read(store.root.join("lower.txt")).expect("read back"),
            b"lo".to_vec()
        );
        let resp = router(store.clone())
            .oneshot(req(
                "POST",
                "/nope.txt",
                &[("authorization", "BEARER TOK-ABC123")],
                b"lo",
            ))
            .await
            .expect("oneshot");
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "the credentials stay case-sensitive"
        );
    }

    #[tokio::test]
    async fn token_via_query_param_works_and_filename_query_names_the_file() {
        let (_tmp, store) = test_store(MAX_TOTAL_STORE);
        let resp = router(store.clone())
            .oneshot(req(
                "PUT",
                "/?token=tok-abc123&filename=via-query.txt",
                &[],
                b"q",
            ))
            .await
            .expect("oneshot");
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "?token= must authenticate: {resp:?}"
        );
        assert!(
            std::fs::read(store.root.join("via-query.txt"))
                .map(|b| b == b"q")
                .unwrap_or(false)
        );
    }

    #[tokio::test]
    async fn mutating_without_token_is_401_but_get_stays_public() {
        // Every mutating method is refused before the body is read; reads
        // need no token (the static origin's model).
        let (_tmp, store) = test_store(MAX_TOTAL_STORE);
        let app = router(store.clone());
        for method in ["POST", "PUT", "DELETE", "PATCH"] {
            let resp = app
                .clone()
                .oneshot(req(method, "/x.txt", &[], b"nope"))
                .await
                .expect("oneshot");
            assert_eq!(
                resp.status(),
                StatusCode::UNAUTHORIZED,
                "{method} without token"
            );
            assert_eq!(
                resp.headers()
                    .get(header::WWW_AUTHENTICATE)
                    .map(|v| v.to_str().expect("ascii")),
                Some("Bearer"),
                "{method} must advertise the auth scheme"
            );
        }
        // Not even an over-cap unauthenticated body is read: 401, not 413.
        let big = vec![b'x'; 2000];
        let resp = app
            .oneshot(req("POST", "/flood", &[], &big))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            std::fs::read_dir(store.root.as_path())
                .expect("read dir")
                .count(),
            0,
            "nothing stored"
        );
    }

    #[tokio::test]
    async fn wrong_token_is_401_and_nothing_is_stored() {
        let (_tmp, store) = test_store(MAX_TOTAL_STORE);
        let app = router(store.clone());
        for uri in ["/x.txt?token=wrong", "/x.txt"] {
            let resp = app
                .clone()
                .oneshot(req(
                    "POST",
                    uri,
                    &[("authorization", "Bearer tok-wrong")],
                    b"nope",
                ))
                .await
                .expect("oneshot");
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{uri}");
        }
        assert_eq!(
            std::fs::read_dir(store.root.as_path())
                .expect("read dir")
                .count(),
            0,
            "no file may appear for a refused upload"
        );
    }

    #[tokio::test]
    async fn non_upload_methods_with_token_fall_through_to_405() {
        // There is deliberately no delete/move API: with a valid token,
        // DELETE still reaches ServeDir's uniform 405.
        let (_tmp, store) = test_store(MAX_TOTAL_STORE);
        let app = router(store.clone());
        app.oneshot(req("POST", "/f.txt?token=tok-abc123", &[], b"x"))
            .await
            .expect("seed upload");
        let resp = router(store.clone())
            .oneshot(req("DELETE", "/f.txt?token=tok-abc123", &[], b""))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert!(store.root.join("f.txt").exists(), "the file must survive");
    }

    #[tokio::test]
    async fn oversized_chunked_body_is_413_and_stores_nothing() {
        // The in-handler cap enforcement (chunked bodies carry no
        // Content-Length for the limit layer to pre-reject): 413, nothing stored.
        let (_tmp, store) = test_store(MAX_TOTAL_STORE);
        let big = vec![b'z'; 1025]; // store cap is 1024 in test_store
        let resp = router(store.clone())
            .oneshot(req("POST", "/flood.bin?token=tok-abc123", &[], &big))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            std::fs::read_dir(store.root.as_path())
                .expect("read dir")
                .count(),
            0,
            "an over-cap upload must not be stored"
        );
    }

    #[tokio::test]
    async fn names_over_the_temp_budget_get_a_precise_400_and_at_the_budget_store() {
        // Regression: a name between the raw 255-byte cap and what the temp
        // name holds passed sanitize, then died ENAMETOOLONG at the temp open
        // as a generic 500. The budget cap rejects it up front with a 400
        // naming the rule; a name exactly AT the budget stores cleanly.
        let (_tmp, store) = test_store(MAX_TOTAL_STORE);
        let app = router(store.clone());
        let over = "a".repeat(MAX_NAME_BYTES + 1);
        let resp = app
            .clone()
            .oneshot(req("POST", &format!("/{over}?token=tok-abc123"), &[], b"x"))
            .await
            .expect("oneshot");
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "an over-budget name must be a precise 400, never a 500"
        );
        let body = String::from_utf8(body_of(resp).await).expect("utf-8 body");
        assert!(
            body.contains("longer than") && body.contains("bytes"),
            "the 400 must name the length rule: {body}"
        );
        assert!(
            !store.root.join(&over).exists() && !store.temp_path(&over).exists(),
            "a rejected name must leave no file and no temp"
        );

        // Exactly at the budget: the write path holds end to end.
        let at = "b".repeat(MAX_NAME_BYTES);
        let resp = router(store.clone())
            .oneshot(req("POST", &format!("/{at}?token=tok-abc123"), &[], b"x"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::CREATED, "at-budget name");
        assert!(store.root.join(&at).exists(), "the at-budget name stored");
    }

    #[tokio::test]
    async fn stale_temp_linked_to_the_stored_file_cannot_corrupt_it() {
        // Regression: a crash between the publish's hard_link and its unlink
        // leaves the temp path hard-linked to the PUBLISHED file. The next
        // same-name upload must unlink that stale temp BEFORE its
        // truncate-open, or it writes through the link, silently overwriting
        // the stored file while answering 409.
        let (_tmp, store) = test_store(MAX_TOTAL_STORE);
        let app = router(store.clone());
        app.clone()
            .oneshot(req("POST", "/x.txt?token=tok-abc123", &[], b"first"))
            .await
            .expect("first upload");
        // Forge the crash state: temp path exists, sharing the stored file's
        // inode.
        std::fs::hard_link(store.root.join("x.txt"), store.temp_path("x.txt"))
            .expect("forge stale temp link");

        let resp = app
            .clone()
            .oneshot(req("POST", "/x.txt?token=tok-abc123", &[], b"second"))
            .await
            .expect("second upload");
        assert_eq!(resp.status(), StatusCode::CONFLICT, "the name still exists");
        assert_eq!(
            std::fs::read(store.root.join("x.txt")).expect("read back"),
            b"first".to_vec(),
            "the 409 must not have written through the stale temp link"
        );
        // The recovery consumed the stale temp; nothing is left behind.
        assert!(
            !store.temp_path("x.txt").exists(),
            "the stale temp must be gone after the publish attempt"
        );

        // The invariant stays recovered for the uploads that follow.
        let resp = app
            .oneshot(req("POST", "/y.txt?token=tok-abc123", &[], b"next"))
            .await
            .expect("follow-up upload");
        assert_eq!(resp.status(), StatusCode::CREATED);
        assert_eq!(
            std::fs::read(store.root.join("y.txt")).expect("read back"),
            b"next".to_vec(),
        );
    }

    #[tokio::test]
    async fn duplicate_name_is_409_and_the_original_is_untouched() {
        // Uploads never overwrite: the second upload of a name conflicts, and
        // the first file's bytes survive byte-for-byte.
        let (_tmp, store) = test_store(MAX_TOTAL_STORE);
        let app = router(store.clone());
        app.clone()
            .oneshot(req("POST", "/dup.txt?token=tok-abc123", &[], b"first"))
            .await
            .expect("first upload");
        let resp = app
            .clone()
            .oneshot(req("PUT", "/dup.txt?token=tok-abc123", &[], b"second"))
            .await
            .expect("second upload");
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        assert_eq!(
            std::fs::read(store.root.join("dup.txt")).expect("read back"),
            b"first".to_vec(),
            "the original file must be untouched"
        );
    }

    #[tokio::test]
    async fn second_origin_on_the_same_dir_cannot_overwrite_the_first_ones_file() {
        // Cross-process safety pin: two DropStores on the SAME directory
        // (the shape a hand-edited registry could produce; the CLI's pre-flight
        // refuses it for ft-managed services) must still be safe at the write
        // level — the collision-checked hard-link publish (not a rename,
        // which silently overwrites on Unix) makes B's conflicting upload a
        // 409 while A's bytes survive, and distinct names store from both.
        let tmp = tempfile::tempdir().expect("tempdir");
        let a = DropStore::open(tmp.path(), "token-aaaa".to_string(), 1024, MAX_TOTAL_STORE)
            .expect("open store a");
        let b = DropStore::open(tmp.path(), "token-bbbb".to_string(), 1024, MAX_TOTAL_STORE)
            .expect("open store b");
        let resp = router(a.clone())
            .oneshot(req("POST", "/shared.txt?token=token-aaaa", &[], b"from-a"))
            .await
            .expect("a uploads");
        assert_eq!(resp.status(), StatusCode::CREATED);
        let resp = router(b.clone())
            .oneshot(req("POST", "/shared.txt?token=token-bbbb", &[], b"from-b"))
            .await
            .expect("b uploads same name");
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        assert_eq!(
            std::fs::read(tmp.path().join("shared.txt")).expect("read back"),
            b"from-a".to_vec(),
            "origin A's file must survive origin B's conflicting upload"
        );
        // B's failed upload left no temp litter in the shared directory.
        assert!(
            !b.temp_path("shared.txt").exists(),
            "a conflicted upload must not leave a temp file"
        );
        // Distinct names still store fine from both origins (the temp
        // namespaces are disjoint), with each origin counting only its own.
        let resp = router(b)
            .oneshot(req("POST", "/from-b.txt?token=token-bbbb", &[], b"bb"))
            .await
            .expect("b uploads distinct name");
        assert_eq!(resp.status(), StatusCode::CREATED);
        assert_eq!(
            std::fs::read(tmp.path().join("from-b.txt")).expect("read back"),
            b"bb".to_vec(),
            "origin B stores its own names without interference"
        );
    }

    #[test]
    fn temp_names_are_scoped_per_service_token() {
        // Same bucket, different tokens: never a shared temp path, so one
        // service's write cannot truncate another's in-flight temp. Same
        // token, same path (a service truncates only its OWN stale temps).
        let tmp = tempfile::tempdir().expect("tempdir");
        let a = DropStore::open(tmp.path(), "token-aaaa".to_string(), 1024, MAX_TOTAL_STORE)
            .expect("open a");
        let b = DropStore::open(tmp.path(), "token-bbbb".to_string(), 1024, MAX_TOTAL_STORE)
            .expect("open b");
        let a_tmp = a.temp_path("x.txt");
        let b_tmp = b.temp_path("x.txt");
        assert_ne!(a_tmp, b_tmp, "different tokens must give different temps");
        assert_eq!(a.temp_path("x.txt"), a_tmp, "same token, same temp path");
        // Temps stay dot-prefixed (invisible to uploads and confine-served
        // GETs alike).
        let name = a_tmp
            .file_name()
            .expect("file name")
            .to_string_lossy()
            .into_owned();
        assert!(name.starts_with('.'), "temp must be a dotfile: {name}");
    }

    #[tokio::test]
    async fn multibyte_operator_token_uploads_and_temp_names_stay_sane() {
        // Regression, end-to-end: with the old byte-sliced temp tag, an
        // operator --token whose 8th byte falls mid-char panicked in
        // temp_path — every upload answered 500. The token rides ?token=
        // percent-encoded ON PURPOSE: a Bearer header value cannot carry
        // UTF-8 (HeaderValue::to_str rejects it), so the query is the only
        // wire shape a multibyte token can travel by — and its decoded value
        // is exactly what used to panic.
        let tmp = tempfile::tempdir().expect("tempdir");
        let token = "鍵🔑日本語";
        let store = DropStore::open(tmp.path(), token.to_string(), 1024, MAX_TOTAL_STORE)
            .expect("open store");
        let resp = router(store.clone())
            .oneshot(req(
                "POST",
                "/upload.bin?token=%E9%8D%B5%F0%9F%94%91%E6%97%A5%E6%9C%AC%E8%AA%9E",
                &[],
                b"multibyte",
            ))
            .await
            .expect("oneshot");
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "a multibyte --token must not break uploads"
        );
        assert_eq!(
            std::fs::read(store.root.join("upload.bin")).expect("read back"),
            b"multibyte".to_vec()
        );
        // The temp scheme stayed sane: a dot-prefixed component carrying the
        // part marker, consumed by the publish.
        let temp = store.temp_path("upload.bin");
        let file_name = temp
            .file_name()
            .expect("file name")
            .to_string_lossy()
            .into_owned();
        assert!(
            file_name.starts_with('.'),
            "temp must stay a dotfile: {file_name}"
        );
        assert!(
            file_name.contains(".part-"),
            "temp must keep the part marker: {file_name}"
        );
        assert!(!temp.exists(), "publish must consume the temp file");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn upload_onto_a_preexisting_symlink_is_refused_without_touching_the_target() {
        // A symlink planted in the bucket pointing outside must never be
        // followed by an upload: the hard-link publish lands on the NAME and
        // fails AlreadyExists, so the upload conflicts and the outside target
        // keeps its bytes.
        use std::os::unix::fs::symlink;
        let (tmp, store) = test_store(MAX_TOTAL_STORE);
        let outside = tempfile::tempdir().expect("outside tempdir");
        std::fs::write(outside.path().join("victim"), "ORIGINAL").expect("seed victim");
        symlink(outside.path().join("victim"), store.root.join("link")).expect("symlink");

        let resp = router(store.clone())
            .oneshot(req("POST", "/link?token=tok-abc123", &[], b"EVIL"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        assert_eq!(
            std::fs::read(outside.path().join("victim")).expect("victim intact"),
            b"ORIGINAL".to_vec(),
            "the symlink target must be untouched"
        );
        drop(tmp);
    }

    #[tokio::test]
    async fn traversal_and_dotfile_names_are_rejected_with_400() {
        // Percent-decoded path names and ?filename= values go through the
        // same sanitizer: separators, parent refs, and dotfiles are 400s that
        // write nothing. (The valid token is ON PURPOSE: auth runs before
        // filename validation, so the token is what lets these adversarial
        // names reach the sanitizer at all.)
        let (_tmp, store) = test_store(MAX_TOTAL_STORE);
        let app = router(store.clone());
        let cases = [
            "/%2e%2e%2fescaped.txt",      // ../escaped.txt, percent-encoded
            "/sub%2Fescaped.txt",         // a/b with an encoded separator
            "/.env",                      // dotfile by path
            "/..%2Fescaped.txt",          // .. with an encoded separator
            "/x?filename=../escaped.txt", // traversal via the query
            "/x?filename=.env",           // dotfile via the query
            "/a/b",                       // raw multi-segment path
        ];
        for uri in cases {
            let uri = if uri.contains('?') {
                format!("{uri}&token=tok-abc123")
            } else {
                format!("{uri}?token=tok-abc123")
            };
            let resp = app
                .clone()
                .oneshot(req("POST", &uri, &[], b"nope"))
                .await
                .expect("oneshot");
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{uri}");
        }
        assert_eq!(
            std::fs::read_dir(store.root.as_path())
                .expect("read dir")
                .count(),
            0,
            "no rejected name may leave a file behind"
        );
    }

    #[tokio::test]
    async fn path_and_filename_query_together_is_400() {
        // One name, one place: ambiguity is refused, never resolved silently.
        let (_tmp, store) = test_store(MAX_TOTAL_STORE);
        let resp = router(store)
            .oneshot(req(
                "POST",
                "/path.txt?filename=query.txt&token=tok-abc123",
                &[],
                b"x",
            ))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn total_cap_returns_507_and_counts_preexisting_files() {
        // The total cap covers content ALREADY in the directory (the startup
        // walk), not just bytes this process uploaded.
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("pre-existing.bin"), vec![b'p'; 700]).expect("seed");
        let store =
            DropStore::open(tmp.path(), "tok-abc123".to_string(), 1024, 1000).expect("open store");
        let app = router(store.clone());
        // Fits exactly (700 + 300 == cap).
        let resp = app
            .clone()
            .oneshot(req(
                "POST",
                "/fits.bin?token=tok-abc123",
                &[],
                &vec![b'f'; 300],
            ))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::CREATED);
        // One more byte is over the cap: 507, nothing stored, no temp litter.
        let resp = app
            .clone()
            .oneshot(req("POST", "/over.bin?token=tok-abc123", &[], b"x"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::INSUFFICIENT_STORAGE);
        assert!(
            !store.root.join("over.bin").exists() && !store.temp_path("over.bin").exists(),
            "a 507 must leave no file and no temp"
        );
    }

    #[tokio::test]
    async fn file_count_cap_returns_a_precise_409_and_stores_nothing() {
        // The count cap bounds the O(entries) listing under the byte cap
        // (0-byte uploads never fill the byte cap): a 409 with its own body,
        // distinct from the name-collision 409, and nothing stored past it.
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("pre1"), b"a").expect("seed 1");
        std::fs::write(tmp.path().join("pre2"), b"b").expect("seed 2");
        let store = DropStore::open_with_file_cap(
            tmp.path(),
            "tok-abc123".to_string(),
            1024,
            MAX_TOTAL_STORE,
            2,
        )
        .expect("open store");
        // The startup walk counted the two pre-existing files: the FIRST
        // upload is already past the cap (manual deletions, like the byte
        // cap's, need a restart to be credited).
        let resp = router(store.clone())
            .oneshot(req("POST", "/next.txt?token=tok-abc123", &[], b"x"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let body = String::from_utf8(body_of(resp).await).expect("utf-8 body");
        assert!(
            body.contains("file-count") && !body.contains("already exists"),
            "the 409 must name the count rule, not a collision: {body}"
        );
        assert!(
            !store.root.join("next.txt").exists() && !store.temp_path("next.txt").exists(),
            "a refused upload must leave no file and no temp"
        );
    }

    #[tokio::test]
    async fn listing_renders_uploads_escapes_markup_and_hides_dotfiles() {
        // Uploads listed with sizes, markup in names escaped, dotfiles
        // hidden, and a `<token>` PLACEHOLDER only — the page is public, so
        // the real token must never be rendered into it.
        let (tmp, store) = test_store(MAX_TOTAL_STORE);
        std::fs::write(tmp.path().join(".secret"), "x").expect("plant dotfile");
        let app = router(store.clone());
        // Percent-encoded on the wire (`<`/`>` are illegal in a request
        // target); the decoded name is `a<b>.txt`, which sanitize allows and
        // the listing must escape.
        app.clone()
            .oneshot(req("POST", "/a%3Cb%3E.txt?token=tok-abc123", &[], b"abc"))
            .await
            .expect("upload angled name");
        app.clone()
            .oneshot(req("POST", "/plain.txt?token=tok-abc123", &[], b"xy"))
            .await
            .expect("upload plain");

        let resp = app
            .oneshot(req("GET", "/", &[], b""))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/html; charset=utf-8"
        );
        let html = String::from_utf8(body_of(resp).await).expect("utf-8 html");
        assert!(
            html.contains("&lt;b&gt;.txt"),
            "markup must be escaped: {html}"
        );
        assert!(html.contains("plain.txt"), "{html}");
        assert!(!html.contains(".secret"), "dotfiles must be hidden: {html}");
        assert!(
            !html.contains("tok-abc123"),
            "the real token must never appear: {html}"
        );
        assert!(
            html.contains("&lt;token&gt;"),
            "the hint must carry the placeholder: {html}"
        );
        assert!(
            html.contains("system-ui"),
            "must use the shared page scaffold: {html}"
        );
    }

    #[tokio::test]
    async fn head_root_answers_headers_with_no_body() {
        let (_tmp, store) = test_store(MAX_TOTAL_STORE);
        let app = router(store.clone());
        let page = {
            let resp = app
                .clone()
                .oneshot(req("GET", "/", &[], b""))
                .await
                .expect("GET /");
            body_of(resp).await
        };
        let resp = app
            .oneshot(req("HEAD", "/", &[], b""))
            .await
            .expect("HEAD /");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CONTENT_LENGTH).unwrap(),
            page.len().to_string().as_str(),
            "HEAD must report the GET representation's true length"
        );
        assert!(body_of(resp).await.is_empty());
    }

    #[tokio::test]
    async fn multipart_body_is_stored_as_opaque_capped_bytes() {
        // No multipart parsing (no such dependency): the raw capped bytes are
        // stored, so the API contract is honest about what landed on disk.
        let (_tmp, store) = test_store(MAX_TOTAL_STORE);
        let body = b"--BOUNDARY\r\ncontent-disposition: form-data; name=\"f\"; filename=\"x.txt\"\r\n\r\nhi\r\n--BOUNDARY--\r\n";
        let resp = router(store.clone())
            .oneshot(req(
                "POST",
                "/form.bin?token=tok-abc123",
                &[("content-type", "multipart/form-data; boundary=BOUNDARY")],
                body,
            ))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::CREATED);
        assert_eq!(
            std::fs::read(store.root.join("form.bin")).expect("stored"),
            body.to_vec(),
            "multipart must be stored byte-for-byte, unparsed"
        );
    }

    #[tokio::test]
    async fn empty_upload_creates_an_empty_file() {
        let (_tmp, store) = test_store(MAX_TOTAL_STORE);
        let resp = router(store.clone())
            .oneshot(req("PUT", "/empty.bin?token=tok-abc123", &[], b""))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::CREATED);
        let stored = std::fs::metadata(store.root.join("empty.bin")).expect("stored");
        assert_eq!(stored.len(), 0);
    }

    #[tokio::test]
    async fn get_side_confinement_matches_the_static_server() {
        // The read side must behave exactly like `ft <dir>`: dotfiles denied,
        // escaping symlinks refused, missing paths 404.
        #[cfg(unix)]
        use std::os::unix::fs::symlink;
        let (tmp, store) = test_store(MAX_TOTAL_STORE);
        std::fs::write(tmp.path().join(".env"), "SECRET=1").expect("plant dotfile");
        #[cfg(unix)]
        {
            let outside = tempfile::tempdir().expect("outside");
            std::fs::write(outside.path().join("secret"), "TOPSECRET").expect("seed");
            symlink(outside.path().join("secret"), store.root.join("leak")).expect("symlink");
        }
        let app = router(store);
        let resp = app
            .clone()
            .oneshot(req("GET", "/.env", &[], b""))
            .await
            .expect("oneshot");
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "dotfiles must be denied"
        );
        let resp = app
            .clone()
            .oneshot(req("GET", "/missing.txt", &[], b""))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        #[cfg(unix)]
        {
            let resp = app
                .oneshot(req("GET", "/leak", &[], b""))
                .await
                .expect("oneshot");
            assert_eq!(
                resp.status(),
                StatusCode::NOT_FOUND,
                "symlink escape must be refused"
            );
        }
    }

    #[tokio::test]
    async fn origin_serves_over_a_real_socket_and_pre_rejects_declared_oversize() {
        // Real-TCP smoke (oneshot bypasses the HTTP server): an authenticated
        // POST is answered 201, and a body that DECLARES an over-cap
        // Content-Length is pre-rejected 413 by the limit layer before the
        // handler reads a byte.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (_tmp, store) = test_store(1 << 20);
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind ephemeral loopback listener");
        let addr = listener.local_addr().expect("local addr");
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            crate::static_server::serve_on(router(store), listener, async {
                let _ = shutdown_rx.await;
            })
            .await
        });

        let mut sock = tokio::net::TcpStream::connect(addr).await.expect("connect");
        sock.write_all(
            b"POST /real.txt HTTP/1.1\r\nhost: smoke\r\nauthorization: Bearer tok-abc123\r\ncontent-length: 5\r\n\r\nhello",
        )
        .await
        .expect("write request");
        let mut buf = vec![0u8; 1024];
        let n = sock.read(&mut buf).await.expect("read response");
        let head = String::from_utf8_lossy(&buf[..n]).into_owned();
        assert!(
            head.starts_with("HTTP/1.1 201 Created"),
            "a stored upload must be answered 201, got: {head}"
        );

        let mut sock = tokio::net::TcpStream::connect(addr).await.expect("connect");
        sock.write_all(
            b"POST /flood.bin HTTP/1.1\r\nhost: smoke\r\nauthorization: Bearer tok-abc123\r\ncontent-length: 99999999\r\n\r\n",
        )
        .await
        .expect("write oversized request");
        let n = sock.read(&mut buf).await.expect("read response");
        let head = String::from_utf8_lossy(&buf[..n]).into_owned();
        assert!(
            head.starts_with("HTTP/1.1 413"),
            "a declared-oversize body must be pre-rejected 413, got: {head}"
        );

        let _ = shutdown_tx.send(());
        let res = server.await.expect("join serve task");
        assert!(res.is_ok(), "serve_on drained without error: {res:?}");
    }
}
