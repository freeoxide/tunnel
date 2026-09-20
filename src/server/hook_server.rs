//! Webhook receiver/inspector origin: an ft-owned loopback origin behind
//! cloudflared that records every request — method, path, query, allowlisted
//! headers, size-capped body — into a private JSON store and answers 200.
//! `GET /__inspect` (HTML) and `GET /__inspect.json` (JSON) render the
//! records newest-first; the inspection endpoints themselves are never
//! recorded. Header capture is an ALLOWLIST so credential-bearing headers
//! can never reach the store or the public inspection view.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use axum::Json;
use axum::Router;
use axum::extract::{Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::timeout::TimeoutLayer;

use crate::server::static_server::{escape_html, html_page};

/// Bounds slow clients and the graceful drain, like the static server's.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Recorded-body cap; enforced twice (the limit layer's 413 and the
/// capture's own truncation) — see [`record`] for why both.
const MAX_REQUEST_BODY: usize = 64 * 1024;

/// Default retention; `ft hook --keep <n>` overrides (1..=1000). u16 because
/// that is what the worker argv carries.
pub(crate) const DEFAULT_KEEP: u16 = 200;

/// Max accepted `--keep`; the read ceiling is computed at this max so it
/// never depends on the loading keep ([`HookLog::load`] clamps to it).
const MAX_KEEP: usize = 1000;

/// The per-service store, a sibling of the logs so `ft logs` stays coherent.
pub(crate) const REQUESTS_FILENAME: &str = "requests.json";

const INSPECT_PATH: &str = "/__inspect";

const JSON_PATH: &str = "/__inspect.json";

/// An ALLOWLIST, not a denylist: only known-debugging headers are copied, so
/// a future credential-bearing header cannot leak by being forgotten.
const RECORDED_HEADERS: &[&str] = &[
    "accept",
    "content-length",
    "content-type",
    "user-agent",
    "x-forwarded-for",
    "x-forwarded-proto",
    // Vendor event-routing headers — they identify the delivery.
    "x-github-delivery",
    "x-github-event",
    "x-gitlab-event",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordedRequest {
    /// Monotonic per-service counter (higher = newer); survives reloads, so
    /// ordering never depends on clock comparisons.
    pub seq: u64,
    pub received_at: DateTime<Utc>,
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub headers: Vec<(String, String)>,
    /// First [`MAX_REQUEST_BODY`] bytes, lossily decoded — binary bodies
    /// render as replacement chars; the inspector is a debugging view.
    pub body: String,
    /// FULL byte length before any cap/decoding.
    pub body_len: usize,
    /// `body` is only a prefix. Unreachable behind the limit layer, but kept
    /// honest by capture's own arithmetic.
    pub truncated: bool,
}

impl RecordedRequest {
    /// Build a record from a request head + body; pure, so the capture rules
    /// are unit-testable.
    fn capture(seq: u64, parts: &Parts, body: &[u8]) -> Self {
        let headers = parts
            .headers
            .iter()
            .filter(|(name, _)| {
                RECORDED_HEADERS
                    .iter()
                    .any(|allowed| name.as_str() == *allowed)
            })
            // A header VALUE with non-UTF-8 bytes (legal in HTTP) is dropped
            // rather than lossily mangled: a mangled value reads as real.
            .filter_map(|(name, value)| {
                let value = value.to_str().ok()?;
                Some((name.as_str().to_owned(), value.to_owned()))
            })
            .collect();
        let capped = &body[..body.len().min(MAX_REQUEST_BODY)];
        Self {
            seq,
            received_at: crate::model::now_utc(),
            method: parts.method.as_str().to_owned(),
            path: parts.uri.path().to_owned(),
            query: parts.uri.query().map(str::to_owned),
            headers,
            body: String::from_utf8_lossy(capped).into_owned(),
            body_len: body.len(),
            truncated: capped.len() < body.len(),
        }
    }
}

/// Newest-first Vec mirrored to `requests.json` (0600, atomic tmp+rename) on
/// every append.
#[derive(Debug)]
pub struct HookLog {
    path: PathBuf,
    keep: usize,
    next_seq: u64,
    /// Newest-first — by construction on append, by seq-sort on load.
    requests: Vec<RecordedRequest>,
}

/// Worst-case JSON expansion of one body byte (control bytes escape to a
/// 6-byte `\u00XX`). NUL bodies are valid UTF-8 and legitimate, so the read
/// bound MUST budget the expansion — an escape-unaware bound wipes such
/// stores on reload: remotely triggerable record loss.
const JSON_ESCAPE_FACTOR: usize = 6;

/// hyper's whole-wire request-head budget under axum's default builder (8
/// KiB + 4 KiB × 100 headers). No cap of ours sits below it — capture
/// truncates neither path/query nor header values — so the read bound must
/// assume heads this large; if hyper's default grows, this must grow with
/// it.
const HYPER_HEAD_BUDGET: usize = 417_792;

/// Per-record head allowance: [`HYPER_HEAD_BUDGET`] × 2 — the http crate
/// admits raw `"`/`\` in head material and serde_json expands each such byte
/// 1→2 — plus 2 KiB of JSON structure. A smaller allowance would misclassify
/// legitimate stores on reload and wipe them.
const STORE_RECORD_OVERHEAD: usize = HYPER_HEAD_BUDGET * 2 + 2 * 1024;

/// Upper bound on a store this server could have written at `keep` records;
/// saturating, u64 for [`read_store_blob`]'s `File::take`.
fn store_read_bound(keep: usize) -> u64 {
    let per_record = (MAX_REQUEST_BODY * JSON_ESCAPE_FACTOR + STORE_RECORD_OVERHEAD) as u64;
    (keep as u64).saturating_mul(per_record)
}

/// [`store_read_bound`] at [`MAX_KEEP`], independent of the loading keep — a
/// store written at ANY supported keep fits; load() truncates after.
fn absolute_read_bound() -> u64 {
    store_read_bound(MAX_KEEP)
}

/// Read at most `bound + 1` bytes (the +1 tells at-the-bound from past-it);
/// bounding the READ, not just the parse, so no stray huge file is slurped.
fn read_store_blob(path: &Path, bound: u64) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;
    let file = std::fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take(bound.saturating_add(1)).read_to_end(&mut bytes)?;
    Ok(bytes)
}

impl HookLog {
    /// Load the store at `path`, or start empty when it does not exist. A
    /// corrupt (or past-the-ceiling) store degrades to empty: corruption
    /// implies disk trouble (the write is atomic), and bricking the service
    /// is worse than restarting the log — webhook senders re-deliver. Any
    /// OTHER read error fails the load: the store may be intact behind it,
    /// and an empty fallback would let the next append's rename destroy it.
    /// The loaded store is re-truncated to `keep` — a lowered keep never
    /// wipes the log.
    pub fn load(path: PathBuf, keep: usize) -> std::io::Result<Self> {
        // keep arrives unvalidated on the hidden run-worker path; clamp so
        // retention can't write past the ceiling.
        let keep = keep.min(MAX_KEEP);
        let ceiling = absolute_read_bound();
        // Past the ceiling by metadata: refuse without reading a giant.
        let mut requests = if std::fs::metadata(&path).is_ok_and(|m| m.len() > ceiling) {
            tracing::warn!(
                path = %path.display(),
                "hook request store is larger than the absolute read bound; starting a new one"
            );
            Vec::new()
        } else {
            match read_store_blob(&path, ceiling) {
                // Grew between stat and read: same corrupt-store recovery.
                Ok(bytes) if bytes.len() as u64 > ceiling => {
                    tracing::warn!(
                        path = %path.display(),
                        "hook request store is larger than the absolute read bound; starting a new one"
                    );
                    Vec::new()
                }
                // Fatter than the loading keep allows but under the ceiling:
                // legitimate (written under a higher keep) — truncate below.
                Ok(bytes) if !bytes.iter().all(u8::is_ascii_whitespace) => {
                    match serde_json::from_slice::<Vec<RecordedRequest>>(&bytes) {
                        Ok(parsed) => parsed,
                        Err(e) => {
                            tracing::warn!(%e, path = %path.display(), "hook request store is corrupt; starting a new one");
                            Vec::new()
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
                Ok(_) => Vec::new(),
                Err(e) => return Err(e),
            }
        };
        requests.sort_by_key(|r| std::cmp::Reverse(r.seq));
        requests.truncate(keep);
        // Saturate: `+ 1` at a hand-edited u64::MAX would panic in debug and
        // wrap in release, stamping the next record as the OLDEST.
        let next_seq = requests
            .first()
            .map(|r| r.seq.saturating_add(1))
            .unwrap_or(1);
        Ok(Self {
            path,
            keep,
            next_seq,
            requests,
        })
    }

    /// Insert + persist: atomic tmp+rename with private perms (the store
    /// carries request paths and bodies — the logs' 0600 class).
    fn record(&mut self, req: RecordedRequest) -> std::io::Result<()> {
        self.requests.insert(0, req);
        self.requests.truncate(self.keep);
        self.persist()
    }

    /// Saturates like load (see the comment there); at saturation duplicate
    /// seqs are unavoidable, but the stable sort keeps the order well-defined.
    fn next_seq(&mut self) -> u64 {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        seq
    }

    /// Point-in-time copy, bounded by `keep` × the body cap.
    fn snapshot(&self) -> Vec<RecordedRequest> {
        self.requests.clone()
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.requests.len()
    }

    fn persist(&self) -> std::io::Result<()> {
        let data = serde_json::to_vec(&self.requests)
            .map_err(|e| std::io::Error::other(format!("serializing the request store: {e}")))?;
        let tmp = self.path.with_extension("json.tmp");
        {
            let mut opts = OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            crate::fsutil::apply_private_mode(&mut opts);
            let mut file = opts.open(&tmp)?;
            file.write_all(&data)?;
        }
        std::fs::rename(&tmp, &self.path)
    }
}

/// Recover from poisoning: in-memory state stays valid across a panic
/// (insert + truncate are infallible), so recording continues.
fn lock(log: &Mutex<HookLog>) -> MutexGuard<'_, HookLog> {
    log.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Mirrors the static server's layering minus TraceLayer: the request record
/// IS the log — a trace would duplicate it into worker.log.
pub fn router(log: Arc<Mutex<HookLog>>) -> Router {
    Router::new()
        // The inspection routes are matched BEFORE the recording fallback, so
        // they (and only they) never land in the store.
        .route(JSON_PATH, get(inspect_json))
        .route(INSPECT_PATH, get(inspect_html))
        .fallback(record)
        .with_state(log)
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

/// Fallback handler: record, answer 200; a persist failure is a 500 so the
/// sender can retry — never a silent "acknowledged but unwritten".
async fn record(State(log): State<Arc<Mutex<HookLog>>>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    // Second cap enforcement: the layer pre-rejects a DECLARED oversize
    // (Content-Length); chunked bodies carry none — this read caps those.
    let bytes = match axum::body::to_bytes(body, MAX_REQUEST_BODY).await {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::warn!(%e, "request body unreadable (over the cap or aborted)");
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                "request body over the size cap, not recorded\n",
            )
                .into_response();
        }
    };
    // Blocking fs work off the async threads (request-path discipline).
    let persisted = tokio::task::spawn_blocking(move || {
        let mut log = lock(&log);
        let seq = log.next_seq();
        let record = RecordedRequest::capture(seq, &parts, &bytes);
        log.record(record)
    })
    .await;
    match persisted {
        Ok(Ok(())) => (StatusCode::OK, "recorded\n").into_response(),
        Ok(Err(e)) => {
            tracing::error!(%e, "failed to persist the recorded request");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to persist the recorded request\n",
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!(%e, "recording task panicked");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to record the request\n",
            )
                .into_response()
        }
    }
}

/// Snapshot off the async thread: the record path holds this lock across
/// persist's write, so an async-side lock() could park a tokio worker.
async fn snapshot_offline(log: &Arc<Mutex<HookLog>>) -> Vec<RecordedRequest> {
    let log = Arc::clone(log);
    tokio::task::spawn_blocking(move || lock(&log).snapshot())
        .await
        .unwrap_or_default()
}

async fn inspect_html(State(log): State<Arc<Mutex<HookLog>>>) -> Html<String> {
    let requests = snapshot_offline(&log).await;
    Html(render_inspection(&requests))
}

/// Every request-derived string passes through [`escape_html`] — webhook
/// bodies are attacker-controlled by definition.
fn render_inspection(requests: &[RecordedRequest]) -> String {
    let title = format!("Recorded requests — {}", requests.len());
    let mut body = String::from("<ul>\n");
    if requests.is_empty() {
        body.push_str("<li>(no requests recorded yet — send one through the tunnel)</li>\n");
    }
    for r in requests {
        let target = match &r.query {
            Some(q) => format!("{}?{}", r.path, q),
            None => r.path.clone(),
        };
        let received = r.received_at.to_rfc3339_opts(SecondsFormat::Millis, true);
        body.push_str(&format!(
            "<li><strong>{}</strong> {} <small>#{seq} · {received} · {} bytes{}</small>\n",
            escape_html(&r.method),
            escape_html(&target),
            r.body_len,
            if r.truncated { " (truncated)" } else { "" },
            seq = r.seq,
            received = escape_html(&received),
        ));
        if !r.headers.is_empty() {
            body.push_str("<pre>");
            for (name, value) in &r.headers {
                body.push_str(&escape_html(&format!("{name}: {value}\n")));
            }
            body.push_str("</pre>\n");
        }
        if !r.body.is_empty() {
            body.push_str(&format!("<pre>{}</pre>\n", escape_html(&r.body)));
        }
        body.push_str("</li>\n");
    }
    body.push_str("</ul>\n<hr>\n");
    html_page(&escape_html(&title), &body)
}

async fn inspect_json(State(log): State<Arc<Mutex<HookLog>>>) -> Json<Vec<RecordedRequest>> {
    Json(snapshot_offline(&log).await)
}

#[cfg(test)]
mod tests {
    //! Capture rules as pure units, then the full Router via tower::oneshot.

    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn req(method: &str, uri: &str, body: &[u8]) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::from(body.to_vec()))
            .expect("build request")
    }

    async fn body_of(resp: Response) -> Vec<u8> {
        axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("read body")
            .to_vec()
    }

    /// Build a `Parts` head for [`RecordedRequest::capture`] without a full
    /// request round-trip.
    fn parts(method: &str, uri: &str, headers: &[(&str, &str)]) -> Parts {
        let mut builder = Request::builder().method(method).uri(uri);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(()).expect("build request head").into_parts().0
    }

    #[test]
    fn capture_records_method_path_query_and_selected_headers() {
        let head = parts(
            "POST",
            "/hooks/github?state=42",
            &[
                ("content-type", "application/json"),
                ("x-github-event", "push"),
                ("user-agent", "GitHub-Hookshot/abc"),
            ],
        );
        let r = RecordedRequest::capture(7, &head, b"{\"a\":1}");
        assert_eq!(r.seq, 7);
        assert_eq!(r.method, "POST");
        assert_eq!(r.path, "/hooks/github");
        assert_eq!(r.query.as_deref(), Some("state=42"));
        assert_eq!(
            r.headers,
            vec![
                ("content-type".to_string(), "application/json".to_string()),
                ("x-github-event".to_string(), "push".to_string()),
                ("user-agent".to_string(), "GitHub-Hookshot/abc".to_string()),
            ]
        );
        assert_eq!(r.body, "{\"a\":1}");
        assert_eq!(r.body_len, 7);
        assert!(!r.truncated);
    }

    #[test]
    fn capture_never_records_credential_headers() {
        let head = parts(
            "POST",
            "/x",
            &[
                ("authorization", "Bearer sekrit"),
                ("cookie", "session=sekrit"),
                ("x-hub-signature-256", "sha256=sekrit"),
                ("x-api-key", "sekrit"),
                ("content-type", "text/plain"),
            ],
        );
        let r = RecordedRequest::capture(1, &head, b"");
        assert_eq!(
            r.headers,
            vec![("content-type".to_string(), "text/plain".to_string())],
            "only allowlisted headers may be recorded: {:?}",
            r.headers
        );
    }

    #[test]
    fn capture_caps_the_body_and_flags_truncation() {
        // Pinned even though the limit layer makes truncation unreachable
        // over HTTP.
        let big = vec![b'x'; MAX_REQUEST_BODY + 1234];
        let head = parts("POST", "/x", &[]);
        let r = RecordedRequest::capture(1, &head, &big);
        assert_eq!(r.body_len, MAX_REQUEST_BODY + 1234);
        assert_eq!(r.body.len(), MAX_REQUEST_BODY);
        assert!(r.truncated);
    }

    #[test]
    fn capture_preserves_non_utf8_bodies_lossily() {
        let head = parts("POST", "/x", &[]);
        let binary = [0xff, 0xfe, b'a', b'b'];
        let r = RecordedRequest::capture(1, &head, &binary);
        assert_eq!(r.body_len, 4);
        assert!(
            r.body.contains('\u{FFFD}'),
            "lossy decode expected: {:?}",
            r.body
        );
    }

    #[test]
    fn hook_log_keeps_only_the_newest_requests() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("requests.json");
        let mut log = HookLog::load(path.clone(), 3).expect("load");
        for seq in 1..=5u64 {
            let head = parts("GET", &format!("/{seq}"), &[]);
            let record = RecordedRequest::capture(seq, &head, b"");
            log.record(record).expect("record");
        }
        assert_eq!(log.len(), 3);
        let snap = log.snapshot();
        let seqs: Vec<u64> = snap.iter().map(|r| r.seq).collect();
        assert_eq!(seqs, vec![5, 4, 3], "newest first, oldest evicted");
        let reloaded = HookLog::load(path, 3).expect("reload");
        assert_eq!(reloaded.snapshot(), snap);
    }

    #[test]
    fn hook_log_persists_and_reloads_with_continuing_seqs() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("requests.json");
        {
            let mut log = HookLog::load(path.clone(), 10).expect("load");
            let head = parts("POST", "/first", &[]);
            log.record(RecordedRequest::capture(1, &head, b"one"))
                .expect("record");
        }
        let mut log = HookLog::load(path, 10).expect("reload");
        assert_eq!(log.snapshot().len(), 1);
        assert_eq!(log.snapshot()[0].path, "/first");
        let seq = log.next_seq();
        let head = parts("POST", "/second", &[]);
        log.record(RecordedRequest::capture(seq, &head, b"two"))
            .expect("record");
        let snap = log.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].path, "/second", "newest first after reload");
        assert_eq!(snap[0].seq, 2, "seq continues past the loaded max");
    }

    #[test]
    fn load_saturates_a_hand_edited_max_seq_counter_and_still_appends() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("requests.json");
        {
            let mut log = HookLog::load(path.clone(), 5).expect("seed load");
            let head = parts("POST", "/seed", &[]);
            log.record(RecordedRequest::capture(u64::MAX, &head, b"seed"))
                .expect("seed record");
        }
        let mut log = HookLog::load(path.clone(), 5).expect("reload at MAX seq");
        assert_eq!(
            log.next_seq,
            u64::MAX,
            "the reloaded counter must saturate at u64::MAX, not wrap to 0"
        );
        let seq = log.next_seq();
        assert_eq!(
            seq,
            u64::MAX,
            "next_seq saturates at u64::MAX instead of overflowing"
        );
        let head = parts("POST", "/after", &[]);
        log.record(RecordedRequest::capture(seq, &head, b"after"))
            .expect("record at MAX seq");
        assert_eq!(log.len(), 2);
        let reloaded = HookLog::load(path, 5).expect("reload after the append");
        let paths: Vec<String> = reloaded.snapshot().into_iter().map(|r| r.path).collect();
        assert_eq!(paths, vec!["/after", "/seed"]);
    }

    // Unix-gated: set_len is not sparse on NTFS, and a real 1.2 GiB fixture
    // is too heavy for a test.
    #[cfg(unix)]
    #[test]
    fn load_treats_an_oversized_store_as_corruption() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("requests.json");
        // Sparse file — the metadata check refuses it unread.
        std::fs::File::create(&path)
            .and_then(|f| f.set_len(absolute_read_bound() + 1))
            .expect("plant a sparse over-ceiling store");
        let log = HookLog::load(path, 200).expect("an oversized store still loads (as empty)");
        assert_eq!(log.len(), 0, "oversized store must load as empty");
    }

    #[test]
    fn lowering_keep_loads_a_fat_legit_store_and_truncates_it() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("requests.json");
        {
            let mut log = HookLog::load(path.clone(), 10).expect("seed load");
            for seq in 1..=5u64 {
                let head = parts("POST", &format!("/{seq}"), &[]);
                let body = vec![0u8; MAX_REQUEST_BODY];
                log.record(RecordedRequest::capture(seq, &head, &body))
                    .expect("record");
            }
        }
        let persisted_len = std::fs::metadata(&path).expect("store exists").len();
        assert!(
            persisted_len > store_read_bound(1),
            "the fixture must exceed the keep=1 bound (the old wipe trigger)"
        );
        assert!(
            persisted_len <= absolute_read_bound(),
            "the fixture must sit inside the absolute ceiling"
        );
        let reloaded = HookLog::load(path, 1).expect("reload with a lowered keep");
        let snap = reloaded.snapshot();
        assert_eq!(snap.len(), 1, "load-and-truncate, not wipe");
        assert_eq!(snap[0].seq, 5, "the NEWEST record survives the truncation");
        assert_eq!(snap[0].body.len(), MAX_REQUEST_BODY);
    }

    #[test]
    fn load_clamps_an_over_max_keep_to_the_supported_ceiling() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("requests.json");
        let over_max = MAX_KEEP + 200;
        let mut log = HookLog::load(path.clone(), over_max).expect("load");
        assert_eq!(
            log.keep, MAX_KEEP,
            "the keep must clamp to the supported max"
        );
        for seq in 1..=3u64 {
            let head = parts("POST", &format!("/{seq}"), &[]);
            log.record(RecordedRequest::capture(seq, &head, b"x"))
                .expect("record");
        }
        let reloaded = HookLog::load(path, over_max).expect("reload");
        assert_eq!(reloaded.keep, MAX_KEEP, "the clamp holds across reloads");
        assert_eq!(reloaded.snapshot().len(), 3, "records survive the reload");
    }

    #[test]
    fn a_control_byte_body_at_the_cap_survives_reload() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("requests.json");
        {
            let mut log = HookLog::load(path.clone(), 1).expect("load");
            let head = parts("POST", "/nul", &[]);
            let body = vec![0u8; MAX_REQUEST_BODY];
            log.record(RecordedRequest::capture(1, &head, &body))
                .expect("record");
        }
        let persisted_len = std::fs::metadata(&path).expect("store exists").len();
        assert!(
            persisted_len > (MAX_REQUEST_BODY + 96 * 1024) as u64,
            "the fixture must exceed the naive bound the old load() killed it by"
        );
        assert!(
            persisted_len <= store_read_bound(1),
            "the fixture must sit inside the escape-aware bound"
        );
        let reloaded = HookLog::load(path, 1).expect("reload");
        let snap = reloaded.snapshot();
        assert_eq!(snap.len(), 1, "a legitimate store must survive reload");
        assert_eq!(snap[0].body.len(), MAX_REQUEST_BODY);
        assert!(snap[0].body.bytes().all(|b| b == 0), "NULs round-trip");
    }

    #[test]
    fn a_quote_heavy_head_with_a_nul_body_survives_reload() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("requests.json");
        // ~120 KiB of quotes — under hyper's wire budget and the Uri cap, so
        // the origin accepts this head.
        let quote_path = format!("/{}", "\"".repeat(60_000));
        let quote_header = "\"".repeat(60_000);
        let head = parts("POST", &quote_path, &[("user-agent", &quote_header)]);
        {
            let mut log = HookLog::load(path.clone(), 1).expect("load");
            let body = vec![0u8; MAX_REQUEST_BODY];
            log.record(RecordedRequest::capture(1, &head, &body))
                .expect("record");
        }
        let persisted_len = std::fs::metadata(&path).expect("store exists").len();
        let round2_bound = (MAX_REQUEST_BODY * JSON_ESCAPE_FACTOR + 96 * 1024) as u64;
        assert!(
            persisted_len > round2_bound,
            "the fixture must exceed the round-2 bound the old load() killed it by"
        );
        assert!(
            persisted_len <= store_read_bound(1),
            "the fixture must sit inside the head-budget-aware bound"
        );
        let reloaded = HookLog::load(path, 1).expect("reload");
        let snap = reloaded.snapshot();
        assert_eq!(snap.len(), 1, "a legitimate store must survive reload");
        assert_eq!(snap[0].body.len(), MAX_REQUEST_BODY);
        assert!(snap[0].body.bytes().all(|b| b == 0), "NULs round-trip");
        assert_eq!(snap[0].path, quote_path, "the quote-heavy path round-trips");
        assert_eq!(
            snap[0].headers,
            vec![("user-agent".to_string(), quote_header)],
            "the quote-heavy header value round-trips"
        );
    }

    #[test]
    fn hook_log_survives_a_corrupt_store() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("requests.json");
        std::fs::write(&path, b"{ this is not json").expect("seed corrupt store");
        let log = HookLog::load(path, 5).expect("a corrupt store still loads (as empty)");
        assert_eq!(log.len(), 0, "corrupt store loads as empty");
    }

    #[test]
    fn load_starts_empty_when_the_store_does_not_exist() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let log = HookLog::load(tmp.path().join("requests.json"), 5)
            .expect("a missing store must load as empty");
        assert_eq!(log.len(), 0);
    }

    /// A read error that is NOT NotFound: a regular file occupying the
    /// store's parent slot (ENOTDIR on Unix; Windows differs, hence the gate).
    #[cfg(unix)]
    #[test]
    fn load_fails_fast_on_a_non_not_found_read_error_without_clobbering() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let blocker = tmp.path().join("blocker");
        std::fs::write(&blocker, b"intact").expect("write blocker file");
        let store = blocker.join("requests.json"); // parent is a FILE -> ENOTDIR

        let err =
            HookLog::load(store, 5).expect_err("a non-NotFound read error must fail the load");
        assert_ne!(
            err.kind(),
            std::io::ErrorKind::NotFound,
            "the failure must be a real read error, not a missing file"
        );
        assert_eq!(
            std::fs::read(&blocker).expect("blocker intact"),
            b"intact",
            "the failed load must not have touched the on-disk data"
        );
    }

    #[cfg(unix)]
    #[test]
    fn hook_log_store_is_private_and_stays_private() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("requests.json");
        std::fs::write(&path, b"[]").expect("seed");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("loosen perms");

        let mut log = HookLog::load(path.clone(), 5).expect("load");
        let head = parts("GET", "/x", &[]);
        log.record(RecordedRequest::capture(1, &head, b""))
            .expect("record");

        let mode = std::fs::metadata(&path)
            .expect("store exists")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "store must be owner-only");
    }

    // --- the full Router, driven like the static server's HTTP tests --------

    #[tokio::test]
    async fn recorded_requests_answer_200_and_land_in_the_store() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let log = Arc::new(Mutex::new(
            HookLog::load(tmp.path().join("requests.json"), usize::from(DEFAULT_KEEP))
                .expect("load"),
        ));
        let resp = router(log.clone())
            .oneshot(req("POST", "/hooks/gh?run=7", b"{\"ok\":true}"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);

        let snap = lock(&log).snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].method, "POST");
        assert_eq!(snap[0].path, "/hooks/gh");
        assert_eq!(snap[0].query.as_deref(), Some("run=7"));
        assert_eq!(snap[0].body, "{\"ok\":true}");
    }

    #[tokio::test]
    async fn json_view_serves_records_newest_first() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let log = Arc::new(Mutex::new(
            HookLog::load(tmp.path().join("requests.json"), usize::from(DEFAULT_KEEP))
                .expect("load"),
        ));
        for (i, body) in ["first", "second"].iter().enumerate() {
            let resp = router(log.clone())
                .oneshot(req("POST", "/x", body.as_bytes()))
                .await
                .expect("oneshot");
            assert_eq!(resp.status(), StatusCode::OK, "request {i}");
        }

        let resp = router(log.clone())
            .oneshot(req("GET", JSON_PATH, b""))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json",
        );
        let bytes = body_of(resp).await;
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).expect("valid json");
        let items = parsed.as_array().expect("array").clone();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0]["body"], "second", "newest first");
        assert_eq!(items[1]["body"], "first");
        assert_eq!(items[0]["path"], "/x");
        assert_eq!(items[0]["method"], "POST");
        assert!(items[0]["seq"].is_u64());
        assert!(items[0]["received_at"].is_string());
    }

    #[tokio::test]
    async fn inspect_view_renders_newest_first_and_escapes_markup() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let log = Arc::new(Mutex::new(
            HookLog::load(tmp.path().join("requests.json"), usize::from(DEFAULT_KEEP))
                .expect("load"),
        ));
        // Raw '<' is illegal in a request target — sent percent-encoded.
        router(log.clone())
            .oneshot(req("GET", "/old?a=%3Cb%3E", b"plain"))
            .await
            .expect("oneshot");
        router(log.clone())
            .oneshot(req("POST", "/new", b"<script>alert(1)</script>"))
            .await
            .expect("oneshot");

        let resp = router(log.clone())
            .oneshot(req("GET", INSPECT_PATH, b""))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/html; charset=utf-8"
        );
        let html = String::from_utf8(body_of(resp).await).expect("utf-8 html");
        let new = html.find("/new").expect("newest request listed");
        let old = html.find("/old").expect("older request listed");
        assert!(new < old, "newest requests must render first: {html}");
        assert!(
            html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"),
            "body must be escaped: {html}"
        );
        assert!(html.contains("/old?a=%3Cb%3E"), "query as sent: {html}");
        assert!(
            !html.contains("<script>"),
            "no raw markup may survive: {html}"
        );
        assert!(html.contains("Recorded requests"), "{html}");
        assert!(
            html.contains("system-ui"),
            "must use the shared style: {html}"
        );
    }

    #[tokio::test]
    async fn inspect_endpoints_are_not_recorded() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let log = Arc::new(Mutex::new(
            HookLog::load(tmp.path().join("requests.json"), usize::from(DEFAULT_KEEP))
                .expect("load"),
        ));
        router(log.clone())
            .oneshot(req("GET", INSPECT_PATH, b""))
            .await
            .expect("oneshot");
        router(log.clone())
            .oneshot(req("GET", JSON_PATH, b""))
            .await
            .expect("oneshot");
        assert_eq!(
            lock(&log).snapshot().len(),
            0,
            "inspection views must not be recorded"
        );
    }

    #[tokio::test]
    async fn non_get_on_the_inspect_paths_is_405_and_unrecorded() {
        // get() routes 405 other methods themselves, before the fallback —
        // pinned against axum changes.
        let tmp = tempfile::tempdir().expect("tempdir");
        let log = Arc::new(Mutex::new(
            HookLog::load(tmp.path().join("requests.json"), usize::from(DEFAULT_KEEP))
                .expect("load"),
        ));
        for path in [INSPECT_PATH, JSON_PATH] {
            let resp = router(log.clone())
                .oneshot(req("POST", path, b""))
                .await
                .expect("oneshot");
            assert_eq!(
                resp.status(),
                StatusCode::METHOD_NOT_ALLOWED,
                "POST {path} must be method-rejected"
            );
        }
        assert_eq!(
            lock(&log).snapshot().len(),
            0,
            "a 405'd inspect probe must not be recorded"
        );
    }

    #[tokio::test]
    async fn oversized_body_is_rejected_and_not_recorded() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let log = Arc::new(Mutex::new(
            HookLog::load(tmp.path().join("requests.json"), usize::from(DEFAULT_KEEP))
                .expect("load"),
        ));
        let big = vec![b'z'; MAX_REQUEST_BODY + 1];
        let resp = router(log.clone())
            .oneshot(req("POST", "/flood", &big))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            lock(&log).snapshot().len(),
            0,
            "an over-cap request must not be recorded"
        );
    }

    #[tokio::test]
    async fn origin_serves_over_a_real_socket_and_pre_rejects_declared_oversize() {
        // Real-TCP smoke (oneshot bypasses the HTTP server): a declared
        // oversize Content-Length is pre-rejected 413 by the limit layer.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let tmp = tempfile::tempdir().expect("tempdir");
        let log = Arc::new(Mutex::new(
            HookLog::load(tmp.path().join("requests.json"), usize::from(DEFAULT_KEEP))
                .expect("load"),
        ));
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind ephemeral loopback listener");
        let addr = listener.local_addr().expect("local addr");
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let server_log = log.clone();
        let server = tokio::spawn(async move {
            crate::server::static_server::serve_on(router(server_log), listener, async {
                let _ = shutdown_rx.await;
            })
            .await
        });

        let mut sock = tokio::net::TcpStream::connect(addr).await.expect("connect");
        sock.write_all(b"POST /real HTTP/1.1\r\nhost: smoke\r\ncontent-length: 5\r\n\r\nhello")
            .await
            .expect("write request");
        let mut buf = vec![0u8; 1024];
        let n = sock.read(&mut buf).await.expect("read response");
        let head = String::from_utf8_lossy(&buf[..n]).into_owned();
        assert!(
            head.starts_with("HTTP/1.1 200 OK"),
            "a recorded request must be answered 200, got: {head}"
        );

        let mut sock = tokio::net::TcpStream::connect(addr).await.expect("connect");
        sock.write_all(b"POST /flood HTTP/1.1\r\nhost: smoke\r\ncontent-length: 99999999\r\n\r\n")
            .await
            .expect("write oversized request");
        let n = sock.read(&mut buf).await.expect("read response");
        let head = String::from_utf8_lossy(&buf[..n]).into_owned();
        assert!(
            head.starts_with("HTTP/1.1 413"),
            "a declared-oversize body must be pre-rejected 413, got: {head}"
        );

        assert_eq!(
            lock(&log).snapshot().len(),
            1,
            "the 413 must not be recorded"
        );

        let _ = shutdown_tx.send(());
        let res = server.await.expect("join serve task");
        assert!(res.is_ok(), "serve_on drained without error: {res:?}");
    }

    #[tokio::test]
    async fn empty_store_renders_the_empty_notice() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let log = Arc::new(Mutex::new(
            HookLog::load(tmp.path().join("requests.json"), usize::from(DEFAULT_KEEP))
                .expect("load"),
        ));
        let resp = router(log.clone())
            .oneshot(req("GET", INSPECT_PATH, b""))
            .await
            .expect("oneshot");
        let html = String::from_utf8(body_of(resp).await).expect("utf-8 html");
        assert!(
            html.contains("no requests recorded yet"),
            "empty store must say so: {html}"
        );
    }
}
