//! Webhook receiver/inspector origin: an ft-owned loopback origin behind
//! cloudflared that records every request — method, path, query, allowlisted
//! headers, size-capped body — into a private JSON store and answers 200.
//! `GET /__inspect` (HTML) and `GET /__inspect.json` (JSON) render the
//! records newest-first; the inspection endpoints themselves are never
//! recorded. Header capture is an ALLOWLIST so credential-bearing headers
//! can never reach the store or the public inspection view.
//!
//! The store file is a JSON array maintained as an append window so a
//! record costs O(record), not O(retained bytes) (see [`HookLog::record`]).

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{Read as _, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

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
    /// Build a record from a request head + body + a caller-stamped receive
    /// time; pure, so the capture rules are unit-testable. The stamp is the
    /// CALLER's business so it can be taken before the store's lock wait —
    /// a queued request must report when it arrived, not when it was
    /// admitted.
    fn capture(seq: u64, received_at: DateTime<Utc>, parts: &Parts, body: &[u8]) -> Self {
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
            received_at,
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

/// Newest-first deque mirrored to `requests.json` (0600): front-push and
/// back-pop keep both the append and the eviction O(1) in memory.
#[derive(Debug)]
pub struct HookLog {
    path: PathBuf,
    keep: usize,
    next_seq: u64,
    /// Newest-first (front = newest) — by construction on append, by
    /// seq-sort on load.
    requests: VecDeque<RecordedRequest>,
    /// Immutable view snapshot, rebuilt lazily: a record invalidates it and
    /// the next view pays one O(keep) rebuild that every later view shares,
    /// so the write path never copies the store for the inspection routes.
    snapshot: Option<Arc<Vec<RecordedRequest>>>,
    /// Append-window cursors for the file on disk; `None` whenever the
    /// framing cannot be trusted (fresh load of foreign bytes, any io
    /// error), forcing the next record through a full atomic rewrite.
    window: Option<Window>,
}

/// Where the live records sit in `requests.json`. The file is
/// `[` + evicted-whitespace + records oldest-first `,`-separated +
/// tail-whitespace + `]`: appending the newest record writes only its own
/// bytes into the tail pad, evicting the oldest whitens only its own bytes
/// at the head — the retained bytes in between never move, so a record
/// costs O(record) of fs work instead of a whole-file rewrite.
#[derive(Debug)]
struct Window {
    /// Offset of the first live record (1 + evicted bytes).
    live_start: u64,
    /// Offset one past the last live record (start of the tail pad).
    live_end: u64,
    /// Total file length; the byte at `file_len - 1` is `]`.
    file_len: u64,
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

/// Tail-pad floor reserved by a full rewrite. The pad is what makes the
/// per-record appends possible; half the live bytes (floored here) keeps a
/// rewrite amortized over proportionally many records at any store shape.
const MIN_TAIL_PAD: usize = 64 * 1024;

/// Upper bound on a store this server could have written at `keep` records;
/// saturating, u64 for [`read_store_blob`]'s `File::take`. Live bytes only —
/// the journal's pad slack is added once, in [`absolute_read_bound`].
fn store_read_bound(keep: usize) -> u64 {
    let per_record = (MAX_REQUEST_BODY * JSON_ESCAPE_FACTOR + STORE_RECORD_OVERHEAD) as u64;
    (keep as u64).saturating_mul(per_record)
}

/// [`store_read_bound`] at [`MAX_KEEP`], independent of the loading keep — a
/// store written at ANY supported keep fits; load() truncates after — plus
/// the journal's own slack: a file is live bytes + pad (≤ live/2, floored at
/// [`MIN_TAIL_PAD`]) + the two framing bytes, all of it legitimate.
fn absolute_read_bound() -> u64 {
    let live = store_read_bound(MAX_KEEP);
    live + live / 2 + MIN_TAIL_PAD as u64 + 2
}

/// Read at most `bound + 1` bytes (the +1 tells at-the-bound from past-it);
/// bounding the READ, not just the parse, so no stray huge file is slurped.
/// `len_hint` (the stat that gated the read) reserves the Vec's capacity
/// up front instead of growing it geometrically.
fn read_store_blob(path: &Path, bound: u64, len_hint: u64) -> std::io::Result<Vec<u8>> {
    let file = File::open(path)?;
    let mut bytes = Vec::with_capacity(len_hint.min(bound.saturating_add(1)) as usize);
    file.take(bound.saturating_add(1)).read_to_end(&mut bytes)?;
    Ok(bytes)
}

impl HookLog {
    /// Load the store at `path`, or start empty when it does not exist. A
    /// corrupt (or past-the-ceiling) store degrades to empty: corruption
    /// implies disk trouble, and bricking the service is worse than
    /// restarting the log — webhook senders re-deliver. The exception is a
    /// TORN append window ([`repair_torn_window`]): the in-place protocol
    /// can only damage an edge, so the intact records are recovered instead
    /// of wiped. Any OTHER read error fails the load: the store may be
    /// intact behind it, and an empty fallback would let the next append's
    /// rename destroy it.
    /// The loaded store is re-truncated to `keep` — a lowered keep never
    /// wipes the log.
    pub fn load(path: PathBuf, keep: usize) -> std::io::Result<Self> {
        // keep arrives unvalidated on the hidden run-worker path; clamp so
        // retention can't write past the ceiling.
        let keep = keep.min(MAX_KEEP);
        let ceiling = absolute_read_bound();
        // One stat feeds both the oversized refusal and the read's capacity
        // hint — no second metadata() pass.
        let mut window = None;
        let mut requests = match std::fs::metadata(&path) {
            // Past the ceiling by metadata: refuse without reading a giant.
            Ok(m) if m.len() > ceiling => {
                tracing::warn!(
                    path = %path.display(),
                    "hook request store is larger than the absolute read bound; starting a new one"
                );
                Vec::new()
            }
            meta => {
                let len_hint = meta.as_ref().map(std::fs::Metadata::len).unwrap_or(0);
                match read_store_blob(&path, ceiling, len_hint) {
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
                            Ok(parsed) => {
                                window = Window::scan(&bytes, &parsed, keep);
                                parsed
                            }
                            Err(e) => match repair_torn_window(&bytes) {
                                Some(recovered) => {
                                    tracing::warn!(
                                        %e,
                                        path = %path.display(),
                                        recovered = recovered.len(),
                                        "hook request store is torn; recovering the intact records"
                                    );
                                    recovered
                                }
                                None => {
                                    tracing::warn!(%e, path = %path.display(), "hook request store is corrupt; starting a new one");
                                    Vec::new()
                                }
                            },
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
                    Ok(_) => Vec::new(),
                    Err(e) => return Err(e),
                }
            }
        };
        // The file is oldest-first, so reverse first: the stable sort then
        // keeps the LAST-recorded of equal (saturated) seqs in front, the
        // same tie-break the record path's deque order gives.
        requests.reverse();
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
            requests: requests.into(),
            snapshot: None,
            window,
        })
    }

    /// Insert + persist. Steady state is O(record): the new record is
    /// serialized once and written into the file's tail pad, the evicted
    /// oldest is whitened in place — the retained bytes in between never
    /// move. Only when the pad runs out (or after a load of untrusted
    /// framing, or an io error) does [`HookLog::reserve`] rewrite the whole
    /// file atomically, amortized over half-the-live-bytes of pad.
    ///
    /// No fsync, by contract: exactly like the old whole-file persist,
    /// durability ends at the page cache — the drop store's fsync
    /// asymmetry is documented behavior, not a bug to fix here; any future
    /// fsync must ride a group commit, never land per record.
    ///
    /// `pub(crate)` so the benches can drive the record->persist path
    /// directly; same-crate visibility only, no behavior change.
    pub(crate) fn record(&mut self, req: RecordedRequest) -> std::io::Result<()> {
        self.snapshot = None;
        self.requests.push_front(req);
        let bytes =
            serde_json::to_vec(self.requests.front().expect("just pushed")).map_err(ser_io)?;
        let fits = self.window.as_ref().is_some_and(|w| {
            // Strictly greater: the extra byte is the separator comma; an
            // empty live region skips it, so this over-requires by one.
            w.file_len - 1 - w.live_end > bytes.len() as u64
        });
        if !fits {
            // Evict in memory first so the rewrite carries exactly the
            // retained set.
            while self.requests.len() > self.keep {
                self.requests.pop_back();
            }
            return self.reserve();
        }
        let evict = self.requests.len() > self.keep;
        let mut window = self.window.take().expect("fits implies a window");
        let result = match OpenOptions::new().write(true).open(&self.path) {
            Ok(mut file) => (|| {
                append_at(&mut file, &mut window, &bytes)?;
                if evict {
                    let oldest = self.requests.pop_back().expect("evict implies an oldest");
                    let oldest_bytes = serde_json::to_vec(&oldest).map_err(ser_io)?;
                    evict_at(
                        &mut file,
                        &mut window,
                        &oldest_bytes,
                        !self.requests.is_empty(),
                    )?;
                }
                Ok(())
            })(),
            // The store vanished under a live window (external deletion):
            // recreate it in THIS delivery, like the old whole-file persist
            // did — the retry contract is for real disk trouble, not this.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                while self.requests.len() > self.keep {
                    self.requests.pop_back();
                }
                return self.reserve();
            }
            Err(e) => Err(e),
        };
        match result {
            Ok(()) => self.window = Some(window),
            // In-place edits may have torn the framing mid-write; force a
            // full rewrite on the next record.
            Err(_) => self.window = None,
        }
        result
    }

    /// Saturates like load (see the comment there); at saturation duplicate
    /// seqs are unavoidable, but the stable sort keeps the order well-defined.
    fn next_seq(&mut self) -> u64 {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        seq
    }

    /// Shared immutable snapshot for the inspection views: the Arc hand-off
    /// is a clone, not a store copy under the lock, and consecutive views
    /// share one rebuild until the next record invalidates it.
    fn snapshot_arc(&mut self) -> Arc<Vec<RecordedRequest>> {
        Arc::clone(
            self.snapshot
                .get_or_insert_with(|| Arc::new(self.requests.iter().cloned().collect())),
        )
    }

    /// Point-in-time copy, bounded by `keep` × the body cap (tests; the
    /// views take the shared [`HookLog::snapshot_arc`]).
    #[cfg(test)]
    fn snapshot(&mut self) -> Vec<RecordedRequest> {
        self.requests.iter().cloned().collect()
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.requests.len()
    }

    /// The only O(retained) write, paid on a load of untrusted framing,
    /// after io errors, and when the tail pad runs out. Atomic tmp+rename
    /// with private perms (the store carries request paths and bodies — the
    /// logs' 0600 class): a crash leaves either the old or the new file,
    /// never a torn one.
    fn reserve(&mut self) -> std::io::Result<()> {
        let mut data = Vec::with_capacity(self.requests.len() * 256 + MIN_TAIL_PAD + 2);
        data.push(b'[');
        for record in self.requests.iter().rev() {
            if data.len() > 1 {
                data.push(b',');
            }
            let bytes = serde_json::to_vec(record).map_err(ser_io)?;
            data.extend_from_slice(&bytes);
        }
        let live_end = data.len() as u64;
        let pad = (live_end / 2).max(MIN_TAIL_PAD as u64);
        data.resize(data.len() + pad as usize, b' ');
        data.push(b']');
        let tmp = self.path.with_extension("json.tmp");
        {
            let mut opts = OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            crate::fsutil::apply_private_mode(&mut opts);
            let mut file = opts.open(&tmp)?;
            file.write_all(&data)?;
        }
        std::fs::rename(&tmp, &self.path)?;
        self.window = Some(Window {
            live_start: 1,
            live_end,
            file_len: data.len() as u64,
        });
        Ok(())
    }
}

impl Window {
    /// Trust the on-disk framing only when the file is byte-for-byte
    /// something this store writes: bracket-framed with no whitespace
    /// outside the brackets, records already in canonical oldest-first
    /// order (non-decreasing seq — the in-place evict whitens the LEFT
    /// end), nothing about to be truncated (the live region must equal the
    /// retained set), and every record re-serializing to its exact on-disk
    /// length (serde is deterministic for these values, but a format
    /// change across binary versions must force a rewrite, not corrupt
    /// the file). Anything else — hand-edited, legacy newest-first —
    /// returns None and the next record rewrites the file atomically.
    fn scan(bytes: &[u8], parsed: &[RecordedRequest], keep: usize) -> Option<Self> {
        if parsed.len() > keep
            || parsed.windows(2).any(|pair| pair[0].seq > pair[1].seq)
            || bytes.first() != Some(&b'[')
            || bytes.last() != Some(&b']')
        {
            return None;
        }
        let interior = &bytes[1..bytes.len() - 1];
        let live_start = interior
            .iter()
            .position(|b| !b.is_ascii_whitespace())
            .map_or(1, |i| 1 + i as u64);
        let live_end = interior
            .iter()
            .rposition(|b| !b.is_ascii_whitespace())
            .map_or(live_start, |i| 2 + i as u64);
        let mut cursor = live_start;
        for (i, record) in parsed.iter().enumerate() {
            let ser = serde_json::to_vec(record).ok()?;
            cursor += ser.len() as u64 + u64::from(i > 0);
        }
        (cursor == live_end).then_some(Self {
            live_start,
            live_end,
            file_len: bytes.len() as u64,
        })
    }
}

/// serde failures are not io, but every caller of them is doing fs work and
/// reports `io::Result` — fold the message in.
fn ser_io(e: serde_json::Error) -> std::io::Error {
    std::io::Error::other(format!("serializing a recorded request: {e}"))
}

/// Recover the intact records from a torn append window. The in-place
/// protocol can only damage an EDGE of the array — a partial new record at
/// the right (append torn mid-write) or the remnant of a half-whitened
/// oldest at the left (evict torn mid-write) — so recovery keeps every
/// complete, well-formed record and drops leading junk plus an incomplete
/// trailing value. Damage between two good records (or complete-but-invalid
/// trailing bytes) is foreign corruption: None, and the caller wipes as
/// before. Without this, a crash between a torn write and the next
/// successful record cost the WHOLE retained history — a loss path the old
/// atomic tmp+rename persist excluded.
fn repair_torn_window(bytes: &[u8]) -> Option<Vec<RecordedRequest>> {
    if bytes.first() != Some(&b'[') || bytes.last() != Some(&b']') {
        return None;
    }
    let interior = &bytes[1..bytes.len() - 1];
    let mut ranges: Vec<std::ops::Range<usize>> = Vec::new();
    let mut i = 0;
    while i < interior.len() {
        while i < interior.len() && interior[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= interior.len() {
            break;
        }
        if interior[i] == b',' {
            // A separator at value position is edge damage too (a torn
            // evict that whitened the record but not its comma, or a torn
            // append that wrote only the comma).
            i += 1;
            continue;
        }
        match scan_value(interior, i) {
            Some(end) => {
                ranges.push(i..end);
                i = end;
            }
            // An incomplete value is the torn new record; it simply yields
            // no range.
            None => break,
        }
    }
    let mut records = Vec::with_capacity(ranges.len());
    for range in ranges {
        match serde_json::from_slice::<RecordedRequest>(&interior[range]) {
            Ok(record) => records.push(record),
            // A torn evict leaves the remnant of ONE half-whitened record
            // at the head; anything invalid AFTER a good record is foreign
            // corruption, not a tear.
            Err(_) if records.is_empty() => continue,
            Err(_) => return None,
        }
    }
    Some(records)
}

/// Scan one comma-separated JSON value starting at `start` (a non-ws,
/// non-comma byte); the exclusive end offset, or None when the value does
/// not complete before the buffer ends (a torn write). Mismatched garbage
/// brackets can "complete" early — harmless: the range then fails
/// deserialization and is treated as damage.
fn scan_value(bytes: &[u8], start: usize) -> Option<usize> {
    let end = bytes.len();
    match bytes[start] {
        b'"' => {
            let mut i = start + 1;
            while i < end {
                match bytes[i] {
                    b'\\' => i += 2,
                    b'"' => return Some(i + 1),
                    _ => i += 1,
                }
            }
            None
        }
        b'{' | b'[' => {
            let mut depth = 0usize;
            let mut in_string = false;
            let mut i = start;
            while i < end {
                let b = bytes[i];
                if in_string {
                    if b == b'\\' {
                        i += 2;
                        continue;
                    }
                    if b == b'"' {
                        in_string = false;
                    }
                } else {
                    match b {
                        b'"' => in_string = true,
                        b'{' | b'[' => depth += 1,
                        b'}' | b']' => {
                            depth = depth.checked_sub(1)?;
                            if depth == 0 {
                                return Some(i + 1);
                            }
                        }
                        _ => {}
                    }
                }
                i += 1;
            }
            None
        }
        _ => {
            let mut i = start;
            while i < end && !(bytes[i] == b',' || bytes[i].is_ascii_whitespace()) {
                i += 1;
            }
            Some(i)
        }
    }
}

/// Positional write: seek+write_all stands in for pwrite (portable), and no
/// reader exists outside the store's mutex, so the seek is race-free.
fn write_at(file: &mut File, offset: u64, bytes: &[u8]) -> std::io::Result<()> {
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(bytes)
}

/// Write the newest record into the tail pad; the retained bytes are
/// untouched. `window` must describe the live region exactly (see
/// [`Window::scan`]).
fn append_at(file: &mut File, window: &mut Window, bytes: &[u8]) -> std::io::Result<()> {
    let mut framed = Vec::with_capacity(bytes.len() + 1);
    if window.live_start != window.live_end {
        framed.push(b',');
    }
    framed.extend_from_slice(bytes);
    write_at(file, window.live_end, &framed)?;
    window.live_end += framed.len() as u64;
    Ok(())
}

/// Whiten the evicted oldest record (and its trailing separator) at the
/// head of the live region: the file keeps its length, the array just
/// loses its last element.
fn evict_at(
    file: &mut File,
    window: &mut Window,
    oldest: &[u8],
    more_remain: bool,
) -> std::io::Result<()> {
    let len = oldest.len() + usize::from(more_remain);
    write_at(file, window.live_start, &vec![b' '; len])?;
    window.live_start += len as u64;
    Ok(())
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
    // Stamped before the blocking hop and the store's lock wait: a request
    // queued behind another delivery reports when it ARRIVED, not when it
    // was admitted.
    let received_at = crate::model::now_utc();
    // Blocking fs work off the async threads (request-path discipline).
    let persisted = tokio::task::spawn_blocking(move || {
        let mut log = lock(&log);
        let seq = log.next_seq();
        let record = RecordedRequest::capture(seq, received_at, &parts, &bytes);
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
/// the store write, so an async-side lock() could park a tokio worker. The
/// Arc hand-off makes the lock hold a clone, not a store copy.
async fn snapshot_offline(log: &Arc<Mutex<HookLog>>) -> Arc<Vec<RecordedRequest>> {
    let log = Arc::clone(log);
    tokio::task::spawn_blocking(move || lock(&log).snapshot_arc())
        .await
        .unwrap_or_default()
}

async fn inspect_html(State(log): State<Arc<Mutex<HookLog>>>) -> Html<String> {
    let requests = snapshot_offline(&log).await;
    // Rendering walks every retained record — off the async runtime thread.
    let html = tokio::task::spawn_blocking(move || render_inspection(&requests))
        .await
        .unwrap_or_default();
    Html(html)
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

/// Same payload `Json<Vec<RecordedRequest>>` served, but serialized off the
/// async runtime thread (it is O(retained bytes)) straight from the shared
/// snapshot — no second deep copy under the lock.
async fn inspect_json(State(log): State<Arc<Mutex<HookLog>>>) -> Response {
    let requests = snapshot_offline(&log).await;
    let body =
        tokio::task::spawn_blocking(move || serde_json::to_vec(&*requests).map_err(ser_io)).await;
    match body {
        Ok(Ok(bytes)) => (
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )],
            bytes,
        )
            .into_response(),
        Ok(Err(e)) => {
            tracing::error!(%e, "failed to serialize the inspection view");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to serialize the inspection view\n",
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!(%e, "inspection view task panicked");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to render the inspection view\n",
            )
                .into_response()
        }
    }
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
    /// A receive stamp for [`RecordedRequest::capture`]; no pinned rule
    /// asserts on the value, only on where it is taken (see `record`).
    fn recv_stamp() -> DateTime<Utc> {
        crate::model::now_utc()
    }

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
        let r = RecordedRequest::capture(7, recv_stamp(), &head, b"{\"a\":1}");
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
        let r = RecordedRequest::capture(1, recv_stamp(), &head, b"");
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
        let r = RecordedRequest::capture(1, recv_stamp(), &head, &big);
        assert_eq!(r.body_len, MAX_REQUEST_BODY + 1234);
        assert_eq!(r.body.len(), MAX_REQUEST_BODY);
        assert!(r.truncated);
    }

    #[test]
    fn capture_preserves_non_utf8_bodies_lossily() {
        let head = parts("POST", "/x", &[]);
        let binary = [0xff, 0xfe, b'a', b'b'];
        let r = RecordedRequest::capture(1, recv_stamp(), &head, &binary);
        assert_eq!(r.body_len, 4);
        assert!(
            r.body.contains('\u{FFFD}'),
            "lossy decode expected: {:?}",
            r.body
        );
    }

    /// transfer-A11 pin: [`HYPER_HEAD_BUDGET`] must recompute hyper's own
    /// whole-wire head budget — hyper-1.10.1 `src/proto/h1/io.rs:22-24`
    /// (`DEFAULT_MAX_BUFFER_SIZE = 8192 + 4096 * 100`) built from
    /// `src/proto/h1/role.rs:31` (`DEFAULT_MAX_HEADERS = 100`). If hyper
    /// grows a default and this drifts low, load() classes legitimate
    /// stores as oversized and the next append wipes the whole history.
    #[test]
    fn hyper_head_budget_is_pinned_to_hyper_1_10_wire_defaults() {
        let recomputed = 8 * 1024 + 4 * 1024 * 100;
        assert_eq!(
            HYPER_HEAD_BUDGET, recomputed,
            "HYPER_HEAD_BUDGET must equal hyper's DEFAULT_MAX_BUFFER_SIZE"
        );
        assert_eq!(
            STORE_RECORD_OVERHEAD,
            HYPER_HEAD_BUDGET * 2 + 2 * 1024,
            "the per-record allowance must inherit the head pin"
        );
        let worst_case_file = store_read_bound(MAX_KEEP) * 3 / 2 + MIN_TAIL_PAD as u64 + 2;
        assert!(
            absolute_read_bound() >= worst_case_file,
            "the read bound must cover the padded journal a full store produces"
        );
    }

    /// The read bound refuses nothing AT the bound: a fixture of exactly
    /// `bound` bytes reads in full, while the +1 slack is what surfaces a
    /// past-the-bound fixture as longer than the bound (the load gate's
    /// only discriminator between at-it and past-it).
    #[test]
    fn read_store_blob_reads_a_fixture_exactly_at_the_bound_in_full() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let bound: u64 = 1024;
        let at_path = tmp.path().join("at.json");
        std::fs::write(&at_path, vec![b' '; bound as usize]).expect("at-bound fixture");
        let at =
            read_store_blob(&at_path, bound, bound).expect("an at-bound fixture must read in full");
        assert_eq!(at.len() as u64, bound, "the bound itself is not a refusal");
        let past_path = tmp.path().join("past.json");
        std::fs::write(&past_path, vec![b' '; bound as usize + 1]).expect("past-bound fixture");
        let past = read_store_blob(&past_path, bound, bound + 1).expect("read");
        assert_eq!(
            past.len() as u64,
            bound + 1,
            "the +1 slack must surface a past-bound fixture as over the bound"
        );
    }

    #[test]
    fn hook_log_keeps_only_the_newest_requests() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("requests.json");
        let mut log = HookLog::load(path.clone(), 3).expect("load");
        for seq in 1..=5u64 {
            let head = parts("GET", &format!("/{seq}"), &[]);
            let record = RecordedRequest::capture(seq, recv_stamp(), &head, b"");
            log.record(record).expect("record");
        }
        assert_eq!(log.len(), 3);
        let snap = log.snapshot();
        let seqs: Vec<u64> = snap.iter().map(|r| r.seq).collect();
        assert_eq!(seqs, vec![5, 4, 3], "newest first, oldest evicted");
        let mut reloaded = HookLog::load(path, 3).expect("reload");
        assert_eq!(reloaded.snapshot(), snap);
    }

    #[test]
    fn hook_log_persists_and_reloads_with_continuing_seqs() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("requests.json");
        {
            let mut log = HookLog::load(path.clone(), 10).expect("load");
            let head = parts("POST", "/first", &[]);
            log.record(RecordedRequest::capture(1, recv_stamp(), &head, b"one"))
                .expect("record");
        }
        let mut log = HookLog::load(path, 10).expect("reload");
        assert_eq!(log.snapshot().len(), 1);
        assert_eq!(log.snapshot()[0].path, "/first");
        let seq = log.next_seq();
        let head = parts("POST", "/second", &[]);
        log.record(RecordedRequest::capture(seq, recv_stamp(), &head, b"two"))
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
            log.record(RecordedRequest::capture(
                u64::MAX,
                recv_stamp(),
                &head,
                b"seed",
            ))
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
        log.record(RecordedRequest::capture(seq, recv_stamp(), &head, b"after"))
            .expect("record at MAX seq");
        assert_eq!(log.len(), 2);
        let mut reloaded = HookLog::load(path, 5).expect("reload after the append");
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
                log.record(RecordedRequest::capture(seq, recv_stamp(), &head, &body))
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
        let mut reloaded = HookLog::load(path, 1).expect("reload with a lowered keep");
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
            log.record(RecordedRequest::capture(seq, recv_stamp(), &head, b"x"))
                .expect("record");
        }
        let mut reloaded = HookLog::load(path, over_max).expect("reload");
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
            log.record(RecordedRequest::capture(1, recv_stamp(), &head, &body))
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
        let mut reloaded = HookLog::load(path, 1).expect("reload");
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
            log.record(RecordedRequest::capture(1, recv_stamp(), &head, &body))
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
        let mut reloaded = HookLog::load(path, 1).expect("reload");
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
        log.record(RecordedRequest::capture(1, recv_stamp(), &head, b""))
            .expect("record");

        let mode = std::fs::metadata(&path)
            .expect("store exists")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "store must be owner-only");
    }

    /// A run long enough to cross the tail-pad exhaustion (several full
    /// rewrites): the append-window cursors must still describe the file
    /// exactly, or in-place appends/evicts would silently corrupt it.
    #[test]
    fn many_records_keep_the_window_truthful_across_rewrites() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("requests.json");
        let mut log = HookLog::load(path.clone(), 7).expect("load");
        for seq in 1..=2_000u64 {
            let head = parts("POST", &format!("/{seq}"), &[]);
            log.record(RecordedRequest::capture(seq, recv_stamp(), &head, b"pay"))
                .expect("record");
        }
        assert_eq!(log.len(), 7);
        let snap = log.snapshot();
        let seqs: Vec<u64> = snap.iter().map(|r| r.seq).collect();
        assert_eq!(seqs, vec![2_000, 1_999, 1_998, 1_997, 1_996, 1_995, 1_994]);
        let mut reloaded = HookLog::load(path, 7).expect("reload after the long run");
        assert_eq!(reloaded.snapshot(), snap, "the window must land intact");
    }

    /// A legacy (or hand-edited) newest-first array is not this store's
    /// canonical oldest-first framing: it must still load, and the next
    /// record must rewrite it into the canonical layout instead of
    /// appending into cursors that do not describe it.
    #[test]
    fn a_legacy_newest_first_store_loads_and_is_normalized_on_the_next_record() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("requests.json");
        let legacy = vec![
            RecordedRequest::capture(2, recv_stamp(), &parts("POST", "/new", &[]), b""),
            RecordedRequest::capture(1, recv_stamp(), &parts("POST", "/old", &[]), b""),
        ];
        std::fs::write(
            &path,
            serde_json::to_vec(&legacy).expect("serialize legacy"),
        )
        .expect("plant legacy store");

        let mut log = HookLog::load(path.clone(), 5).expect("load");
        let seqs: Vec<u64> = log.snapshot().iter().map(|r| r.seq).collect();
        assert_eq!(seqs, vec![2, 1], "legacy records load newest-first");

        let head = parts("POST", "/after", &[]);
        log.record(RecordedRequest::capture(3, recv_stamp(), &head, b"x"))
            .expect("record");
        let mut reloaded = HookLog::load(path.clone(), 5).expect("reload");
        let paths: Vec<String> = reloaded.snapshot().into_iter().map(|r| r.path).collect();
        assert_eq!(paths, vec!["/after", "/new", "/old"]);
        // The normalized file is a plain JSON array — the format any
        // external reader (and the bench) expects.
        let on_disk: Vec<RecordedRequest> =
            serde_json::from_slice(&std::fs::read(&path).expect("read the store"))
                .expect("the store file stays a JSON array");
        assert_eq!(on_disk.len(), 3);
    }

    /// A crash mid-append leaves a partial record at the right edge: the
    /// intact records must come back instead of the whole store wiping.
    #[test]
    fn a_torn_append_keeps_the_intact_records_on_reload() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("requests.json");
        let rec1 = RecordedRequest::capture(1, recv_stamp(), &parts("POST", "/one", &[]), b"one");
        let rec2 = RecordedRequest::capture(2, recv_stamp(), &parts("POST", "/two", &[]), b"two");
        let mut torn = Vec::new();
        torn.push(b'[');
        torn.extend(serde_json::to_vec(&rec1).expect("serialize"));
        torn.push(b',');
        torn.extend(serde_json::to_vec(&rec2).expect("serialize"));
        torn.push(b',');
        torn.extend(br#"{"seq":3,"path":"/thre"#); // the torn new record
        torn.extend_from_slice(b"      ");
        torn.push(b']');
        std::fs::write(&path, &torn).expect("plant torn store");

        let mut log = HookLog::load(path.clone(), 5).expect("reload");
        let snap = log.snapshot();
        assert_eq!(snap.len(), 2, "the intact records survive the torn edge");
        assert_eq!(snap[0].path, "/two", "newest first as always");
        // The recovered store keeps recording; the next record rewrites it
        // into the canonical framing.
        let head = parts("POST", "/after", &[]);
        log.record(RecordedRequest::capture(3, recv_stamp(), &head, b"x"))
            .expect("record");
        let mut reloaded = HookLog::load(path, 5).expect("reload after recovery");
        let paths: Vec<String> = reloaded.snapshot().into_iter().map(|r| r.path).collect();
        assert_eq!(paths, vec!["/after", "/two", "/one"]);
    }

    /// A crash mid-evict leaves the remnant of the half-whitened oldest at
    /// the left edge — or just its separator comma, when the whitening
    /// consumed the record bytes but not the comma: the records behind it
    /// must come back.
    #[test]
    fn a_torn_evict_keeps_the_records_behind_it_on_reload() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("requests.json");
        let rec1 = RecordedRequest::capture(1, recv_stamp(), &parts("POST", "/old", &[]), b"");
        let rec2 = RecordedRequest::capture(2, recv_stamp(), &parts("POST", "/new", &[]), b"");
        let ser1 = serde_json::to_vec(&rec1).expect("serialize");
        let mut torn = Vec::new();
        torn.push(b'[');
        torn.extend_from_slice(b"   ");
        torn.extend_from_slice(&ser1[ser1.len() / 2..]);
        torn.push(b',');
        torn.extend(serde_json::to_vec(&rec2).expect("serialize"));
        torn.extend_from_slice(b"    ");
        torn.push(b']');
        std::fs::write(&path, &torn).expect("plant torn store");

        let mut log = HookLog::load(path.clone(), 5).expect("reload");
        let snap = log.snapshot();
        assert_eq!(snap.len(), 1, "the records behind the torn edge survive");
        assert_eq!(snap[0].path, "/new");

        let mut torn = Vec::new();
        torn.push(b'[');
        torn.extend_from_slice(b" , ");
        torn.extend(serde_json::to_vec(&rec2).expect("serialize"));
        torn.extend_from_slice(b"  ");
        torn.push(b']');
        std::fs::write(&path, &torn).expect("plant separator-only torn store");
        let mut log = HookLog::load(path, 5).expect("reload");
        assert_eq!(log.snapshot().len(), 1);
        assert_eq!(log.snapshot()[0].path, "/new");
    }

    /// Damage BETWEEN two good records is not a tear shape: foreign
    /// corruption keeps the wipe semantics.
    #[test]
    fn foreign_damage_between_good_records_still_wipes() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("requests.json");
        let rec1 = RecordedRequest::capture(1, recv_stamp(), &parts("POST", "/one", &[]), b"");
        let rec2 = RecordedRequest::capture(2, recv_stamp(), &parts("POST", "/two", &[]), b"");
        let mut damaged = Vec::new();
        damaged.push(b'[');
        damaged.extend(serde_json::to_vec(&rec1).expect("serialize"));
        damaged.push(b',');
        damaged.extend_from_slice(b"42");
        damaged.push(b',');
        damaged.extend(serde_json::to_vec(&rec2).expect("serialize"));
        damaged.push(b']');
        std::fs::write(&path, &damaged).expect("plant damaged store");

        let log = HookLog::load(path, 5).expect("reload");
        assert_eq!(log.len(), 0, "interior damage must wipe, not half-recover");
    }

    /// External deletion mid-run: the old whole-file persist recreated the
    /// store in the same delivery; the append window must too, not 500
    /// once and wait for the sender's retry.
    #[test]
    fn record_recreates_an_externally_deleted_store_in_the_same_delivery() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("requests.json");
        let mut log = HookLog::load(path.clone(), 5).expect("load");
        let head = parts("POST", "/first", &[]);
        log.record(RecordedRequest::capture(1, recv_stamp(), &head, b"one"))
            .expect("record");
        std::fs::remove_file(&path).expect("delete the store under a live window");

        let head = parts("POST", "/second", &[]);
        log.record(RecordedRequest::capture(2, recv_stamp(), &head, b"two"))
            .expect("record must recreate the store, not 500 once");
        assert!(path.exists(), "the store is back in THIS delivery");
        let mut reloaded = HookLog::load(path, 5).expect("reload");
        let paths: Vec<String> = reloaded.snapshot().into_iter().map(|r| r.path).collect();
        assert_eq!(paths, vec!["/second", "/first"]);
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
