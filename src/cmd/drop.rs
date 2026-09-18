//! The DROP command.
//!
//! `ft drop <dir>` runs an ft-owned upload-receiver origin (see
//! `drop_server`) behind a cloudflared Quick Tunnel and registers the result
//! like any other service. The background flow mirrors
//! START/PROXY/RUN/HOOK's reserve-entry → spawn-worker → poll-for-URL shape;
//! the worker binds the origin itself on `127.0.0.1:<port>` (fail-fast on a
//! bind error), so success is "URL published" — no separate origin probe.
//!
//! Unlike HOOK there is a directory — the upload TARGET — so the START flow's
//! directory safety checks (`resolve_dir` + `is_sensitive_dir`) run here too,
//! BEFORE any state is touched, and the worker re-runs them inside the
//! detached process (same defense-in-depth split as Static). A sensitive
//! directory is refused UNCONDITIONALLY — no `--yes` exists on this command,
//! because a drop bucket is WRITE-TOUCHED by the public tunnel: it is a
//! strictly more dangerous target than a read-only static publish, and a
//! detached worker could not confirm anyway.
//!
//! The access token is resolved before any state is touched: `--token` (which
//! must be non-empty after trimming — it is trimmed once at this boundary and
//! the trimmed value is what gets stored, printed, and compared) or a freshly
//! minted one ([`drop_server::generate_token`] — OS CSPRNG). The token is
//! written into the service's private state dir
//! ([`drop_server::store_token`], 0600) after the entry is reserved and
//! before the worker is spawned (the worker reads it back at startup — same
//! fail-fast window as the hook's request store), printed once on success,
//! and shown by `ft detail`.
//!
//! One bucket, one owner: a directory that is ALREADY a drop target refuses a
//! second drop service (checked inside the reserve's flock, so concurrent
//! starts are serialized — see [`find_drop_dir_conflict`]). Two drop origins
//! on one directory would race their writes and stack their total-cap
//! allowances; the drop origin's write path is additionally cross-process
//! safe on its own (per-service temp names + collision-checked hard-link
//! publish, see `drop_server`), which covers shapes the registry cannot see
//! (hand-edited entries).
//!
//! The foreground flow duplicates the shared foreground machinery from
//! `cmd/start.rs` (`run_foreground_inner`) instead of extending it — that
//! file is outside this area's allowed paths, and the repo's frozen-core
//! rule says duplication with "keep the two in sync" comments beats touching
//! shared files (the same trade START/PROXY/RUN/HOOK already make for
//! `last_reason`/`last_line`, the poll loop, and `EntryGuard`). Keep in sync
//! with `cmd/start.rs::run_foreground_inner` (and `cmd/hook.rs`'s copy) if
//! its teardown order changes.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, bail, ensure};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::Mutex;

use crate::cloudflared;
use crate::cmd::start::{is_sensitive_dir, resolve_dir};
use crate::drop_server::{self, DropStore};
use crate::error::Result;
use crate::model::{Registry, Service, ServiceKind};
use crate::name;
use crate::output;
use crate::port;
use crate::proc;
use crate::spawn;
use crate::state::StateDir;

/// Reload cadence while waiting for the worker to publish the public URL.
/// Mirrors START/PROXY/RUN/HOOK's poll loop (whose helpers are private to
/// `cmd/start.rs`).
const POLL_INTERVAL: Duration = Duration::from_millis(250);
/// Upper bound on how long the parent will wait for the tunnel URL.
const POLL_TIMEOUT: Duration = Duration::from_secs(30);
/// Most bytes read from a log when surfacing a start-failure reason. Logs can
/// grow large; only the trailing window is examined (the first, partial line
/// after a mid-file seek is skipped).
const LAST_REASON_CAP: u64 = 16 * 1024;
/// Upper bound on draining in-flight uploads on Ctrl-C before we abort the
/// server task, so a stuck request can't hang the foreground command.
/// Mirrors `cmd/start.rs`'s foreground drain bound.
const SERVER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(3);

/// Entry point for the DROP command.
pub async fn run(
    dir: PathBuf,
    port: Option<u16>,
    name: Option<String>,
    foreground: bool,
    token: Option<String>,
    max_size: Option<u64>,
) -> Result<()> {
    // Pre-flight 1: the upload target. The origin both reads and WRITES this
    // directory, so it must resolve like a static publish — and sensitive
    // directories are refused unconditionally (see the module docs). Runs
    // BEFORE any state is touched so a rejection leaves zero state.
    let dir = resolve_dir(&dir)?;
    ensure!(
        !is_sensitive_dir(&dir),
        "refusing to use {} as a drop bucket: it is a sensitive directory, and \
         uploads WRITE into it through a public tunnel",
        dir.display()
    );

    // Pre-flight 2: the origin is ft's own server, so the port must be FREE —
    // the inverse of PROXY's pre-flight, same reasoning as HOOK: a friendly
    // up-front failure beats a tunnel fronting a worker that dies on its bind
    // check seconds later.
    let port = match port {
        Some(p) => {
            ensure!(
                port::is_port_free(p),
                "port {p} is already in use — ft's drop origin needs to bind it \
                 (is another instance still running?)"
            );
            p
        }
        None => port::allocate_free_port()?,
    };

    // The token is resolved up front so every refusal above and below happens
    // before any state exists. An explicitly EMPTY (or whitespace-only) token
    // would authenticate nothing; refuse it rather than silently minting one
    // (the operator asked for a specific secret). Resolved TRIMMED ONCE, HERE:
    // the value [`resolve_token`] returns is the single binding every consumer
    // downstream sees — the token file, the printed credential, and the
    // origin's in-memory token — so a shell-quoted token with edge whitespace
    // cannot end up stored untrimmed and 401 every upload while the operator
    // pastes the trimmed one.
    let token = resolve_token(token)?;
    // Bounds the per-upload cap; the total-store cap is the fixed
    // drop_server::MAX_TOTAL_STORE (documented single-knob contract).
    let max_size = max_size.unwrap_or(drop_server::DEFAULT_MAX_SIZE);

    if foreground {
        run_foreground(dir, port, name, token, max_size).await
    } else {
        run_background(dir, port, name, token, max_size).await
    }
}

/// Resolve the drop access token: the operator's `--token` trimmed ONCE (the
/// trim is the point — validation, the stored token file, the printed
/// credential, and the origin's comparison value must all be the SAME string,
/// so an edge-whitespace shell quote cannot produce a stored secret that
/// 401s its own pasted twin), refused when whitespace-only, or a freshly
/// minted one ([`drop_server::generate_token`], OS CSPRNG) when omitted.
fn resolve_token(token: Option<String>) -> Result<String> {
    match token {
        Some(t) => {
            let t = t.trim();
            ensure!(!t.is_empty(), "--token must be a non-empty secret");
            Ok(t.to_string())
        }
        None => drop_server::generate_token().context("generating an upload token"),
    }
}

/// Background flow: reserve the entry, write the token file, spawn the
/// detached DROP worker (which binds the origin itself), then poll for the
/// tunnel URL (failing fast if the worker dies first).
///
/// Mirrors `cmd::start::run_background`/`cmd::proxy`/`cmd::run`/`cmd::hook`
/// shape-for-shape; the scaffolding is duplicated rather than shared because
/// the static flow's helpers stay private to `cmd/start.rs` (frozen for this
/// area); keep the five in sync.
async fn run_background(
    dir: PathBuf,
    port: u16,
    name: Option<String>,
    token: String,
    max_size: u64,
) -> Result<()> {
    let state = StateDir::new()?;

    // --- cloudflared ------------------------------------------------------
    // Looked up BEFORE reserving anything, so a missing binary fails without
    // leaving a half-started entry to clean up (same ordering as
    // START/PROXY/RUN/HOOK).
    cloudflared::ensure_installed()?;

    state.ensure()?;

    // --- Reserve name + id + entry atomically -----------------------------
    // Same contract as START/PROXY/RUN/HOOK's reservation, including the M1
    // protection that comes free: `worker_pid: 0` + a fresh `created_at` puts
    // the entry inside `model::START_GRACE`, so a concurrent `ft kill` /
    // `ft prune` refuses to reap it during the reserve→spawn→record window
    // below (do NOT add any pid-0 staleness handling of our own —
    // `Service::start_in_progress` owns it). Every exit of ours resolves the
    // window quickly: token/spawn failure, worker death, and the URL timeout
    // below all remove the entry by id, which bypasses the grace guard.
    let (id, name) = Registry::update(&state, |reg| -> Result<(u64, String)> {
        // One bucket, one owner (checked INSIDE the flock, atomically with
        // the reserve — see [`find_drop_dir_conflict`]).
        if let Some(other) = find_drop_dir_conflict(reg, &dir) {
            bail!(
                "directory {} is already the upload target of drop service \
                 '{other}' — one bucket, one owner (a second drop origin on \
                 the same directory would race its writes and stack its \
                 total-cap allowance)",
                dir.display()
            );
        }
        let name = match &name {
            Some(n) => {
                name::validate_name(n)?;
                ensure!(!reg.name_exists(n), "a service named '{n}' already exists");
                n.clone()
            }
            // Default matches the foreground drop flow (`drop-{port}` in
            // [`run_foreground`]) so both modes of `ft drop` produce the same
            // name for the same port, mirroring the hook-{port} convention.
            None => name::unique_name(reg, &format!("drop-{port}")),
        };
        let service_dir = state.ensure_service_dir(&name)?;
        let id = reg.allocate_id();
        reg.services.push(Service {
            id,
            name: name.clone(),
            kind: ServiceKind::Drop,
            // The upload TARGET — a real directory, carried like Static's
            // served dir (the worker re-resolves and re-checks it).
            dir: Some(dir.clone()),
            port,
            local_url: format!("http://127.0.0.1:{port}"),
            public_url: None,
            worker_pid: 0,
            tunnel_pid: None,
            command_pid: None, // Run-only field; a drop spawns no command
            static_flags: Default::default(),
            created_at: crate::model::now_utc(),
            state_dir: service_dir,
            foreground: false,
        });
        Ok((id, name))
    })??;

    // --- Token file -------------------------------------------------------
    // Written BEFORE the worker is spawned (it reads the token at startup and
    // fail-fasts without it) and after the reserve, so the file's lifetime is
    // bounded by the entry's. A failure here removes the entry: half a start
    // (entry without token) would fail the worker seconds later anyway.
    let service_dir = state.ensure_service_dir(&name)?;
    if let Err(e) = drop_server::store_token(&service_dir, &token) {
        let _ = Registry::update(&state, |reg| {
            reg.remove(id);
        });
        return Err(e)
            .with_context(|| format!("storing the drop token in {}", service_dir.display()));
    }

    // --- Spawn worker -----------------------------------------------------
    // Carries the real `dir` (unlike hook's directory-less worker) and the
    // `--max-size` cap; the DROP arm in the worker binds the origin after
    // reading the token file back.
    let worker_pid = match spawn::spawn_drop_worker(id, &name, &dir, port, max_size) {
        Ok(pid) => pid,
        Err(e) => {
            // Release the reserved entry on spawn failure.
            if let Err(cleanup_err) = Registry::update(&state, |reg| {
                reg.remove(id);
            }) {
                tracing::warn!(%cleanup_err, id, "failed to clean up registry entry after spawn failure");
            }
            return Err(e);
        }
    };
    // Record the real worker pid under the lock. Key by the stable numeric id,
    // not the name: the name may be reused for a fresh service after a kill,
    // and an id key is immune to that (and matches how the worker looks itself
    // up), so a concurrent kill cannot make us record the pid against the
    // wrong entry.
    Registry::update(&state, |reg| {
        if let Some(svc) = reg.find_mut(&id.to_string()) {
            svc.worker_pid = worker_pid;
        }
    })?;

    // --- Poll for the tunnel URL (fail-fast on worker death) --------------
    // Same mtime-gated loop as START/PROXY/RUN/HOOK (the worker rewrites
    // registry.json only when it discovers the URL or self-removes).
    let registry_path = state.registry_path();
    let mut last_mtime = std::fs::metadata(&registry_path)
        .and_then(|m| m.modified())
        .ok();
    let deadline = Instant::now() + POLL_TIMEOUT;
    loop {
        if Instant::now() >= deadline {
            break;
        }

        // Cheap stat first. Only re-read+parse when the file actually changed.
        let new_mtime = std::fs::metadata(&registry_path)
            .and_then(|m| m.modified())
            .ok();
        // `None` here means "we did NOT re-read this poll" (mtime unchanged);
        // `Some(None)` means we re-read and our entry is gone (vanished).
        let snapshot: Option<Option<Service>> = if new_mtime != last_mtime {
            last_mtime = new_mtime;
            Some(Registry::load(&state)?.find(&id.to_string()).cloned())
        } else {
            // Registry unchanged since last poll: there is no fresh entry to
            // consult, but the worker may still have died silently between
            // rewrites, so probe it directly to preserve fail-fast behaviour.
            // (This uses the pid we already recorded, not the snapshot's.)
            if !proc::pid_alive(worker_pid) {
                return fail_start(&state, id, &name, worker_pid).await;
            }
            None
        };

        match snapshot {
            Some(Some(svc)) if svc.public_url.is_some() => {
                // Unlike RUN, no extra origin probe: the worker bound the
                // drop origin (and read the token file) before spawning
                // cloudflared (fail-fast on either error), so a published URL
                // already implies an origin.
                output::print_started(&svc);
                output::print_drop_token(&token, &svc.public_url.clone().unwrap_or_default());
                return Ok(());
            }
            Some(Some(svc)) if !proc::pid_alive(svc.worker_pid) => {
                // Worker died before publishing — reap any survivors, surface
                // the reason inline (the entry is removed below, so we can't
                // send the user to `ft logs` afterwards), then fail fast.
                return fail_start(&state, id, &name, worker_pid).await;
            }
            Some(None) => {
                // Our entry vanished — a concurrent `ft kill` removed it, or
                // the worker self-removed on its own failure. Tear the worker
                // down and bail now instead of polling the full 30s with a
                // live, orphaned worker that nothing in the registry points
                // at.
                return fail_start(&state, id, &name, worker_pid).await;
            }
            // Some(Some(svc)) still starting, or None (unchanged registry):
            // poll again.
            _ => {}
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    // Timed out. The worker + cloudflared may still be alive and the entry is
    // still active, so tear them down (the group kill reaches the worker's
    // children) before bailing.
    proc::shutdown_process_group(worker_pid).await;
    if let Err(cleanup_err) = Registry::update(&state, |reg| {
        reg.remove(id);
    }) {
        tracing::warn!(%cleanup_err, id, "failed to clean up registry entry after URL timeout");
    }
    let reason = last_reason(&state, &name);
    bail!("timed out waiting for the tunnel URL{reason}")
}

/// Tear the just-started service down and fail: shared by the poll loop's
/// fail-fast arms (worker death, vanished entry). Duplicated from
/// `cmd/hook.rs`'s frozen-core split; keep in sync.
async fn fail_start(state: &StateDir, id: u64, name: &str, worker_pid: u32) -> Result<()> {
    proc::shutdown_process_group(worker_pid).await;
    if let Err(cleanup_err) = Registry::update(state, |reg| {
        reg.remove(id);
    }) {
        tracing::warn!(%cleanup_err, id, "failed to clean up registry entry after worker death");
    }
    let reason = last_reason(state, name);
    bail!("worker for '{name}' exited before the tunnel came up{reason}")
}

/// Best-effort last non-empty log line to surface in a start-failure message.
/// Checks `tunnel.log` first (cloudflared's own output, where errors usually
/// appear), then `worker.log`. Duplicated from `cmd/start.rs`/`cmd/hook.rs`
/// (where they are private) per the frozen-core split; keep the copies in
/// sync.
fn last_reason(state: &StateDir, name: &str) -> String {
    let pick = [state.tunnel_log(name), state.worker_log(name)]
        .into_iter()
        .find_map(|p| last_line(&p));
    match pick {
        Some(line) => format!(":\n  {line}"),
        None => String::new(),
    }
}

/// The last non-empty line of `path`, reading at most `LAST_REASON_CAP`
/// trailing bytes so a chatty cloudflared cannot make a start-failure message
/// slurp megabytes into memory. Duplicated from `cmd/start.rs`; see
/// [`last_reason`].
fn last_line(path: &Path) -> Option<String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = std::fs::File::open(path).ok()?;
    let len = file.metadata().ok()?.len();
    if len > LAST_REASON_CAP {
        // Seek into the trailing window; the first "line" then starts mid-file
        // and is likely partial, so drop everything up to the first newline.
        file.seek(SeekFrom::Start(len - LAST_REASON_CAP)).ok()?;
    }
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).ok()?;
    let text = String::from_utf8_lossy(&buf);
    let text: &str = if len > LAST_REASON_CAP {
        // Skip the partial first line after a mid-file seek. If the window has
        // no newline at all it is one long line — use it rather than dropping
        // the reason entirely.
        match text.find('\n') {
            Some(i) => &text[i + 1..],
            None => text.as_ref(),
        }
    } else {
        text.as_ref()
    };
    text.lines()
        .map(str::trim)
        .rfind(|l| !l.is_empty())
        .map(str::to_owned)
}

/// One bucket, one owner: find an existing Drop service whose upload target
/// IS `dir` (canonical comparison — aliases and `..` spellings resolve to the
/// same answer), returning its name.
///
/// WHY refuse: two drop origins on one directory would race their writes
/// (cross-process temp/renames) and each carries its own 1 GiB total-cap
/// allowance, so the directory's real bound would double per service. The
/// check runs INSIDE the `Registry::update` flock in both start flows, so
/// two concurrent `ft drop` invocations on one directory are serialized —
/// one reserves, the other sees the reservation and refuses (the drop
/// origin's own write path is, additionally, cross-process safe per
/// `drop_server`'s hard-link discipline; this pre-flight is the documented,
/// friendly guarantee). Only Drop-vs-Drop conflicts: a read-only Static
/// publish of the same directory is untouched by uploads landing in it (they
/// merely become served files) and stays allowed. An existing entry whose
/// directory cannot be resolved cannot be PROVEN equal, so it does not
/// conflict here — the worker's own resolve_dir check refuses such a bucket
/// at startup anyway.
fn find_drop_dir_conflict(reg: &Registry, dir: &Path) -> Option<String> {
    let target = std::fs::canonicalize(dir).ok()?;
    reg.services
        .iter()
        .filter(|svc| svc.kind == ServiceKind::Drop)
        .find_map(|svc| {
            let d = svc.dir.as_ref()?;
            std::fs::canonicalize(d)
                .is_ok_and(|resolved| resolved == target)
                .then(|| svc.name.clone())
        })
}

/// RAII guard that removes a reserved registry entry on drop. Duplicated from
/// `cmd/start.rs` (private there) per the frozen-core split — the foreground
/// flow has early-`?`/panic exits between reserve and teardown, and every one
/// of them must release the entry. Keep in sync.
struct EntryGuard {
    state: StateDir,
    id: u64,
}

impl Drop for EntryGuard {
    fn drop(&mut self) {
        if let Err(e) = Registry::update(&self.state, |reg| {
            reg.remove(self.id);
        }) {
            // Runs on every foreground exit path including panics, so a failed
            // cleanup must be visible (the entry would otherwise leak silently
            // until a later `ft prune`). tracing is sync-safe inside Drop.
            tracing::warn!(%e, id = self.id, "failed to clean up foreground registry entry on drop");
        }
    }
}

/// Why the foreground keep-alive loop ended. A drop foreground has no command
/// child, so unlike `cmd/start.rs`'s enum there is no `CommandExited` arm.
enum ReaderExit {
    ChildExited,
    Signal,
}

/// Foreground flow: run the drop origin and tunnel in this process and block
/// until cloudflared exits, Ctrl-C is received, or (Unix) SIGTERM arrives.
///
/// Duplicated from `cmd/start.rs::run_foreground_inner` (frozen-core split —
/// see the module docs); drop-specific differences: the kind is always
/// [`ServiceKind::Drop`], the origin is the drop server (writes uploads into
/// the target directory), the token file is written before the origin starts
/// (same fail-fast window as the background flow), and the token block is
/// printed once as soon as the origin is up.
async fn run_foreground(
    dir: PathBuf,
    port: u16,
    name: Option<String>,
    token: String,
    max_size: u64,
) -> Result<()> {
    use crate::static_server;

    let state = StateDir::new()?;
    state.ensure()?;

    cloudflared::ensure_installed()?;

    // --- Reserve a registry entry (cross-platform) -------------------------
    // Mirrors `run_background`'s reservation, but marks this as a FOREGROUND
    // service whose worker_pid is THIS process. That makes `ft ls/detail/
    // logs/open` see the foreground tunnel on every platform — notably
    // Windows, where foreground is the only practical mode.
    let (id, name) = Registry::update(&state, |reg| -> Result<(u64, String)> {
        // One bucket, one owner (checked INSIDE the flock, atomically with
        // the reserve — see [`find_drop_dir_conflict`]).
        if let Some(other) = find_drop_dir_conflict(reg, &dir) {
            bail!(
                "directory {} is already the upload target of drop service \
                 '{other}' — one bucket, one owner (a second drop origin on \
                 the same directory would race its writes and stack its \
                 total-cap allowance)",
                dir.display()
            );
        }
        let name = match &name {
            Some(n) => {
                name::validate_name(n)?;
                ensure!(!reg.name_exists(n), "a service named '{n}' already exists");
                n.clone()
            }
            // Default matches the background drop flow (`drop-{port}` in
            // [`run_background`]) so both modes of `ft drop` produce the same
            // name for the same port.
            None => name::unique_name(reg, &format!("drop-{port}")),
        };
        let service_dir = state.ensure_service_dir(&name)?;
        let id = reg.allocate_id();
        reg.services.push(Service {
            id,
            name: name.clone(),
            kind: ServiceKind::Drop,
            dir: Some(dir.clone()),
            port,
            local_url: format!("http://127.0.0.1:{port}"),
            public_url: None,
            worker_pid: std::process::id(),
            tunnel_pid: None,
            command_pid: None,
            static_flags: Default::default(),
            created_at: crate::model::now_utc(),
            state_dir: service_dir,
            foreground: true,
        });
        Ok((id, name))
    })??;

    // From here, every exit path must release the reserved entry (see
    // [`EntryGuard`]).
    let _entry = EntryGuard {
        state: state.clone(),
        id,
    };

    // The token file before the origin starts: `ft detail` shows it, and the
    // in-process origin below is built from the same value.
    let service_dir = state.ensure_service_dir(&name)?;
    drop_server::store_token(&service_dir, &token)
        .with_context(|| format!("storing the drop token in {}", service_dir.display()))?;

    // Tee cloudflared output to tunnel.log so `ft logs <name>` works for
    // foreground tunnels (which otherwise only print to the terminal).
    let tunnel_log = state.tunnel_log(&name);
    let log_writer = Arc::new(Mutex::new(
        crate::fsutil::open_private_append_async(&tunnel_log)
            .await
            .with_context(|| format!("opening tunnel log {}", tunnel_log.display()))?,
    ));

    // Install the SIGTERM handler (Unix) BEFORE spawning the server +
    // cloudflared: if it fails the `?` returns with only the (guard-protected)
    // entry to clean up — no orphaned server task or cloudflared child is left
    // behind.
    #[cfg(unix)]
    let mut sig_term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("installing SIGTERM handler")?;

    // The origin: ft's own drop server in THIS process. `serve` binds
    // 127.0.0.1:<port> (loopback-only, pre-flighted for freeness above) and
    // installs its own Ctrl-C drain; the JoinHandle is kept so the drain can
    // be bounded below. A store that cannot open (unresolvable target, etc.)
    // fails here — inside the guard, before anything else is spawned.
    let store = DropStore::open(&dir, token.clone(), max_size, drop_server::MAX_TOTAL_STORE)
        .with_context(|| format!("opening the drop bucket at {}", dir.display()))?;
    let router = drop_server::router(store);
    let mut server_handle = tokio::spawn(async move {
        if let Err(e) = static_server::serve(router, port).await {
            tracing::error!(%e, "drop server exited with error");
        }
    });

    // The token is the operator's one-time credential view: printed as soon
    // as the origin exists (the public URL follows with cloudflared's first
    // log line).
    output::print_drop_token(&token, &format!("http://127.0.0.1:{port}"));

    let mut child = match cloudflared::spawn(port, PathBuf::new()) {
        Ok(c) => c,
        Err(e) => {
            // Abort the just-spawned server task; the entry is released by
            // the guard on return.
            server_handle.abort();
            return Err(e);
        }
    };
    let tunnel_pid = child.id();

    // Mirror cloudflared output to stdout AND tunnel.log, and publish the
    // public URL on first discovery (so `ft open`/`ft detail` work too).
    // Duplicated from `cmd/start.rs::drain_and_announce` (frozen-core split);
    // keep in sync.
    let found = Arc::new(AtomicBool::new(false));
    let mut tasks = Vec::new();
    if let Some(out) = child.stdout.take() {
        tasks.push(tokio::spawn(drain_and_announce(
            BufReader::new(out).lines(),
            found.clone(),
            name.clone(),
            port,
            state.clone(),
            id,
            tunnel_pid,
            log_writer.clone(),
        )));
    }
    if let Some(err) = child.stderr.take() {
        tasks.push(tokio::spawn(drain_and_announce(
            BufReader::new(err).lines(),
            found.clone(),
            name.clone(),
            port,
            state.clone(),
            id,
            tunnel_pid,
            log_writer.clone(),
        )));
    }

    // Keep the foreground alive until cloudflared exits, Ctrl-C is received,
    // or (Unix) SIGTERM arrives. Racing child.wait() ensures that if
    // cloudflared dies before the URL is found (or any time later) we tear
    // down instead of hanging forever.
    #[cfg(unix)]
    let exit_reason = tokio::select! {
        status = child.wait() => {
            match status {
                Ok(s) => tracing::info!(?s, "cloudflared exited"),
                Err(e) => tracing::error!(%e, "waiting on cloudflared failed"),
            }
            ReaderExit::ChildExited
        }
        _ = sig_term.recv() => {
            tracing::info!("received SIGTERM, shutting down foreground drop");
            ReaderExit::Signal
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("received Ctrl-C, shutting down foreground drop");
            ReaderExit::Signal
        }
    };
    #[cfg(not(unix))]
    let exit_reason = tokio::select! {
        status = child.wait() => {
            match status {
                Ok(s) => tracing::info!(?s, "cloudflared exited"),
                Err(e) => tracing::error!(%e, "waiting on cloudflared failed"),
            }
            ReaderExit::ChildExited
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("received Ctrl-C, shutting down foreground drop");
            ReaderExit::Signal
        }
    };

    // If cloudflared may still be alive, shut it down and reap it to avoid a
    // transient zombie. On ChildExited the select's wait() already reaped it.
    // The signal/escalation/reap sequence is shared with the detached worker
    // via [`cloudflared::shutdown`].
    if matches!(exit_reason, ReaderExit::Signal) {
        cloudflared::shutdown(tunnel_pid, &mut child).await;
    }

    for task in tasks {
        task.abort();
    }

    // `serve`'s own Ctrl-C handler has already begun draining on Ctrl-C; bound
    // it so a stuck request can't hang the foreground command, falling back
    // to abort.
    match tokio::time::timeout(SERVER_SHUTDOWN_TIMEOUT, &mut server_handle).await {
        Ok(_) => {}
        Err(_) => {
            tracing::warn!(
                "drop server did not drain within {:?}, aborting",
                SERVER_SHUTDOWN_TIMEOUT
            );
            server_handle.abort();
        }
    }

    // The `_entry` guard removes our registry entry on return (every exit
    // path).
    Ok(())
}

/// Read `lines` to EOF, mirror each line to stdout AND `tunnel.log`, and
/// publish the first discovered Quick Tunnel URL onto the registry entry
/// (printing the foreground success banner at the same time). Duplicated from
/// `cmd/start.rs::drain_and_announce` (frozen-core split — the helper is
/// private there and `cmd/start.rs` is outside this area's allowed paths);
/// keep in sync.
#[allow(clippy::too_many_arguments)]
async fn drain_and_announce<R>(
    mut lines: tokio::io::Lines<R>,
    found: Arc<AtomicBool>,
    name: String,
    port: u16,
    state: StateDir,
    id: u64,
    tunnel_pid: Option<u32>,
    log_writer: Arc<tokio::sync::Mutex<tokio::fs::File>>,
) where
    R: tokio::io::AsyncBufRead + Unpin,
{
    use tokio::io::AsyncWriteExt;
    while let Ok(Some(line)) = lines.next_line().await {
        println!("{line}");
        {
            let mut f = log_writer.lock().await;
            let _ = f.write_all(line.as_bytes()).await;
            let _ = f.write_all(b"\n").await;
            let _ = f.flush().await;
        }
        if !found.load(Ordering::Acquire)
            && let Some(url) = cloudflared::extract_url(&line)
            && !found.swap(true, Ordering::AcqRel)
        {
            println!();
            println!("Started {name}");
            println!();
            println!("Local:   http://127.0.0.1:{port}");
            println!("Public:  {url}");
            println!();
            if let Err(e) = Registry::update(&state, |reg| {
                if let Some(svc) = reg.find_mut(&id.to_string()) {
                    svc.public_url = Some(url.clone());
                    if svc.tunnel_pid.is_none() {
                        svc.tunnel_pid = tunnel_pid;
                    }
                }
            }) {
                tracing::error!(%e, "failed to record foreground tunnel URL");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! The one-bucket-one-owner pre-flight as a pure decision over a seeded
    //! registry (the fs input — canonicalization — is exercised with real
    //! tempdirs, but nothing else here touches state or cloudflared).

    use super::*;
    use std::path::PathBuf;

    /// A minimal Drop service entry targeting `dir`.
    fn drop_service(id: u64, name: &str, dir: Option<PathBuf>) -> Service {
        Service {
            id,
            name: name.to_string(),
            kind: ServiceKind::Drop,
            dir,
            port: 9000,
            local_url: "http://127.0.0.1:9000".to_string(),
            public_url: None,
            worker_pid: 0,
            tunnel_pid: None,
            command_pid: None,
            static_flags: Default::default(),
            created_at: crate::model::now_utc(),
            state_dir: PathBuf::from("/tmp/state"),
            foreground: false,
        }
    }

    /// The same entry shape but STATIC (a read-only publish of the dir).
    fn static_service(id: u64, name: &str, dir: Option<PathBuf>) -> Service {
        Service {
            kind: ServiceKind::Static,
            ..drop_service(id, name, dir)
        }
    }

    fn registry_of(services: Vec<Service>) -> Registry {
        Registry {
            next_id: services.len() as u64 + 1,
            services,
        }
    }

    #[test]
    fn resolve_token_trims_once_and_refuses_whitespace_only() {
        // R3-9: --token was validated via `t.trim()` but STORED and PRINTED
        // untrimmed, so a token with edge whitespace 401'd every background
        // upload (the pasted/trimmed form never matched the stored one) while
        // the foreground flow worked. The resolved value is the single
        // binding every consumer sees — token file, printed credential, and
        // the origin's comparison value — so it must BE the trimmed secret.
        assert_eq!(
            resolve_token(Some("  sekrit  ".to_string())).expect("padded token"),
            "sekrit",
            "edge whitespace must be trimmed exactly once, at this boundary"
        );
        assert_eq!(
            resolve_token(Some("tok".to_string())).expect("clean token"),
            "tok",
            "a clean token passes through unchanged"
        );
        let err = resolve_token(Some("   ".to_string()))
            .expect_err("a whitespace-only token authenticates nothing");
        assert!(
            err.to_string()
                .contains("--token must be a non-empty secret"),
            "the refusal must name the rule, got: {err}"
        );
    }

    #[test]
    fn resolve_token_mints_when_omitted() {
        // None ⇒ a freshly minted CSPRNG token: 64 lowercase hex chars — the
        // printed-once default the help documents.
        let minted = resolve_token(None).expect("minted token");
        assert_eq!(minted.len(), 64);
        assert!(
            minted
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn conflict_found_for_the_same_directory() {
        // The core contract: a second drop start on a directory that is
        // already a Drop service's target finds that service by name.
        let tmp = tempfile::tempdir().expect("tempdir");
        let bucket = tmp.path().join("bucket");
        std::fs::create_dir_all(&bucket).expect("mkdir");
        let reg = registry_of(vec![drop_service(1, "first", Some(bucket.clone()))]);
        assert_eq!(
            find_drop_dir_conflict(&reg, &bucket).as_deref(),
            Some("first")
        );
    }

    #[test]
    fn conflict_found_through_path_aliases() {
        // Canonical comparison: a `..`-spelled or symlinked path to the same
        // real directory must conflict — the guarantee is about the
        // DIRECTORY, not the spelling of the argument.
        let tmp = tempfile::tempdir().expect("tempdir");
        let real = tmp.path().join("real");
        std::fs::create_dir_all(&real).expect("mkdir");
        let reg = registry_of(vec![drop_service(1, "first", Some(real.clone()))]);

        // A `..`-spelled alias of the same directory (the intermediate dir
        // must exist for realpath to walk it, as on a real command line).
        std::fs::create_dir_all(tmp.path().join("other")).expect("mkdir other");
        let dotted = tmp.path().join("other").join("..").join("real");
        assert_eq!(
            find_drop_dir_conflict(&reg, &dotted).as_deref(),
            Some("first"),
            "a ..-spelled alias must resolve to the same bucket"
        );

        // A symlinked alias (unix only; Windows aliases are junctions with
        // different creation semantics).
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&real, tmp.path().join("alias")).expect("symlink");
            assert_eq!(
                find_drop_dir_conflict(&reg, &tmp.path().join("alias")).as_deref(),
                Some("first"),
                "a symlinked alias must resolve to the same bucket"
            );
        }
    }

    #[test]
    fn different_directory_is_no_conflict() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let a = tmp.path().join("a");
        let b = tmp.path().join("b");
        std::fs::create_dir_all(&a).expect("mkdir a");
        std::fs::create_dir_all(&b).expect("mkdir b");
        let reg = registry_of(vec![drop_service(1, "first", Some(a))]);
        assert_eq!(find_drop_dir_conflict(&reg, &b), None);
    }

    #[test]
    fn static_publish_of_the_same_directory_is_no_conflict() {
        // Deliberate policy: only Drop-vs-Drop conflicts. A read-only static
        // publish of the bucket directory is untouched by uploads landing in
        // it (they merely become served files), so it stays allowed.
        let tmp = tempfile::tempdir().expect("tempdir");
        let bucket = tmp.path().join("bucket");
        std::fs::create_dir_all(&bucket).expect("mkdir");
        let reg = registry_of(vec![static_service(1, "site", Some(bucket.clone()))]);
        assert_eq!(find_drop_dir_conflict(&reg, &bucket), None);
    }

    #[test]
    fn unresolvable_existing_dir_is_no_conflict() {
        // An entry whose dir does not exist cannot be PROVEN equal; the
        // helper skips it rather than failing the start (the worker's own
        // resolve_dir check refuses such a bucket at startup anyway). The
        // same applies to a dir-less Drop entry (hand-edited).
        let tmp = tempfile::tempdir().expect("tempdir");
        let bucket = tmp.path().join("bucket");
        std::fs::create_dir_all(&bucket).expect("mkdir");
        let reg = registry_of(vec![
            drop_service(1, "ghost", Some(tmp.path().join("missing"))),
            drop_service(2, "hand-edited", None),
        ]);
        assert_eq!(find_drop_dir_conflict(&reg, &bucket), None);
    }

    #[test]
    fn unresolvable_requested_dir_is_no_conflict() {
        // A requested dir that cannot canonicalize is refused later by
        // resolve_dir (in run(), before this helper can even be reached) —
        // the helper itself must stay total and report no conflict.
        let reg = registry_of(vec![drop_service(1, "first", None)]);
        assert_eq!(
            find_drop_dir_conflict(&reg, std::path::Path::new("/no/such/dir")),
            None
        );
    }
}
