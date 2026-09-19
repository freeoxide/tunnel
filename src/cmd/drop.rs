//! The DROP command: `ft drop <dir>` runs an ft-owned upload-receiver origin
//! (see `drop_server`) behind a cloudflared Quick Tunnel. The background flow
//! mirrors START's reserve-entry → spawn-worker → poll-for-URL shape,
//! sharing `cmd/start.rs`'s fail-fast helpers (`fail_start`/`fail_timeout`);
//! the poll loop itself is drop-specific (the success arm also prints the
//! token). The worker binds the origin itself on `127.0.0.1:<port>`
//! (fail-fast on a bind error), so success is "URL published" — no separate
//! origin probe.
//!
//! The START flow's directory safety checks (`resolve_dir` +
//! `is_sensitive_dir`) run BEFORE any state is touched, and the worker
//! re-runs them (same defense-in-depth split as Static). A sensitive
//! directory is refused UNCONDITIONALLY — no `--yes` exists here: a drop
//! bucket is WRITE-touched by the public tunnel, strictly more dangerous
//! than a read-only static publish, and a detached worker could not confirm
//! anyway.
//!
//! The token is resolved before any state exists (`--token`, non-empty after
//! a single trim, or a fresh [`drop_server::generate_token`] mint), stored
//! 0600 in the service's state dir after the entry is reserved and before
//! the worker spawns (the worker reads it back fail-fast), printed once on
//! success, and shown by `ft detail`.
//!
//! One bucket, one owner: a directory already a drop target refuses a second
//! drop service (checked inside the reserve's flock — see
//! [`find_drop_dir_conflict`]); the origin's write path is cross-process safe
//! on its own regardless (see `drop_server`).
//!
//! The foreground flow mirrors `cmd/start.rs::run_foreground_inner`'s shape
//! but stays separate: a merge needs a fourth origin variant (static/proxy/
//! run + drop), and the drop-specific parts (token file before the origin,
//! token block printed as soon as the origin is up) read clearer inline.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use anyhow::{Context, bail, ensure};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::Mutex;

use super::{POLL_INTERVAL, POLL_TIMEOUT};
use crate::cloudflared;
use crate::cmd::start::{
    EntryGuard, SERVER_SHUTDOWN_TIMEOUT, drain_and_announce, fail_start, fail_timeout,
    is_sensitive_dir, remove_reservation, resolve_dir, teardown,
};
use crate::drop_server::{self, DropStore};
use crate::error::Result;
use crate::model::{Registry, Service, ServiceKind};
use crate::name;
use crate::output;
use crate::port;
use crate::proc;
use crate::spawn;
use crate::state::StateDir;

/// Entry point for the DROP command.
pub async fn run(
    dir: PathBuf,
    port: Option<u16>,
    name: Option<String>,
    foreground: bool,
    token: Option<String>,
    max_size: Option<u64>,
) -> Result<()> {
    // Pre-flight 1: the upload target. Resolves like a static publish;
    // sensitive directories are refused unconditionally (see module docs) —
    // before any state is touched, so a rejection leaves zero state.
    let dir = resolve_dir(&dir)?;
    ensure!(
        !is_sensitive_dir(&dir),
        "refusing to use {} as a drop bucket: it is a sensitive directory, and \
         uploads WRITE into it through a public tunnel",
        dir.display()
    );

    // Pre-flight 2: ft's own origin, so the port must be FREE — a friendly
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

    // Resolved TRIMMED ONCE, HERE: the value every downstream consumer sees —
    // token file, printed credential, the origin's comparison value — so an
    // edge-whitespace shell quote cannot 401 its own pasted twin. An
    // explicitly empty (or whitespace-only) token is refused rather than
    // silently minted (the operator asked for a specific secret).
    let token = resolve_token(token)?;
    // The per-upload cap; the total-store cap is the fixed
    // drop_server::MAX_TOTAL_STORE.
    let max_size = max_size.unwrap_or(drop_server::DEFAULT_MAX_SIZE);

    if foreground {
        run_foreground(dir, port, name, token, max_size).await
    } else {
        run_background(dir, port, name, token, max_size).await
    }
}

/// Resolve the drop access token: the operator's `--token` trimmed once,
/// refused when whitespace-only, or a freshly minted CSPRNG one when
/// omitted. The returned value is the single binding every consumer sees.
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
/// tunnel URL (failing fast if the worker dies first). A drop-specific
/// sibling of start's `poll_for_url`: the success arm also prints the token.
async fn run_background(
    dir: PathBuf,
    port: u16,
    name: Option<String>,
    token: String,
    max_size: u64,
) -> Result<()> {
    let state = StateDir::new()?;

    // Looked up BEFORE reserving anything, so a missing binary fails without
    // leaving a half-started entry to clean up.
    cloudflared::ensure_installed()?;

    state.ensure()?;

    // Reserve name + id + entry atomically. `worker_pid: 0` + a fresh
    // `created_at` put the entry inside `model::START_GRACE`, so a concurrent
    // `ft kill`/`ft prune` refuses to reap it during the reserve→spawn→record
    // window below (do NOT add pid-0 staleness handling of our own —
    // `Service::start_in_progress` owns it). Every exit below removes the
    // entry by id, bypassing the grace guard — the window resolves quickly.
    let (id, name, service_dir) = reserve_entry(&state, &dir, port, name, 0, false)?;

    // Written BEFORE the worker is spawned (it reads the token at startup and
    // fail-fasts without it) and after the reserve, so the file's lifetime is
    // bounded by the entry's. A failure here removes the entry.
    if let Err(e) = drop_server::store_token(&service_dir, &token) {
        let _ = Registry::update(&state, |reg| {
            reg.remove(id);
        });
        return Err(e)
            .with_context(|| format!("storing the drop token in {}", service_dir.display()));
    }

    // The worker carries the real `dir` (unlike hook's directory-less worker)
    // and the `--max-size` cap; the DROP arm binds the origin after reading
    // the token file back.
    let worker_pid = match spawn::spawn_drop_worker(id, &name, &dir, port, max_size) {
        Ok(pid) => pid,
        Err(e) => {
            // Release the reserved entry on spawn failure.
            remove_reservation(&state, id);
            return Err(e);
        }
    };
    // Record the real worker pid under the lock, keyed by the stable numeric
    // id (the name may be reused after a kill; an id key is immune to that
    // and matches how the worker looks itself up).
    Registry::update(&state, |reg| {
        if let Some(svc) = reg.find_mut(&id.to_string()) {
            svc.worker_pid = worker_pid;
        }
    })?;

    // Poll for the tunnel URL (mtime-gated re-reads; the worker rewrites
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

        // Cheap stat first; re-read+parse only when the file changed.
        let new_mtime = std::fs::metadata(&registry_path)
            .and_then(|m| m.modified())
            .ok();
        // `None` = did NOT re-read this poll (mtime unchanged); `Some(None)` =
        // re-read and our entry is gone (vanished).
        let snapshot: Option<Option<Service>> = if new_mtime != last_mtime {
            last_mtime = new_mtime;
            match Registry::load(&state) {
                Ok(reg) => Some(reg.find(&id.to_string()).cloned()),
                Err(e) => {
                    // Registry unreadable mid-poll: tear the live worker down
                    // (start::teardown's shutdown-then-remove-by-id) first —
                    // bailing bare would orphan it — then surface the cause.
                    teardown(&state, id, worker_pid, "registry read error").await;
                    return Err(e).context("re-reading the registry during the drop start poll");
                }
            }
        } else {
            // Registry unchanged: probe the worker directly to preserve
            // fail-fast (it may have died silently between rewrites).
            if !proc::pid_alive(worker_pid) {
                return fail_start(&state, id, &name, worker_pid).await;
            }
            None
        };

        match snapshot {
            Some(Some(svc)) if svc.public_url.is_some() => {
                // No extra origin probe (unlike RUN): the worker bound the
                // drop origin (and read the token file) before spawning
                // cloudflared, so a published URL already implies an origin.
                output::print_started(&svc);
                output::print_drop_token(&token, svc.public_url.as_deref().unwrap_or(""));
                return Ok(());
            }
            Some(Some(svc)) if !proc::pid_alive(svc.worker_pid) => {
                // Worker died before publishing — surface the reason inline
                // (the entry is removed below, so the user cannot go to
                // `ft logs` afterwards).
                return fail_start(&state, id, &name, worker_pid).await;
            }
            Some(None) => {
                // Entry vanished — a concurrent `ft kill`, or the worker
                // self-removed on its own failure. Tear the worker down and
                // bail instead of polling the full 30s with a live orphan.
                return fail_start(&state, id, &name, worker_pid).await;
            }
            // Still starting, or unchanged registry: poll again.
            _ => {}
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    // Timed out: tear the live worker + cloudflared down (the group kill
    // reaches the worker's children) and remove the entry before bailing.
    fail_timeout(&state, id, &name, worker_pid).await
}

/// Reserve the drop entry inside the `Registry::update` flock. Drop-specific
/// (not the shared `start::reserve_entry`): it refuses a second drop service
/// on the same bucket (see [`find_drop_dir_conflict`]) and returns the
/// service dir so the caller can store the token file before spawning.
fn reserve_entry(
    state: &StateDir,
    dir: &Path,
    port: u16,
    name: Option<String>,
    worker_pid: u32,
    foreground: bool,
) -> Result<(u64, String, PathBuf)> {
    Registry::update(state, |reg| -> Result<(u64, String, PathBuf)> {
        if let Some(other) = find_drop_dir_conflict(reg, dir) {
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
            // drop-{port} in BOTH flows (mirroring the hook-{port}
            // convention), so both modes of `ft drop` produce the same name.
            None => name::unique_name(reg, &format!("drop-{port}")),
        };
        let service_dir = state.ensure_service_dir(&name)?;
        let id = reg.allocate_id();
        reg.services.push(Service {
            id,
            name: name.clone(),
            kind: ServiceKind::Drop,
            // The upload TARGET — carried like Static's served dir (the
            // worker re-resolves and re-checks it).
            dir: Some(dir.to_path_buf()),
            port,
            local_url: format!("http://127.0.0.1:{port}"),
            public_url: None,
            worker_pid,
            tunnel_pid: None,
            command_pid: None, // Run-only field; a drop spawns no command
            static_flags: Default::default(),
            created_at: crate::model::now_utc(),
            state_dir: service_dir.clone(),
            foreground,
        });
        Ok((id, name, service_dir))
    })?
}

/// One bucket, one owner: find an existing Drop service whose upload target
/// IS `dir` (canonical comparison — aliases and `..` spellings resolve to
/// the same answer), returning its name. Two origins on one directory would
/// race writes and stack their 1 GiB total-cap allowances. Checked INSIDE
/// the `Registry::update` flock, so concurrent `ft drop`s are serialized.
/// Only Drop-vs-Drop conflicts: a read-only Static publish of the same
/// directory is untouched by uploads and stays allowed. An unresolvable
/// entry dir cannot be PROVEN equal, so it does not conflict (the worker's
/// own resolve_dir check refuses such a bucket at startup anyway).
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

/// Why the foreground keep-alive loop ended. A drop foreground has no command
/// child, so unlike `cmd/start.rs`'s enum there is no `CommandExited` arm.
enum ReaderExit {
    ChildExited,
    Signal,
}

/// Foreground flow: run the drop origin and tunnel in THIS process and block
/// until cloudflared exits, Ctrl-C is received, or (Unix) SIGTERM arrives.
/// Drop-specific: the origin writes uploads into the target directory, the
/// token file is written before the origin starts, and the token block is
/// printed as soon as the origin is up.
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

    // Reserve a FOREGROUND entry whose worker_pid is THIS process, so `ft
    // ls/detail/logs/open` see the tunnel on every platform (notably Windows,
    // where foreground is the only practical mode).
    let (id, name, service_dir) =
        reserve_entry(&state, &dir, port, name, std::process::id(), true)?;

    // From here, every exit path must release the reserved entry.
    let _entry = EntryGuard::new(state.clone(), id);

    // The token file before the origin starts: `ft detail` shows it, and the
    // in-process origin below is built from the same value.
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
    // cloudflared: if it fails, the `?` returns with only the (guard
    // protected) entry to clean up — no orphaned server task or child.
    #[cfg(unix)]
    let mut sig_term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("installing SIGTERM handler")?;

    // The origin: ft's own drop server in THIS process. `serve` binds
    // 127.0.0.1:<port> and installs its own Ctrl-C drain; the JoinHandle is
    // kept so the drain can be bounded below. A store that cannot open
    // fails here — inside the guard, before anything else is spawned.
    let store = DropStore::open(&dir, token.clone(), max_size, drop_server::MAX_TOTAL_STORE)
        .with_context(|| format!("opening the drop bucket at {}", dir.display()))?;
    let router = drop_server::router(store);
    let mut server_handle = tokio::spawn(async move {
        if let Err(e) = static_server::serve(router, port).await {
            tracing::error!(%e, "drop server exited with error");
        }
    });

    // Printed as soon as the origin exists (the public URL follows with
    // cloudflared's first log line).
    output::print_drop_token(&token, &format!("http://127.0.0.1:{port}"));

    let mut child = match cloudflared::spawn(port) {
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
    // public URL on first discovery (so `ft open`/`ft detail` work too) —
    // via start's shared drain_and_announce.
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

    // Keep the foreground alive until cloudflared exits, Ctrl-C, or (Unix)
    // SIGTERM; racing child.wait() tears down instead of hanging if
    // cloudflared dies before the URL is found (or any time later).
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

    // If cloudflared may still be alive, shut it down and reap it (on
    // ChildExited the select's wait() already reaped it). The
    // signal/escalation/reap sequence is shared with the detached worker via
    // [`cloudflared::shutdown`].
    if matches!(exit_reason, ReaderExit::Signal) {
        cloudflared::shutdown(tunnel_pid, &mut child).await;
    }

    for task in tasks {
        task.abort();
    }

    // `serve`'s own Ctrl-C handler has already begun draining; bound it so a
    // stuck request can't hang the foreground command, falling back to abort.
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

    // The `_entry` guard removes our registry entry on return.
    Ok(())
}

#[cfg(test)]
mod tests {
    //! The one-bucket-one-owner pre-flight as a pure decision over a seeded
    //! registry (canonicalization exercised with real tempdirs).

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
        // Regression: --token used to be validated via `t.trim()` but STORED
        // and PRINTED untrimmed, so an edge-whitespace token 401'd every
        // background upload. The resolved value is the single binding every
        // consumer sees — it must BE the trimmed secret.
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
        // None ⇒ a freshly minted token: 64 lowercase hex chars.
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
        // The core contract: a second drop start on a directory already a
        // Drop service's target finds that service by name.
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
        // Canonical comparison: the guarantee is about the DIRECTORY, not the
        // spelling of the argument.
        let tmp = tempfile::tempdir().expect("tempdir");
        let real = tmp.path().join("real");
        std::fs::create_dir_all(&real).expect("mkdir");
        let reg = registry_of(vec![drop_service(1, "first", Some(real.clone()))]);

        // A `..`-spelled alias (the intermediate dir must exist for realpath
        // to walk it, as on a real command line).
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
        // Deliberate policy: only Drop-vs-Drop conflicts — a read-only
        // static publish is untouched by uploads landing in it.
        let tmp = tempfile::tempdir().expect("tempdir");
        let bucket = tmp.path().join("bucket");
        std::fs::create_dir_all(&bucket).expect("mkdir");
        let reg = registry_of(vec![static_service(1, "site", Some(bucket.clone()))]);
        assert_eq!(find_drop_dir_conflict(&reg, &bucket), None);
    }

    #[test]
    fn unresolvable_existing_dir_is_no_conflict() {
        // An entry whose dir cannot be proven equal (missing, or dir-less
        // via hand-edit) does not conflict; the worker's own resolve_dir
        // check refuses such a bucket at startup anyway.
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
        // A requested dir that cannot canonicalize is refused earlier by
        // resolve_dir in run(); the helper itself stays total.
        let reg = registry_of(vec![drop_service(1, "first", None)]);
        assert_eq!(
            find_drop_dir_conflict(&reg, std::path::Path::new("/no/such/dir")),
            None
        );
    }
}
