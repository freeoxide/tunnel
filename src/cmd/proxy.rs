//! The PROXY command.
//!
//! `ft proxy <port>` attaches a tunnel to a server the operator already runs
//! on a local port: `ft` starts no server of its own, it just spawns
//! `cloudflared` pointing straight at `http://127.0.0.1:<port>` and registers
//! the result like any other service. The default background flow mirrors
//! START's reserve-entry → spawn-worker → poll-for-URL shape (see
//! `cmd/start.rs`, which is also where the shared foreground machinery lives:
//! a `dir` of `None` selects proxy semantics there).
//!
//! Unlike START there is no directory to resolve or confirm — the tunnel
//! fronts a port the operator chose to run — so there is no `--yes` flag.
//! Instead the CLI pre-flights the upstream ([`upstream_alive`]): a friendly
//! "nothing is listening" error beats a tunnel that comes up happily and then
//! 502s every request.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{bail, ensure};

use crate::cloudflared;
use crate::error::Result;
use crate::model::{Registry, Service, ServiceKind};
use crate::name;
use crate::output;
use crate::proc;
use crate::spawn;
use crate::state::StateDir;

/// How long the upstream pre-flight waits for the connect to resolve.
///
/// A loopback connect is answered by the local kernel almost instantly (either
/// the accept queue answers or the connection is refused), so this only bounds
/// pathological stacks; it is NOT a request timeout — nothing is ever read
/// from the socket.
const PROBE_TIMEOUT: Duration = Duration::from_millis(500);

/// Reload cadence while waiting for the worker to publish the public URL.
/// Mirrors START's poll loop (whose helpers are private to `cmd/start.rs`).
const POLL_INTERVAL: Duration = Duration::from_millis(250);
/// Upper bound on how long the parent will wait for the tunnel URL.
const POLL_TIMEOUT: Duration = Duration::from_secs(30);
/// Most bytes read from a log when surfacing a start-failure reason. Logs can
/// grow large; only the trailing window is examined (the first, partial line
/// after a mid-file seek is skipped).
const LAST_REASON_CAP: u64 = 16 * 1024;

/// Entry point for the PROXY command.
pub async fn run(port: u16, name: Option<String>, foreground: bool) -> Result<()> {
    // Friendly pre-flight — a CLI-level convenience ONLY. The worker itself
    // deliberately never probes (cloudflared connects lazily, so a dead
    // upstream is not a worker-side start failure); this is where the friendly
    // error belongs. Hard error in BOTH modes by design: a tunnel that comes
    // up against a dead port 502s every request, which is far more confusing
    // than being told the port is dead up front — especially in the
    // foreground, where the operator is watching. No opt-out flag: anyone who
    // genuinely wants to attach before their server boots can start the
    // server first.
    ensure!(
        upstream_alive(port),
        "nothing is listening on 127.0.0.1:{port} — start the server you want to \
         tunnel (or double-check the port number) first"
    );

    if foreground {
        // Shared foreground machinery from cmd/start.rs: `dir: None` selects
        // proxy semantics (no static server; cloudflared fronts the upstream
        // directly). It reserves its own registry entry and — by design — does
        // not re-probe the port; the pre-flight above already covered it.
        crate::cmd::start::run_foreground(None, name, Some(port)).await
    } else {
        run_background(port, name).await
    }
}

/// True when something accepts connections on `127.0.0.1:port`.
///
/// Loopback-only by construction (the address is fixed, never
/// caller-supplied). A blocking `std::net` connect is fine here: we are ahead
/// of any tokio I/O and a sub-second loopback connect is exactly the cheap
/// check we want.
fn upstream_alive(port: u16) -> bool {
    let addr = SocketAddr::new(IpAddr::from(Ipv4Addr::LOCALHOST), port);
    std::net::TcpStream::connect_timeout(&addr, PROBE_TIMEOUT).is_ok()
}

/// Background flow: reserve the entry, spawn the detached worker, then poll
/// for the public URL (failing fast if the worker dies first).
///
/// Mirrors `cmd::start::run_background` shape-for-shape, minus everything
/// directory-related: no dir resolution, no sensitive-directory prompt, and
/// no port allocation or freeness probe — the port IS the operator's upstream
/// and is *supposed* to be in use. The poll/fail-fast scaffolding is
/// duplicated rather than shared because the static flow's helpers stay
/// private to `cmd/start.rs` (frozen for this area); keep the two in sync.
async fn run_background(port: u16, name: Option<String>) -> Result<()> {
    let state = StateDir::new()?;

    // --- cloudflared ------------------------------------------------------
    // Looked up BEFORE reserving anything, so a missing binary fails without
    // leaving a half-started entry to clean up (same ordering as START).
    cloudflared::ensure_installed()?;

    state.ensure()?;

    // --- Reserve name + id + entry atomically -----------------------------
    // Same contract as START's reservation, including the M1 protection that
    // comes free: `worker_pid: 0` + a fresh `created_at` puts the entry inside
    // `model::START_GRACE`, so a concurrent `ft kill` / `ft prune` refuses to
    // reap it during the reserve→spawn→record window below (do NOT add any
    // pid-0 staleness handling of our own — `Service::start_in_progress`
    // owns it). Every exit of ours resolves the window quickly: spawn
    // failure, worker death, and the URL timeout below all remove the entry
    // by id, which bypasses the grace guard (removing our own reservation is
    // always allowed).
    let (id, name) = Registry::update(&state, |reg| -> Result<(u64, String)> {
        let name = match &name {
            Some(n) => {
                name::validate_name(n)?;
                ensure!(!reg.name_exists(n), "a service named '{n}' already exists");
                n.clone()
            }
            // Default matches the foreground proxy flow (`proxy-{port}` in
            // `cmd::start::run_foreground`) so both modes of `ft proxy`
            // produce the same name for the same port. Name policy is
            // otherwise identical to START's — no proxy-specific divergence.
            None => name::unique_name(reg, &format!("proxy-{port}")),
        };
        let service_dir = state.ensure_service_dir(&name)?;
        let id = reg.allocate_id();
        reg.services.push(Service {
            id,
            name: name.clone(),
            kind: ServiceKind::Proxy,
            dir: None,
            port,
            local_url: format!("http://127.0.0.1:{port}"),
            public_url: None,
            worker_pid: 0,
            tunnel_pid: None,
            created_at: crate::model::now_utc(),
            state_dir: service_dir,
            foreground: false,
        });
        Ok((id, name))
    })??;

    // --- Spawn worker -----------------------------------------------------
    // `dir: None` spawns a PROXY worker: what it fronts comes from the
    // reserved entry, and the spawn path substitutes its `--dir` sentinel.
    let worker_pid = match spawn::spawn_worker(id, &name, None, port) {
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
    // The worker rewrites registry.json only when it discovers the URL or
    // self-removes, so re-read+re-parse it only when its mtime changed — the
    // worker-death probe below still runs every poll, so fail-fast latency is
    // unchanged; this just avoids ~120 full reads+parses for a quiet registry.
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
                proc::shutdown_process_group(worker_pid).await;
                let reason = last_reason(&state, &name);
                if let Err(cleanup_err) = Registry::update(&state, |reg| {
                    reg.remove(id);
                }) {
                    tracing::warn!(%cleanup_err, id, "failed to clean up registry entry after worker death");
                }
                bail!("worker for '{name}' exited before the tunnel came up{reason}");
            }
            None
        };

        match snapshot {
            Some(Some(svc)) if svc.public_url.is_some() => {
                output::print_started(&svc);
                return Ok(());
            }
            Some(Some(svc)) if !proc::pid_alive(svc.worker_pid) => {
                // Worker died before publishing — reap any survivors, surface
                // the reason inline (the entry is removed below, so we can't
                // send the user to `ft logs` afterwards), then fail fast.
                proc::shutdown_process_group(worker_pid).await;
                let reason = last_reason(&state, &name);
                if let Err(cleanup_err) = Registry::update(&state, |reg| {
                    reg.remove(id);
                }) {
                    tracing::warn!(%cleanup_err, id, "failed to clean up registry entry after worker death");
                }
                bail!("worker for '{name}' exited before the tunnel came up{reason}");
            }
            Some(None) => {
                // Our entry vanished — a concurrent `ft kill` removed it, or
                // the worker self-removed on its own failure. Tear the worker
                // down and bail now instead of polling the full 30s with a
                // live, orphaned worker that nothing in the registry points
                // at.
                proc::shutdown_process_group(worker_pid).await;
                let reason = last_reason(&state, &name);
                if let Err(cleanup_err) = Registry::update(&state, |reg| {
                    reg.remove(id);
                }) {
                    tracing::warn!(%cleanup_err, id, "failed to clean up registry entry after worker death");
                }
                bail!("worker for '{name}' exited before the tunnel came up{reason}");
            }
            // Some(Some(svc)) still starting, or None (unchanged registry):
            // poll again.
            _ => {}
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    // Timed out: the worker + cloudflared may still be alive and the entry is
    // still active, so tear them down like the fail-fast path before bailing.
    proc::shutdown_process_group(worker_pid).await;
    if let Err(cleanup_err) = Registry::update(&state, |reg| {
        reg.remove(id);
    }) {
        tracing::warn!(%cleanup_err, id, "failed to clean up registry entry after URL timeout");
    }
    let reason = last_reason(&state, &name);
    bail!("timed out waiting for the tunnel URL{reason}")
}

/// Best-effort last non-empty log line to surface in a start-failure message.
/// Checks `tunnel.log` first (cloudflared's own output, where errors usually
/// appear), then `worker.log` — a proxy service has no `server.log`. Returns
/// an empty string if nothing useful is found.
///
/// Duplicated from `cmd/start.rs` (where it is private) per the frozen-core
/// split of this area; keep the two in sync.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_alive_accepts_a_live_listener() {
        // Loopback-only sockets: no external network is touched.
        let listener =
            std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind loopback listener");
        let port = listener.local_addr().expect("local addr").port();
        assert!(upstream_alive(port), "a live listener must read as alive");
    }

    #[test]
    fn upstream_alive_rejects_a_dead_port() {
        // Bind, note the port, then drop the listener: the port is closed
        // again, and nothing else realistically grabs that exact ephemeral
        // port in the microseconds between.
        let port = {
            let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .expect("bind loopback listener");
            let p = listener.local_addr().expect("local addr").port();
            drop(listener);
            p
        };
        assert!(
            !upstream_alive(port),
            "a closed port must read as dead (the pre-flight's error path)"
        );
    }
}
