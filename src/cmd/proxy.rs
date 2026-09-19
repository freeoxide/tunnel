//! The PROXY command.
//!
//! `ft proxy <port>` attaches a tunnel to a server the operator already runs
//! on a local port: ft starts no server of its own, it just spawns cloudflared
//! pointing straight at `http://127.0.0.1:<port>` and registers the result
//! like any other service. The background flow mirrors START's reserve-entry →
//! spawn-worker → poll-for-URL shape; the shared foreground machinery lives in
//! `cmd/start.rs`, where a `dir` of `None` selects proxy semantics.
//!
//! Unlike START there is no directory to resolve or confirm, so there is no
//! `--yes` flag. Instead the CLI pre-flights the upstream
//! (`doctor::origin_alive`): a friendly "nothing is listening" error beats a
//! tunnel that comes up happily and then 502s every request.

use anyhow::ensure;

use super::start;
use crate::cloudflared;
use crate::cmd::doctor;
use crate::error::Result;
use crate::model::ServiceKind;
use crate::spawn;
use crate::state::StateDir;

/// Entry point for the PROXY command.
pub async fn run(port: u16, name: Option<String>, foreground: bool) -> Result<()> {
    // CLI-level convenience ONLY: the worker itself deliberately never probes
    // (cloudflared connects lazily, so a dead upstream is not a worker-side
    // start failure). Hard error in BOTH modes by design — a tunnel that
    // comes up against a dead port 502s every request, which is far more
    // confusing than being told up front. No opt-out flag: attach after the
    // server boots by starting the server first.
    ensure!(
        doctor::origin_alive(port),
        "nothing is listening on 127.0.0.1:{port} — start the server you want to \
         tunnel (or double-check the port number) first"
    );

    if foreground {
        // `dir: None` selects proxy semantics (no static server; cloudflared
        // fronts the upstream directly). No re-probe by design: the
        // pre-flight above already covered the port.
        start::run_foreground(None, name, Some(port)).await
    } else {
        run_background(port, name).await
    }
}

/// Background flow: reserve the entry, spawn the detached worker, then poll
/// for the public URL (failing fast if the worker dies first). Unlike START
/// there is no directory resolution and no port freeness probe — the port IS
/// the operator's upstream and is *supposed* to be in use.
async fn run_background(port: u16, name: Option<String>) -> Result<()> {
    let state = StateDir::new()?;

    // Looked up before reserving anything, so a missing binary fails without
    // leaving a half-started entry to clean up.
    cloudflared::ensure_installed()?;

    state.ensure()?;

    let (id, name) = start::reserve_entry(
        &state,
        ServiceKind::Proxy,
        None,
        format!("proxy-{port}"),
        port,
        name,
        0,
        false,
        Default::default(),
    )?;

    // `dir: None` spawns a PROXY worker: what it fronts comes from the
    // reserved entry, and the spawn path substitutes its `--dir` sentinel.
    let worker_pid = match spawn::spawn_worker(id, &name, None, port) {
        Ok(pid) => pid,
        Err(e) => {
            start::remove_reservation(&state, id);
            return Err(e);
        }
    };
    start::record_worker_pid(&state, id, worker_pid)?;

    start::poll_for_url(&state, id, &name, worker_pid).await
}
