//! The PROXY command: attach a tunnel to a server the operator already runs —
//! no ft server, just cloudflared pointing straight at the upstream. The
//! background flow mirrors START's reserve → spawn-worker → poll-for-URL
//! shape (foreground machinery in `cmd/start.rs`, `dir: None` = proxy). No
//! `--yes` (no directory); the CLI pre-flights the upstream: a friendly
//! "nothing is listening" beats a tunnel that 502s every request.

use anyhow::ensure;

use super::start;
use crate::cloudflared;
use crate::cmd::doctor;
use crate::error::Result;
use crate::model::ServiceKind;
use crate::spawn;
use crate::state::StateDir;

pub async fn run(port: u16, name: Option<String>, foreground: bool) -> Result<()> {
    // CLI-level convenience ONLY — the worker never probes (cloudflared
    // connects lazily); hard error in both modes, no opt-out by design.
    ensure!(
        doctor::origin_alive(port),
        "nothing is listening on 127.0.0.1:{port} — start the server you want to \
         tunnel (or double-check the port number) first"
    );

    if foreground {
        // `dir: None` selects proxy semantics; no re-probe by design — the
        // pre-flight above already covered the port.
        start::run_foreground(None, name, Some(port)).await
    } else {
        run_background(port, name).await
    }
}

/// Background flow: the shared reserve → spawn-worker → poll-for-URL shape;
/// no port-freeness probe — the port IS the upstream, supposed to be in use.
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
