//! The PROXY command: attach a tunnel to a server the operator already runs —
//! The CLI pre-flights the upstream so the failure is friendly, not a 502.

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
        start::run_foreground(None, name, Some(port)).await
    } else {
        run_background(port, name).await
    }
}

async fn run_background(port: u16, name: Option<String>) -> Result<()> {
    let state = StateDir::new()?;

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
