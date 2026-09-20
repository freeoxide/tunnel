//! Command dispatch for `ft`: [`run`] routes the parsed [`Cli`] to its
//! handler; no subcommand = the implicit START against the positional `dir`.

pub mod detail;
pub mod doctor;
pub mod drop;
pub mod hook;
pub mod kill;
pub mod list;
pub mod logs;
pub mod open;
pub mod proxy;
pub mod prune;
pub mod run;
pub mod sanitize;
pub mod start;

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;

use crate::cli::{Cli, Command};

/// Poll cadence while a parent waits for a worker to publish the public URL.
/// Shared by the START/PROXY/RUN/HOOK background flows.
pub(crate) const POLL_INTERVAL: Duration = Duration::from_millis(250);
/// Upper bound on how long a parent waits for the tunnel URL — generous
/// (30 s) because dev servers boot slowly.
pub(crate) const POLL_TIMEOUT: Duration = Duration::from_secs(30);
/// Origin-probe connect timeout (doctor's blocking probe, run's async twin);
/// loopback resolves instantly, nothing is ever read.
pub(crate) const PROBE_TIMEOUT: Duration = Duration::from_millis(500);

/// Dispatch the parsed CLI; `None` falls through to the implicit START (dir
/// defaults to `.`).
pub async fn run(cli: Cli) -> Result<()> {
    // Short-lived printing commands only — serving paths must NEVER do this
    // (see reset_sigpipe).
    if matches!(
        cli.command,
        Some(
            Command::Ls
                | Command::Detail { .. }
                | Command::Doctor
                | Command::Kill { .. }
                | Command::Logs { .. }
                | Command::Open { .. }
                | Command::Prune
                | Command::Sanitize
        )
    ) {
        crate::output::reset_sigpipe();
    }
    match cli.command {
        Some(Command::Ls) => list::run().await,
        Some(Command::Detail { target }) => detail::run(target).await,
        Some(Command::Doctor) => doctor::run().await,
        Some(Command::Kill { target }) => kill::run(target).await,
        Some(Command::Logs { target, follow }) => logs::run(target, follow).await,
        Some(Command::Open { target }) => open::run(target).await,
        Some(Command::Prune) => prune::run().await,
        Some(Command::Proxy {
            port,
            name,
            foreground,
        }) => proxy::run(port, name, foreground).await,
        Some(Command::Run {
            port,
            name,
            foreground,
            command,
        }) => run::run(port, name, foreground, &command).await,
        Some(Command::Hook {
            port,
            name,
            foreground,
            keep,
        }) => hook::run(port, name, foreground, keep).await,
        Some(Command::Drop {
            dir,
            port,
            name,
            foreground,
            token,
            max_size,
        }) => drop::run(dir, port, name, foreground, token, max_size).await,
        Some(Command::Sanitize) => sanitize::run().await,
        Some(Command::RunWorker {
            id,
            name,
            dir,
            port,
            command,
            keep,
            max_size,
        }) => crate::worker::run(id, name, dir, port, command, keep, max_size).await,
        None => {
            let dir: PathBuf = cli.dir.unwrap_or_else(|| PathBuf::from("."));
            // The static-origin flags exist only on the implicit START, so
            // the never-on-proxy exclusion holds by construction.
            let static_flags = crate::model::StaticFlags {
                spa: cli.spa,
                cors: cli.cors,
                token: cli.token,
            };
            start::run(
                Some(dir),
                cli.name,
                cli.port,
                cli.foreground,
                cli.yes,
                static_flags,
            )
            .await
        }
    }
}
