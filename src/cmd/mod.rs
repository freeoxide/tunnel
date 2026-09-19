//! Command dispatch for `ft`.
//!
//! This module is the single entry point used by `main`: [`run`] consumes the
//! parsed [`Cli`] and routes it to the matching command implementation. When no
//! subcommand is present, the implicit START command runs against the positional
//! `dir` (`ft <dir>`), matching the contract documented on [`crate::cli::Cli`].

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
/// Upper bound on how long a parent waits for the tunnel URL. Dev servers
/// can be slow to boot, so this is generous (30 s).
pub(crate) const POLL_TIMEOUT: Duration = Duration::from_secs(30);

/// Dispatch the parsed CLI to the matching command.
///
/// A `Some(command)` is matched to its handler; `None` falls through to the
/// implicit START command with the positional directory (defaulting to `.`).
pub async fn run(cli: Cli) -> Result<()> {
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
            // The static-origin flags only exist on the implicit START (the
            // CLI structurally has no such flag on any subcommand), so the
            // never-on-proxy exclusion holds by construction.
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
