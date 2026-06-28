//! Command dispatch for `ft`.
//!
//! This module is the single entry point used by `main`: [`run`] consumes the
//! parsed [`Cli`] and routes it to the matching command implementation. When no
//! subcommand is present, the implicit START command runs against the positional
//! `dir` (`ft <dir>`), matching the contract documented on [`crate::cli::Cli`].

pub mod detail;
pub mod kill;
pub mod list;
pub mod logs;
pub mod open;
pub mod start;

use std::path::PathBuf;

use anyhow::Result;

use crate::cli::{Cli, Command};

/// Dispatch the parsed CLI to the matching command.
///
/// A `Some(command)` is matched to its handler; `None` falls through to the
/// implicit START command with the positional directory (defaulting to `.`).
pub async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Some(Command::Ls) => list::run().await,
        Some(Command::Detail { target }) => detail::run(target).await,
        Some(Command::Kill { target }) => kill::run(target).await,
        Some(Command::Logs { target, follow }) => logs::run(target, follow).await,
        Some(Command::Open { target }) => open::run(target).await,
        Some(Command::RunWorker {
            id,
            name,
            dir,
            port,
        }) => crate::worker::run(id, name, dir, port).await,
        None => {
            let dir: PathBuf = cli.dir.unwrap_or_else(|| PathBuf::from("."));
            start::run(Some(dir), cli.name, cli.port, cli.foreground).await
        }
    }
}
