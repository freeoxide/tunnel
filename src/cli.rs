//! Command-line interface definition for `ft`.
//!
//! Uses clap derive. `ft` with no subcommand is treated as the implicit START
//! command against a positional directory: `ft ./site` starts a tunnel for
//! `./site`. All other invocations are explicit subcommands (`ls`, `detail`,
//! `kill`, `logs`, `open`, and the hidden `run-worker`).

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Freeoxide Tunnel — expose local and static services through temporary tunnels.
#[derive(Debug, Parser)]
#[command(
    name = "ft",
    version,
    about = "Freeoxide Tunnel — expose local and static services through temporary tunnels"
)]
pub struct Cli {
    /// Optional subcommand. When omitted, the positional `dir` is used to run
    /// the implicit START command (`ft <dir>`).
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Directory to expose when no subcommand is given (the implicit START).
    ///
    /// clap parses the first token as a subcommand only if it matches one of
    /// the known subcommand names; otherwise it falls through to this
    /// positional, so `ft ./site` works as expected.
    pub dir: Option<PathBuf>,

    /// Explicit service name. Defaults to a generated, unique name.
    #[arg(long)]
    pub name: Option<String>,

    /// Local port to bind on. Defaults to a free, allocated port.
    #[arg(long)]
    pub port: Option<u16>,

    /// Run in the foreground instead of spawning a detached worker.
    #[arg(long, short)]
    pub foreground: bool,

    /// Answer "yes" to the sensitive-directory confirmation prompt
    /// (e.g. when publishing `$HOME` or `/`). Non-interactive runs that target
    /// a sensitive directory must pass this or they will refuse to start.
    #[arg(long, short = 'y')]
    pub yes: bool,
}

/// Explicit subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// List all known services.
    #[command(alias = "ps")]
    Ls,

    /// Show detailed information about a single service.
    #[command(alias = "inspect")]
    Detail {
        /// Service target: numeric ID or name.
        target: String,
    },

    /// Stop a running service and remove it from the registry.
    #[command(alias = "stop")]
    Kill {
        /// Service target: numeric ID or name.
        target: String,
    },

    /// Print or follow the logs for a service.
    Logs {
        /// Service target: numeric ID or name.
        target: String,

        /// Follow the log output (tail -f style).
        #[arg(long, short)]
        follow: bool,
    },

    /// Open the public URL of a service in the default browser.
    Open {
        /// Service target: numeric ID or name.
        target: String,
    },

    /// Remove stale services whose worker process is no longer running.
    #[command(alias = "gc")]
    Prune,

    /// Internal: detached worker process spawned by START.
    #[command(hide = true)]
    RunWorker {
        /// Numeric ID allocated by the registry.
        #[arg(long)]
        id: u64,
        /// Service name.
        #[arg(long)]
        name: String,
        /// Absolute directory being served.
        #[arg(long)]
        dir: PathBuf,
        /// Local port to bind on.
        #[arg(long)]
        port: u16,
    },
}
