// Freeoxide Tunnel (`ft`) — expose local/static services through temporary tunnels.
//
// Binary entry point. The CLI is defined in `cli`, dispatched by `cmd`, and
// the core modules (model, registry, state, ports, names, process helpers)
// live in their own modules. `main` only parses the CLI, runs the dispatch,
// and maps any error to a clean single-line message on stderr before
// exiting non-zero.

mod cli;
mod cloudflared;
mod cmd;
mod error;
mod fsutil;
mod model;
mod name;
mod output;
mod port;
mod proc;
mod registry;
mod server;
mod spawn;
mod state;
mod worker;

use clap::Parser;

use crate::cli::{Cli, Command};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // The detached worker installs its own file-based subscriber (worker.log,
    // plus server.log for static services). Every OTHER invocation gets a
    // default stderr subscriber (RUST_LOG-tuned, default `warn`) so its
    // diagnostics are not silently dropped; `try_init` is a no-op if one is
    // already installed.
    if !matches!(cli.command, Some(Command::RunWorker { .. })) {
        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .try_init();
    }

    if let Err(err) = cmd::run(cli).await {
        // Print only the top-level message so the CLI output stays clean.
        eprintln!("{err}");
        std::process::exit(1);
    }
    Ok(())
}
