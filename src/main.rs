// Freeoxide Tunnel (`ft`) — expose local/static services through temporary tunnels.
//
// Binary entry point. The CLI is defined in `cli`, dispatched by `cmd`, and the
// frozen core (model, registry, state, ports, names, process helpers) lives in
// its own modules. `main` only parses the CLI, runs the dispatch, and maps any
// error to a clean single-line message on stderr before exiting non-zero.

mod cli;
mod cloudflared;
mod cmd;
mod error;
mod model;
mod name;
mod output;
mod port;
mod proc;
mod registry;
mod spawn;
mod state;
mod static_server;
mod worker;

use clap::Parser;

use crate::cli::Cli;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if let Err(err) = cmd::run(cli).await {
        // Print only the top-level message so the CLI output stays clean.
        eprintln!("{err}");
        std::process::exit(1);
    }
    Ok(())
}
