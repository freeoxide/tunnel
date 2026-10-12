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

    // The worker installs its own file subscriber; `try_init` no-ops if set.
    if !matches!(cli.command, Some(Command::RunWorker { .. })) {
        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .try_init();
    }

    if let Err(err) = cmd::run(cli).await {
        eprintln!("{err}");
        std::process::exit(1);
    }
    Ok(())
}
