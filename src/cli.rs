//! Command-line interface definition for `ft`.
//!
//! Uses clap derive. `ft` with no subcommand is treated as the implicit START
//! command against a positional directory: `ft ./site` starts a tunnel for
//! `./site`. All other invocations are explicit subcommands (`ls`, `detail`,
//! `doctor`, `kill`, `logs`, `open`, `prune`, `proxy`, `sanitize`, and the
//! hidden `run-worker`).

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

    /// Diagnose tunnel health and report problems with actionable hints.
    ///
    /// Checks that `cloudflared` is on `PATH`, that every registered
    /// service's worker is still alive, and — the motivating case — that a
    /// live worker's local origin still accepts connections: a proxy whose
    /// upstream port went away serves 502s through an otherwise healthy
    /// tunnel, and nothing in `ft ls` shows it. Strictly read-only: no
    /// registry mutation, no signalling, no spawning; remediations are
    /// printed as hints (`ft kill <name>`, `ft sanitize`, …), never executed.
    /// Takes no arguments and exits 0 whenever it ran at all — findings are
    /// information, not command failures.
    Doctor,

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

    /// Attach a tunnel to a local server that is already running.
    ///
    /// Fronts the existing server on `PORT` (e.g. a dev server on 3000) with a
    /// cloudflared Quick Tunnel. `ft` starts no server of its own here — the
    /// tunnel points straight at `http://127.0.0.1:PORT` — and the service is
    /// registered and managed like any other (`ls`, `detail`, `kill`, `logs`,
    /// `open`, `prune`).
    Proxy {
        /// Local port the existing server listens on (1-65535). The port is
        /// the service's identity in the registry; `ft` never binds it.
        #[arg(value_name = "PORT", value_parser = clap::value_parser!(u16).range(1..))]
        port: u16,

        /// Explicit service name. Defaults to `proxy-<port>` (made unique).
        #[arg(long)]
        name: Option<String>,

        /// Run in the foreground instead of spawning a detached worker.
        #[arg(long, short)]
        foreground: bool,
    },

    /// Remove every dangling service — stale entries AND live tunnels whose
    /// local origin port is dead.
    ///
    /// Covers everything `ft prune` does (entries whose worker died,
    /// abandoned start reservations, best-effort reaping of orphaned
    /// `cloudflared`) plus the zombie prune cannot see: an `ft proxy`
    /// service whose worker and tunnel are happily up while the upstream
    /// server behind them died — the tunnel 502s every request while `ft ls`
    /// shows a healthy service. Origin ports are double-probed (~750 ms
    /// apart) so a dev server that is mid-restart is not reaped. Foreground
    /// services are never killed: an upstream-dead foreground service is
    /// reported as left alone instead (stop it with Ctrl-C in its own
    /// terminal). Takes no arguments and exits 0 whenever it ran.
    #[command(alias = "clean")]
    Sanitize,

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

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{Cli, Command};
    use clap::Parser as _;

    /// Parse `ft <args>` (the binary name is prepended for clap's usage
    /// strings, exactly like a real invocation).
    fn parse(args: &[&str]) -> std::result::Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("ft").chain(args.iter().copied()))
    }

    #[test]
    fn proxy_minimal_positional_port() {
        let cli = parse(&["proxy", "3000"]).expect("`ft proxy 3000` must parse");
        match cli.command {
            Some(Command::Proxy {
                port,
                name,
                foreground,
            }) => {
                assert_eq!(port, 3000);
                assert_eq!(name, None);
                assert!(!foreground);
            }
            other => panic!("expected Proxy, got {other:?}"),
        }
    }

    #[test]
    fn proxy_name_and_foreground_flags() {
        let cli = parse(&["proxy", "3000", "--name", "api", "--foreground"])
            .expect("`ft proxy 3000 --name api --foreground` must parse");
        match cli.command {
            Some(Command::Proxy {
                port,
                name,
                foreground,
            }) => {
                assert_eq!(port, 3000);
                assert_eq!(name.as_deref(), Some("api"));
                assert!(foreground);
            }
            other => panic!("expected Proxy, got {other:?}"),
        }
    }

    #[test]
    fn proxy_rejects_port_zero() {
        // 0 is the kernel's "assign me one" sentinel, never a real upstream;
        // the value-parser range turns it into a clap usage error before any
        // state is touched (mirrors the explicit `port != 0` guards the worker
        // and the foreground path re-run in depth).
        assert!(parse(&["proxy", "0"]).is_err(), "port 0 must be rejected");
    }

    #[test]
    fn proxy_requires_an_in_range_port() {
        assert!(parse(&["proxy"]).is_err(), "the port is required");
        assert!(
            parse(&["proxy", "70000"]).is_err(),
            "ports beyond u16 must be rejected"
        );
        assert!(
            parse(&["proxy", "http"]).is_err(),
            "non-numeric ports must be rejected"
        );
    }

    #[test]
    fn doctor_parses_with_no_arguments() {
        // `ft doctor` is deliberately flagless and argumentless: everything it
        // needs is discovered from the environment, so there is nothing a user
        // could pass that would change what is checked.
        let cli = parse(&["doctor"]).expect("`ft doctor` must parse");
        assert!(matches!(cli.command, Some(Command::Doctor)));
    }

    #[test]
    fn doctor_rejects_any_arguments_or_flags() {
        // Unknown flags and stray positionals must be clap usage errors, not
        // silently ignored tokens — a typo like `ft doctor --fxid` should tell
        // the user rather than run a partial diagnosis.
        assert!(parse(&["doctor", "--anything"]).is_err(), "no flags exist");
        assert!(parse(&["doctor", "extra"]).is_err(), "no arguments exist");
    }

    #[test]
    fn sanitize_parses_with_no_arguments() {
        // Like doctor, sanitize is deliberately flagless and argumentless:
        // its inputs (the registry, worker probes, origin double-probes) are
        // all discovered from the environment, so there is nothing a user
        // could pass that would change what gets cleaned.
        let cli = parse(&["sanitize"]).expect("`ft sanitize` must parse");
        assert!(matches!(cli.command, Some(Command::Sanitize)));
    }

    #[test]
    fn clean_is_an_alias_for_sanitize() {
        // Same variant as the repo's other aliases (ls→ps, kill→stop,
        // prune→gc, detail→inspect): a friendlier spelling, nothing more.
        let cli = parse(&["clean"]).expect("`ft clean` must parse");
        assert!(matches!(cli.command, Some(Command::Sanitize)));
    }

    #[test]
    fn sanitize_rejects_any_arguments_or_flags() {
        // A typo like `ft sanitize --force` must be a clap usage error, not a
        // silently ignored token that runs a partial cleanup.
        assert!(
            parse(&["sanitize", "--anything"]).is_err(),
            "no flags exist"
        );
        assert!(parse(&["sanitize", "extra"]).is_err(), "no arguments exist");
    }

    #[test]
    fn implicit_start_still_reaches_the_positional_dir() {
        // `ft ./site` must keep falling through to the implicit START (the
        // first token matches no subcommand name), and `ft proxy 3000` must
        // NOT be misread as a directory now that `proxy` is a subcommand.
        let cli = parse(&["./site"]).expect("`ft ./site` must parse");
        assert!(cli.command.is_none());
        assert_eq!(cli.dir, Some(PathBuf::from("./site")));
    }
}
