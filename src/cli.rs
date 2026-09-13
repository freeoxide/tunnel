//! Command-line interface definition for `ft`.
//!
//! Uses clap derive. `ft` with no subcommand is treated as the implicit START
//! command against a positional directory: `ft ./site` starts a tunnel for
//! `./site`. All other invocations are explicit subcommands (`ls`, `detail`,
//! `doctor`, `kill`, `logs`, `open`, `prune`, `proxy`, `sanitize`, and the
//! hidden `run-worker`).

use std::ffi::OsString;
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

    /// Run a command (e.g. a dev server) and expose it through a tunnel.
    ///
    /// Spawns the given command, waits for it to accept connections on
    /// `PORT`, then fronts it with a cloudflared Quick Tunnel pointing
    /// straight at `http://127.0.0.1:PORT` — nothing ft-owned in between.
    /// The service is registered and managed like any other (`ls`, `detail`,
    /// `kill`, `logs`, `open`, `prune`), and `ft kill` tears the tunnel AND
    /// the command down together — the spawned child never outlives its
    /// tunnel. `PORT` is also exported to the command's environment so
    /// well-behaved tools pick it up.
    Run {
        /// Local port the command must end up listening on (1-65535).
        /// REQUIRED and explicit (mirroring `ft proxy <port>`): `ft` never
        /// guesses which port a dev server picked. Also exported to the
        /// command's environment as `PORT`.
        #[arg(long, value_name = "PORT", value_parser = clap::value_parser!(u16).range(1..))]
        port: u16,

        /// Explicit service name. Defaults to `run-<port>` (made unique).
        #[arg(long)]
        name: Option<String>,

        /// Run in the foreground instead of spawning a detached worker.
        #[arg(long, short)]
        foreground: bool,

        /// The command to run, after `--` (e.g.
        /// `ft run --port 3000 -- npm start`). Everything after `--` is the
        /// command and its arguments, verbatim.
        #[arg(last = true, value_name = "COMMAND")]
        command: Vec<OsString>,
    },

    /// Run a webhook receiver/inspector and expose it through a tunnel.
    ///
    /// `ft` runs its own origin (like `ft <dir>`, the server lives inside the
    /// worker) that records every request arriving through the tunnel —
    /// method, path, query, selected headers, and the size-capped body — to a
    /// private per-service store, answering each with 200 OK. Inspect the
    /// records through the tunnel itself: `GET /__inspect` (HTML, newest
    /// first) or `GET /__inspect.json` (JSON array for scripts). Only the
    /// newest N requests are kept (`--keep`, default 200), so the disk cannot
    /// fill. The service is registered and managed like any other (`ls`,
    /// `detail`, `kill`, `logs`, `open`, `prune`).
    Hook {
        /// Local port for ft's own hook origin (1-65535). Defaults to a free,
        /// allocated port.
        #[arg(long, value_name = "PORT", value_parser = clap::value_parser!(u16).range(1..))]
        port: Option<u16>,

        /// Explicit service name. Defaults to `hook-<port>` (made unique).
        #[arg(long)]
        name: Option<String>,

        /// Run in the foreground instead of spawning a detached worker.
        #[arg(long, short)]
        foreground: bool,

        /// Keep the newest N recorded requests (1-1000, default 200). Older
        /// records are dropped on every append so the store stays bounded.
        #[arg(long, value_name = "N", value_parser = clap::value_parser!(u16).range(1..=1000))]
        keep: Option<u16>,
    },

    /// Run an upload receiver ("drop bucket") and expose it through a tunnel.
    ///
    /// `ft` runs its own origin (like `ft <dir>`, the server lives inside the
    /// worker) that accepts uploads into `DIR` and serves the stored files
    /// back. Uploads are POST/PUT of a RAW body, named by the path
    /// (`POST /file.txt`) or by `?filename=` on `/`; multipart is not parsed
    /// and is stored as opaque bytes. Every upload MUST present the access
    /// token (`Authorization: Bearer` or `?token=`); downloads (GET) are
    /// public — anyone holding the tunnel URL can read what you drop.
    /// Caps: per-upload `--max-size` (413 over it) and a fixed 1 GiB
    /// total-store cap (507 over it). Uploads never overwrite; dotfiles,
    /// separators, and traversal names are rejected. The service is
    /// registered and managed like any other (`ls`, `detail`, `kill`, `logs`,
    /// `open`, `prune`).
    Drop {
        /// Directory uploads are stored in. It must already exist; sensitive
        /// directories (/, $HOME, /etc, ...) are refused — uploads WRITE
        /// into this directory through the public tunnel, and only ONE drop
        /// service may target a given directory.
        #[arg(value_name = "DIR")]
        dir: PathBuf,

        /// Local port for ft's own drop origin (1-65535). Defaults to a free,
        /// allocated port.
        #[arg(long, value_name = "PORT", value_parser = clap::value_parser!(u16).range(1..))]
        port: Option<u16>,

        /// Explicit service name. Defaults to `drop-<port>` (made unique).
        #[arg(long)]
        name: Option<String>,

        /// Run in the foreground instead of spawning a detached worker.
        #[arg(long, short)]
        foreground: bool,

        /// Access token REQUIRED for every upload (POST/PUT) — sent as
        /// `Authorization: Bearer <SECRET>` or `?token=<SECRET>` and compared
        /// in constant time. When omitted, a crypto-random token is
        /// generated, PRINTED ONCE here, stored in the service's private
        /// state dir, and shown by `ft detail`. Downloads (GET) need no token.
        #[arg(long, value_name = "SECRET")]
        token: Option<String>,

        /// Per-upload size cap in bytes, 1..=1073741824 (default 67108864 =
        /// 64 MiB). Oversized uploads are rejected with 413; the total-store
        /// cap is a fixed 1 GiB (507).
        #[arg(
            long,
            value_name = "BYTES",
            value_parser = clap::value_parser!(u64).range(1..=crate::drop_server::MAX_TOTAL_STORE)
        )]
        max_size: Option<u64>,
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
        /// The user's command child, for a Run worker: everything the spawn
        /// path placed after `--`, verbatim. Empty for static and proxy
        /// workers, which spawn no command.
        #[arg(last = true, required = false, value_name = "COMMAND")]
        command: Vec<OsString>,
        /// Retention for a Hook worker: keep the newest N recorded requests.
        /// `None` for every other kind. Retention is runtime configuration
        /// carried in the worker's argv (like the command tail), not registry
        /// state — it is read by the origin itself, not by any lifecycle
        /// command.
        #[arg(long)]
        keep: Option<u16>,
        /// Per-upload size cap for a Drop worker (`--max-size`). `None` for
        /// every other kind. Runtime configuration carried in the worker's
        /// argv (like `--keep`), not registry state; the access token does
        /// NOT ride the argv (visible in `ps`) — the worker reads it from the
        /// service's private token file.
        #[arg(long)]
        max_size: Option<u64>,
    },
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
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
    fn run_minimal_form_after_the_separator() {
        // `ft run --port 3000 -- npm start`: the explicit port is required,
        // and everything after `--` is the child command, verbatim.
        let cli = parse(&["run", "--port", "3000", "--", "npm", "start"])
            .expect("`ft run --port 3000 -- npm start` must parse");
        match cli.command {
            Some(Command::Run {
                port,
                name,
                foreground,
                command,
            }) => {
                assert_eq!(port, 3000);
                assert_eq!(name, None);
                assert!(!foreground);
                assert_eq!(
                    command,
                    vec![OsString::from("npm"), OsString::from("start")]
                );
            }
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn run_name_foreground_and_command_flags() {
        // Flags belong to `ft` and must be given BEFORE `--`; after the
        // separator everything — including things that look like flags — is
        // passed to the child command untouched.
        let cli = parse(&[
            "run",
            "--port",
            "5173",
            "--name",
            "web",
            "--foreground",
            "--",
            "npm",
            "run",
            "dev",
            "--verbose",
        ])
        .expect("`ft run` with flags and a flag-looking command arg must parse");
        match cli.command {
            Some(Command::Run {
                port,
                name,
                foreground,
                command,
            }) => {
                assert_eq!(port, 5173);
                assert_eq!(name.as_deref(), Some("web"));
                assert!(foreground);
                assert_eq!(
                    command,
                    vec![
                        OsString::from("npm"),
                        OsString::from("run"),
                        OsString::from("dev"),
                        // A flag-looking token AFTER `--` must land in the
                        // command, never be eaten as an ft flag.
                        OsString::from("--verbose"),
                    ]
                );
            }
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn run_rejects_port_zero_and_out_of_range() {
        // The port is the contract with the spawned command (and is exported
        // as PORT), so 0 — the kernel's "assign me one" sentinel — and
        // out-of-range values are rejected before anything runs.
        assert!(
            parse(&["run", "--port", "0", "--", "x"]).is_err(),
            "port 0 must be rejected"
        );
        assert!(
            parse(&["run", "--port", "70000", "--", "x"]).is_err(),
            "ports beyond u16 must be rejected"
        );
    }

    #[test]
    fn run_requires_the_separator_and_a_command() {
        // `ft run` alone is a usage error (no port, no command). A port
        // without any `--` tail parses to an EMPTY command here — clap keeps
        // the `last = true` positional optional — so the empty-command
        // refusal is deliberately owned by cmd::run's runtime check, which
        // fires before any state is touched; this test pins that split so a
        // future clap change cannot move the error into state-creating
        // territory unnoticed.
        assert!(parse(&["run"]).is_err(), "missing port and command");
        match parse(&["run", "--port", "3000"])
            .expect("port-only must parse")
            .command
        {
            Some(Command::Run { command, .. }) => {
                assert!(command.is_empty(), "no `--` tail means an empty command");
            }
            other => panic!("expected Run, got {other:?}"),
        }
        assert!(
            parse(&["run", "--port", "3000", "npm", "start"]).is_err(),
            "a command before `--` is not accepted"
        );
    }

    #[test]
    fn run_worker_command_is_optional_and_verbatim() {
        // The hidden run-worker subcommand must keep parsing WITHOUT a
        // command tail (static and proxy workers pass none — existing spawn
        // argv shape), and with one it receives the child command verbatim
        // after its own `--`.
        let cli = parse(&[
            "run-worker",
            "--id",
            "7",
            "--name",
            "blog",
            "--dir",
            "/srv/blog",
            "--port",
            "8000",
        ])
        .expect("the historical run-worker argv shape must keep parsing");
        match cli.command {
            Some(Command::RunWorker { command, .. }) => assert!(command.is_empty()),
            other => panic!("expected RunWorker, got {other:?}"),
        }

        let cli = parse(&[
            "run-worker",
            "--id",
            "9",
            "--name",
            "dev",
            "--dir",
            "/ft-proxy-has-no-directory",
            "--port",
            "3000",
            "--",
            "npm",
            "run",
            "dev",
        ])
        .expect("a run-worker argv carrying a command must parse");
        match cli.command {
            Some(Command::RunWorker { command, .. }) => assert_eq!(
                command,
                vec![
                    OsString::from("npm"),
                    OsString::from("run"),
                    OsString::from("dev")
                ]
            ),
            other => panic!("expected RunWorker, got {other:?}"),
        }
    }

    #[test]
    fn hook_minimal_form_defaults_everything() {
        // `ft hook` with no flags at all must parse: the port is allocated
        // later by the command (like the implicit static start), the name
        // derives from the port, and retention falls back to the documented
        // default.
        let cli = parse(&["hook"]).expect("`ft hook` must parse");
        match cli.command {
            Some(Command::Hook {
                port,
                name,
                foreground,
                keep,
            }) => {
                assert_eq!(port, None);
                assert_eq!(name, None);
                assert!(!foreground);
                assert_eq!(keep, None);
            }
            other => panic!("expected Hook, got {other:?}"),
        }
    }

    #[test]
    fn hook_flags_parse_and_reject_out_of_range_values() {
        // Every flag of `ft hook` parses when in range — and the two numeric
        // ones are usage errors out of range, before any state is touched
        // (port 0 is the kernel's "assign me one" sentinel; keep 0 would
        // retain nothing, and both bounds are the CLI's documented contract).
        let cli = parse(&[
            "hook",
            "--port",
            "9000",
            "--name",
            "gh",
            "--foreground",
            "--keep",
            "50",
        ])
        .expect("`ft hook` with all flags must parse");
        match cli.command {
            Some(Command::Hook {
                port,
                name,
                foreground,
                keep,
            }) => {
                assert_eq!(port, Some(9000));
                assert_eq!(name.as_deref(), Some("gh"));
                assert!(foreground);
                assert_eq!(keep, Some(50));
            }
            other => panic!("expected Hook, got {other:?}"),
        }

        assert!(
            parse(&["hook", "--port", "0"]).is_err(),
            "port 0 must be rejected"
        );
        assert!(
            parse(&["hook", "--port", "70000"]).is_err(),
            "ports beyond u16 must be rejected"
        );
        assert!(
            parse(&["hook", "--keep", "0"]).is_err(),
            "keep 0 must be rejected"
        );
        assert!(
            parse(&["hook", "--keep", "1001"]).is_err(),
            "keep beyond the documented 1000 cap must be rejected"
        );
    }

    #[test]
    fn run_worker_keep_flag_is_optional() {
        // The hidden run-worker gains the Hook retention flag: it must keep
        // parsing WITHOUT it (every historical worker argv shape passes none)
        // and carry it verbatim when a hook spawn passes `--keep N`.
        let cli = parse(&[
            "run-worker",
            "--id",
            "3",
            "--name",
            "gh",
            "--dir",
            "/ft-proxy-has-no-directory",
            "--port",
            "9000",
        ])
        .expect("the historical run-worker argv shape must keep parsing");
        match cli.command {
            Some(Command::RunWorker { keep, .. }) => assert_eq!(keep, None),
            other => panic!("expected RunWorker, got {other:?}"),
        }

        let cli = parse(&[
            "run-worker",
            "--id",
            "4",
            "--name",
            "gh",
            "--dir",
            "/ft-proxy-has-no-directory",
            "--port",
            "9001",
            "--keep",
            "7",
        ])
        .expect("a run-worker argv carrying --keep must parse");
        match cli.command {
            Some(Command::RunWorker { keep, .. }) => assert_eq!(keep, Some(7)),
            other => panic!("expected RunWorker, got {other:?}"),
        }
    }

    #[test]
    fn drop_minimal_form_is_just_the_directory() {
        // `ft drop ~/inbox` must parse with every flag defaulted: the port is
        // allocated later by the command (like `ft hook`), the name derives
        // from the port, the token is generated at runtime, and the cap falls
        // back to the documented default.
        let cli = parse(&["drop", "inbox"]).expect("`ft drop inbox` must parse");
        match cli.command {
            Some(Command::Drop {
                dir,
                port,
                name,
                foreground,
                token,
                max_size,
            }) => {
                assert_eq!(dir, PathBuf::from("inbox"));
                assert_eq!(port, None);
                assert_eq!(name, None);
                assert!(!foreground);
                assert_eq!(token, None);
                assert_eq!(max_size, None);
            }
            other => panic!("expected Drop, got {other:?}"),
        }
    }

    #[test]
    fn drop_flags_parse_and_reject_out_of_range_values() {
        // Every flag of `ft drop` parses when in range — and the numeric ones
        // are usage errors out of range, before any state is touched (port 0
        // is the kernel's "assign me one" sentinel; the cap is bounded by the
        // fixed 1 GiB total-store cap, so no single upload can be configured
        // past what the bucket can hold).
        let cli = parse(&[
            "drop",
            "/srv/inbox",
            "--port",
            "9000",
            "--name",
            "share",
            "--foreground",
            "--token",
            "sekrit",
            "--max-size",
            "1048576",
        ])
        .expect("`ft drop` with all flags must parse");
        match cli.command {
            Some(Command::Drop {
                dir,
                port,
                name,
                foreground,
                token,
                max_size,
            }) => {
                assert_eq!(dir, PathBuf::from("/srv/inbox"));
                assert_eq!(port, Some(9000));
                assert_eq!(name.as_deref(), Some("share"));
                assert!(foreground);
                assert_eq!(token.as_deref(), Some("sekrit"));
                assert_eq!(max_size, Some(1048576));
            }
            other => panic!("expected Drop, got {other:?}"),
        }

        assert!(
            parse(&["drop", "inbox", "--port", "0"]).is_err(),
            "port 0 must be rejected"
        );
        assert!(
            parse(&["drop", "inbox", "--port", "70000"]).is_err(),
            "ports beyond u16 must be rejected"
        );
        assert!(
            parse(&["drop", "inbox", "--max-size", "0"]).is_err(),
            "a zero cap must be rejected"
        );
        assert!(
            parse(&["drop", "inbox", "--max-size", "1073741825"]).is_err(),
            "a cap beyond the 1 GiB total-store bound must be rejected"
        );
    }

    #[test]
    fn run_worker_max_size_flag_is_optional() {
        // The hidden run-worker gains the Drop cap flag: it must keep parsing
        // WITHOUT it (every historical worker argv shape passes none) and
        // carry it verbatim when a drop spawn passes `--max-size N`.
        let cli = parse(&[
            "run-worker",
            "--id",
            "3",
            "--name",
            "share",
            "--dir",
            "/srv/inbox",
            "--port",
            "9000",
        ])
        .expect("the historical run-worker argv shape must keep parsing");
        match cli.command {
            Some(Command::RunWorker { max_size, .. }) => assert_eq!(max_size, None),
            other => panic!("expected RunWorker, got {other:?}"),
        }

        let cli = parse(&[
            "run-worker",
            "--id",
            "4",
            "--name",
            "share",
            "--dir",
            "/srv/inbox",
            "--port",
            "9001",
            "--max-size",
            "4096",
        ])
        .expect("a run-worker argv carrying --max-size must parse");
        match cli.command {
            Some(Command::RunWorker { max_size, .. }) => assert_eq!(max_size, Some(4096)),
            other => panic!("expected RunWorker, got {other:?}"),
        }
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
