//! End-to-end integration tests for the `ft` binary.
//!
//! This is a binary crate (`[[bin]] name = "ft"`), so integration tests cannot
//! import internal modules. Instead we spawn the freshly-built binary via the
//! `CARGO_BIN_EXE_ft` env var that Cargo injects for integration tests, and
//! drive the real CLI dispatch, registry load/validate/save, and process
//! liveness probes as a black box.
//!
//! Each test pins `XDG_STATE_HOME` to a private tempdir (passed only to the
//! spawned subprocess via `Command::env`, never mutated on the test process)
//! so `ft` resolves its state tree (`$XDG_STATE_HOME/freeoxide/tunnel`)
//! there. We seed `registry.json` directly to exercise the on-disk
//! load → validate → classify → save round-trip that unit tests can only
//! cover in pieces.
//!
//! The cloudflared/URL-discovery happy path is intentionally NOT covered here:
//! it needs a real `cloudflared` binary and network, so it is out of scope for
//! CI. These tests target the registry/proc seams that `ft ls`, `ft prune`,
//! and `ft detail` exercise without any external process.
//!
//! The `ft proxy` command is covered on the same terms: its loopback upstream
//! pre-flight runs BEFORE cloudflared is looked up or any state is created, so
//! the failure path is drivable with a dead ephemeral port, and the proxy
//! rendering/lifecycle surface is drivable with `"kind": "proxy"` seeded
//! fixtures (kill/prune/logs are kind-agnostic — they target pids).
//!
//! `ft doctor` is covered the same way: it must exit 0 whether or not
//! `cloudflared` is installed (a missing binary is a finding, never an error —
//! CI has none), and its motivating 502 finding is drivable by seeding a
//! foreground "running" proxy (the test's own pid + a public URL) whose
//! upstream port is a freshly dead ephemeral one.
//!
//! `ft sanitize` is covered on those same fixtures, with one wrinkle: its
//! foreground liveness is prune's PID-reuse-safe `--foreground` cmdline
//! probe (NOT `Service::status`'s plain existence check), so a "running"
//! foreground entry needs a worker whose cmdline actually carries the token
//! — a decoy `sh -c 'while :; do sleep 30; done' --foreground` child
//! (sanitize never signals a foreground worker, so the decoy is safe; the
//! loop form keeps the token in the shell's argv — see
//! `spawn_foreground_worker`).
//! Its origin port is either really bound or freshly dead, plus the seeded
//! stale / reservation bodies prune uses. A live BACKGROUND zombie (which
//! sanitize would tear down with real group signals) needs a real
//! `run-worker` process, so that arm is not black-box drivable and stays
//! covered by the pure decision table's unit tests in `cmd/sanitize.rs`.

#![cfg(unix)] // proc::pid_alive uses a Unix-only cmdline identity probe.

use std::fs;
use std::net::{Ipv4Addr, TcpListener};
use std::path::PathBuf;
use std::process::Command;

use tempfile::TempDir;

/// Absolute path to the freshly-built `ft` binary (Cargo provides this env var
/// to integration tests). Resolving up front (rather than per-test) surfaces a
/// clear panic if the harness forgets to set it.
fn ft_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ft"))
}

/// Where `ft` reads/writes its registry for a given `XDG_STATE_HOME` root.
fn registry_path(xdg_root: &std::path::Path) -> PathBuf {
    xdg_root
        .join("freeoxide")
        .join("tunnel")
        .join("registry.json")
}

/// Build a minimal-but-valid single-service registry blob.
///
/// Fields mirror `model::Service`. `worker_pid`/`foreground`/`public_url` are
/// the levers the liveness probe and `ft prune` branch on, so they are the
/// test knobs; everything else is fixed boilerplate that satisfies
/// `Registry::validate` (non-zero id, non-empty unique name, non-zero port).
fn registry_json(worker_pid: u32, foreground: bool, public_url: Option<&str>) -> String {
    let url_field = match public_url {
        Some(u) => format!("{u:?}"),
        None => "null".to_string(),
    };
    format!(
        r#"{{
  "next_id": 2,
  "services": [
    {{
      "id": 1,
      "name": "seed-svc",
      "kind": "static",
      "dir": "/tmp/seed-dir",
      "port": 8080,
      "local_url": "http://127.0.0.1:8080",
      "public_url": {url_field},
      "worker_pid": {worker_pid},
      "tunnel_pid": null,
      "created_at": "2026-07-21T00:00:00Z",
      "state_dir": "/tmp/seed-state",
      "foreground": {foreground}
    }}
  ]
}}"#
    )
}

/// Proxy-flavoured counterpart of [`registry_json`]: a single-service
/// registry whose entry carries `"kind": "proxy"` and `"dir": null` — exactly
/// the on-disk shape `ft proxy` reserves. `worker_pid` and `created_at` are
/// the levers: the staleness probes branch on the pid (0 = reserved, a huge
/// pid = recorded-but-dead worker), and the M1 start-grace tests need to pin
/// a fresh vs an expired `created_at`.
fn proxy_registry_json(worker_pid: u32, created_at: &str, public_url: Option<&str>) -> String {
    let url_field = match public_url {
        Some(u) => format!("{u:?}"),
        None => "null".to_string(),
    };
    format!(
        r#"{{
  "next_id": 2,
  "services": [
    {{
      "id": 1,
      "name": "seed-proxy",
      "kind": "proxy",
      "dir": null,
      "port": 3000,
      "local_url": "http://127.0.0.1:3000",
      "public_url": {url_field},
      "worker_pid": {worker_pid},
      "tunnel_pid": null,
      "created_at": "{created_at}",
      "state_dir": "/tmp/seed-proxy-state",
      "foreground": false
    }}
  ]
}}"#
    )
}

/// Registry body for a foreground proxy that reads Running through sanitize's
/// real probes: the given (live) pid with `foreground: true` plus a published
/// public URL, fronting `port`. Whether its origin is alive depends only on
/// whether the caller bound a listener on `port` first — exactly the seam
/// doctor's finding and sanitize's double-probe decide on. The pid must come
/// from [`spawn_foreground_worker`]: sanitize checks foreground liveness with
/// the PID-reuse-safe `--foreground` cmdline probe (prune's rule), so a bare
/// "own pid" fixture would — correctly — read as stale.
fn foreground_proxy_json(pid: u32, port: u16) -> String {
    format!(
        r#"{{
  "next_id": 2,
  "services": [
    {{
      "id": 1,
      "name": "seed-proxy",
      "kind": "proxy",
      "dir": null,
      "port": {port},
      "local_url": "http://127.0.0.1:{port}",
      "public_url": "https://x.trycloudflare.com",
      "worker_pid": {pid},
      "tunnel_pid": null,
      "created_at": "2026-07-21T00:00:00Z",
      "state_dir": "/tmp/seed-proxy-state",
      "foreground": true
    }}
  ]
}}"#
    )
}

/// A decoy "foreground worker" owned by the test that spawned it: dropping
/// the guard kills and reaps the shell, so a panic between spawn and the
/// test's cleanup point cannot leak the decoy — the endless loop would
/// otherwise outlive the test for the machine's remaining uptime. Killing
/// the shell does not reach its children, so the in-flight `sleep 30` can
/// orphan for up to 30 s more before its own timer expires: bounded, and
/// documented rather than hidden.
struct DecoyWorker {
    child: std::process::Child,
}

impl DecoyWorker {
    fn pid(&self) -> u32 {
        self.child.id()
    }
}

impl Drop for DecoyWorker {
    fn drop(&mut self) {
        // Best-effort: both calls fail harmlessly on an already-dead child,
        // and wait() reaps it so the pid cannot linger as a zombie.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Block until the decoy's command line — as `ps` prints it — carries the
/// `--foreground` token the binary's identity probe gates on.
///
/// A readiness barrier, not paranoia: the cmdline surfaces the probe reads
/// (`/proc/<pid>/cmdline` on Linux, KERN_PROCARGS2 on macOS) can lag the
/// fork, and losing that race makes the probe CORRECTLY read the decoy as
/// stale — surfacing as a baffling assertion failure deep inside `ft
/// sanitize`'s output instead of an error at the spawn site. Polling here
/// turns any such platform quirk into a clear setup error, and the timeout
/// panic reports the LAST observation — ps's output, or the error of a ps
/// that could not run — keeping "token absent" distinct from "ps
/// unavailable".
fn wait_for_foreground_token(pid: u32) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    // The last poll's observation — the ps output when it ran, the error
    // when it did not — so the timeout panic cannot conflate the two.
    let mut last_seen = String::from("`ps` has not completed a poll yet");
    while std::time::Instant::now() < deadline {
        // `ps -o command= -p PID` prints the full argv on Linux and macOS
        // alike — a black-box view of the same cmdline the probe reads.
        let poll = Command::new("ps")
            .arg("-o")
            .arg("command=")
            .arg("-p")
            .arg(pid.to_string())
            .output();
        match poll {
            Ok(out) => {
                let command = String::from_utf8_lossy(&out.stdout).into_owned();
                if command.contains("--foreground") {
                    return;
                }
                last_seen = format!("`ps` reports {command:?}");
            }
            Err(e) => last_seen = format!("`ps` itself failed to run: {e}"),
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    panic!("decoy never became probe-ready for pid {pid}: {last_seen}");
}

/// Spawn a decoy "foreground worker": a live process whose cmdline contains
/// `--foreground` — the exact identity sanitize's foreground liveness probe
/// gates on — staying alive until killed, which the returned [`DecoyWorker`]
/// guard does on drop.
///
/// A real foreground worker is an `ft <dir> --foreground` process, which
/// needs `cloudflared` and the network, so the black-box tests drive just
/// the identity seam instead: `sh -c CMD NAME` puts NAME (`--foreground`)
/// into the sh process's cmdline, where `/proc/<pid>/cmdline` (and macOS's
/// KERN_PROCARGS2) happily report it. Sanitize never signals a foreground
/// worker — it only reports it — so the decoy cannot become collateral
/// damage of the very rule it stands in for.
///
/// The `-c` body is deliberately an endless sleep LOOP (`while :; do
/// sleep 30; done`), not the simple command — or `;`-separated list — a
/// tidy-minded pass would reduce it to: several shells silently REPLACE
/// their own process image with a final external command, taking the token
/// with them. bash (macOS's /bin/sh) does it for a lone `-c` simple
/// command — the macOS CI flake: argv collapsed to bare `sleep 30` and the
/// probe correctly read the entry stale — and busybox ash demonstrably
/// tail-execs the LAST command of a top-level `;` list as well (the same
/// EV_EXIT/shellexec tail-exec runs throughout the dash/ash/ksh lineage;
/// Debian dash 0.5.12 happens to fork instead, but one build's behaviour
/// is not a portable guarantee). A loop body is never in tail position on
/// any of them — the shell must return to run the next iteration — so the
/// token stays in the shell's argv for its whole life, and the loop also
/// never ends: the [`DecoyWorker`] guard's Drop is the decoy's only exit.
/// The post-spawn [`wait_for_foreground_token`] poll then guarantees the
/// token is visible before the caller seeds state, so the decoy's identity
/// is a checked fact rather than a hope.
fn spawn_foreground_worker() -> DecoyWorker {
    // The guard is built BEFORE the readiness barrier runs: if the barrier
    // panics, unwinding drops the guard and reaps the decoy — a bare
    // `std::process::Child`'s Drop is a no-op and would leak the endless
    // loop for the machine's remaining uptime.
    let worker = DecoyWorker {
        child: Command::new("sh")
            .arg("-c")
            // An endless loop on purpose — see the doc comment above before
            // simplifying.
            .arg("while :; do sleep 30; done")
            // Becomes the shell's $0 and a cmdline token for the identity
            // probe.
            .arg("--foreground")
            .spawn()
            .expect("spawning decoy foreground worker"),
    };
    wait_for_foreground_token(worker.pid());
    worker
}

/// Seed `registry.json` under `xdg_root` with one service and return its path.
fn seed_registry(xdg_root: &std::path::Path, body: &str) -> PathBuf {
    let path = registry_path(xdg_root);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, body).unwrap();
    path
}

/// Run `ft <args>` against an isolated state dir. Returns (status, combined
/// stdout+stderr) so assertions can look at either stream.
fn run_ft(xdg_root: &std::path::Path, args: &[&str]) -> (bool, String) {
    let output = Command::new(ft_bin())
        .args(args)
        // Isolate the subprocess's state tree to our tempdir. Setting this on
        // the Command affects ONLY the child — no mutation of the test
        // process's env, which would be `unsafe` in edition 2024.
        .env("XDG_STATE_HOME", xdg_root)
        // Keep the binary from inheriting a noisy RUST_LOG that would pollute
        // stdout (where our assertions look) with trace output.
        .env("RUST_LOG", "")
        .output()
        .expect("spawning `ft` binary");
    let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&output.stderr));
    (output.status.success(), combined)
}

/// A loopback port with nothing listening on it.
///
/// Bind an ephemeral listener, note its port, then drop it: the port is closed
/// again immediately (same technique as the in-module `upstream_alive` tests
/// in `cmd/proxy.rs`; only loopback is ever touched). Another process could
/// theoretically re-grab that exact ephemeral port in the microseconds before
/// `ft` probes it, but the kernel does not hand out just-released ephemeral
/// ports that eagerly — accepted risk, same as the unit tests.
fn dead_loopback_port() -> u16 {
    let listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind ephemeral loopback listener");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    port
}

/// A loopback port left in TIME_WAIT by a just-stopped server.
///
/// Bind an ephemeral listener, connect a client, then close the SERVER side
/// first (listener, then the accepted stream, while the client is still
/// open): the active close leaves the server endpoint — bound to the returned
/// port — held by FIN_WAIT/TIME_WAIT sockets instead of a listener. Loopback
/// only, same accepted-risk note as [`dead_loopback_port`].
fn time_wait_loopback_port() -> u16 {
    let listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind ephemeral loopback listener");
    let port = listener.local_addr().expect("local addr").port();
    let client = std::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port)).expect("connect");
    let accepted = listener.accept().expect("accept").0;
    // Drop order is the point: the server closes while the client is still
    // open, so the close is ACTIVE on the server endpoint.
    drop(listener);
    drop(accepted);
    drop(client);
    port
}

/// Every file AND directory under `root`, recursively; empty when `root` does
/// not exist yet.
///
/// Pins the proxy pre-flight's "zero state" guarantee precisely: not just "no
/// registry entry" but also no `services/` dir and no `registry.lock`.
/// Directories are collected too — `StateDir::ensure` creates an empty root +
/// `services/` with zero files, so a files-only walk would let exactly that
/// regression pass the emptiness assertion.
fn tree_paths(root: &std::path::Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        // A missing dir simply contributes nothing (its children cannot exist).
        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path.clone());
                }
                paths.push(path);
            }
        }
    }
    paths
}

/// The current UTC time as an RFC 3339 `YYYY-MM-DDTHH:MM:SSZ` timestamp.
///
/// Needed to seed a `created_at` INSIDE `model::START_GRACE` (60 s), which a
/// fixed fixture date can never be. `chrono` is a regular dependency (not a
/// dev-dependency) and this crate has no lib target, so integration tests
/// cannot use it — the civil-from-days conversion is done by hand instead
/// (Howard Hinnant's algorithm; ranges are exact over i64 division).
fn now_rfc3339() -> String {
    fn civil_from_days(days: i64) -> (i64, u32, u32) {
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z.rem_euclid(146_097);
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        (if m <= 2 { y + 1 } else { y }, m as u32, d as u32)
    }
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after 1970")
        .as_secs() as i64;
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    let rem = secs.rem_euclid(86_400);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

#[test]
fn ls_on_empty_registry_reports_no_services() {
    // No seeded registry file at all: `Registry::load` falls back to a fresh
    // default, and `ft ls` must print the empty-registry sentinel rather than
    // erroring on the missing file.
    let dir = TempDir::new().unwrap();
    let (ok, out) = run_ft(dir.path(), &["ls"]);
    assert!(ok, "`ft ls` on an empty registry failed: {out}");
    assert!(
        out.contains("(no services)"),
        "expected the empty-registry sentinel, got: {out}"
    );
}

#[test]
fn prune_reaps_stale_entry_and_persists() {
    // Seed a background entry whose worker_pid points at a process that does
    // not exist (4_000_000 is far outside any real pid namespace). `ft prune`
    // must classify it as stale, remove it, and persist the empty registry.
    let dir = TempDir::new().unwrap();
    let reg = seed_registry(
        dir.path(),
        &registry_json(4_000_000, /* foreground */ false, None),
    );

    let (ok, out) = run_ft(dir.path(), &["prune"]);
    assert!(ok, "`ft prune` failed: {out}");
    assert!(
        out.contains("Pruned 1 stale service"),
        "expected prune to report one reaped service, got: {out}"
    );
    assert!(
        out.contains("seed-svc"),
        "expected the pruned service's name in the output, got: {out}"
    );

    // The registry on disk must now be empty: prune went through the real
    // load → classify → save pipeline and committed the change.
    let after = fs::read_to_string(&reg).unwrap();
    assert!(
        !after.contains("seed-svc"),
        "prune should have removed the stale entry, but registry is still: {after}"
    );

    // A follow-up `ft prune` is idempotent and reports nothing to do.
    let (ok2, out2) = run_ft(dir.path(), &["prune"]);
    assert!(ok2, "second `ft prune` failed: {out2}");
    assert!(
        out2.contains("No stale services"),
        "expected idempotent empty prune, got: {out2}"
    );
}

// Limited to Linux/macOS: the "stale" expectation below hinges on the
// cmdline-needle behaviour of `pid_alive`, which only those two (plus Windows)
// implement. On other Unix `pid_alive` falls back to a plain signal-0 probe,
// which would read our live `sleep` child as alive and flip the expectation.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn ls_reports_status_through_real_proc_probe() {
    // Two seeded entries exercising the status probe end-to-end through the
    // binary's real `Service::status` (which calls into `proc::pid_alive` /
    // `proc::process_exists`):
    //   - id 1: worker_pid 0  -> "starting" (no probe; reserved-id path).
    //   - id 2: worker_pid = a live `sleep` child of THIS test. Because the
    //     child's cmdline lacks the `run-worker` needle, the cmdline-aware
    //     `pid_alive` reads it as a foreign (PID-reused) process -> "stale".
    //     This is the exact seam the START poll loop and prune rely on, driven
    //     here through the real binary rather than a unit test.
    let dir = TempDir::new().unwrap();
    let mut sleep = Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("spawning `sleep 30`");
    let live_pid = sleep.id();

    let body = format!(
        r#"{{
  "next_id": 3,
  "services": [
    {{
      "id": 1,
      "name": "starting-entry",
      "kind": "static",
      "dir": "/tmp/a",
      "port": 8001,
      "local_url": "http://127.0.0.1:8001",
      "public_url": null,
      "worker_pid": 0,
      "tunnel_pid": null,
      "created_at": "2026-07-21T00:00:00Z",
      "state_dir": "/tmp/a-state",
      "foreground": false
    }},
    {{
      "id": 2,
      "name": "foreign-pid",
      "kind": "static",
      "dir": "/tmp/b",
      "port": 8002,
      "local_url": "http://127.0.0.1:8002",
      "public_url": null,
      "worker_pid": {live_pid},
      "tunnel_pid": null,
      "created_at": "2026-07-21T00:00:00Z",
      "state_dir": "/tmp/b-state",
      "foreground": false
    }}
  ]
}}"#
    );
    seed_registry(dir.path(), &body);

    let (ok, out) = run_ft(dir.path(), &["ls"]);
    let _ = sleep.kill();
    let _ = sleep.wait();

    assert!(ok, "`ft ls` failed: {out}");
    assert!(
        out.contains("starting-entry") && out.contains("starting"),
        "expected the worker_pid==0 entry to read as starting, got: {out}"
    );
    assert!(
        out.contains("foreign-pid") && out.contains("stale"),
        "expected a foreign (non-`run-worker`) pid to read as stale, got: {out}"
    );
}

#[test]
fn detail_round_trips_a_seeded_entry() {
    // `ft detail <id>` reads, validates, and renders a single entry through the
    // real binary — covering the detail dispatch + registry find seam.
    let dir = TempDir::new().unwrap();
    seed_registry(
        dir.path(),
        &registry_json(
            4_000_000,
            /* foreground */ false,
            Some("https://x.trycloudflare.com"),
        ),
    );

    let (ok_by_id, out_by_id) = run_ft(dir.path(), &["detail", "1"]);
    assert!(ok_by_id, "`ft detail 1` failed: {out_by_id}");
    assert!(
        out_by_id.contains("seed-svc"),
        "missing name in: {out_by_id}"
    );
    assert!(
        out_by_id.contains("Public URL:"),
        "missing public url field in: {out_by_id}"
    );
    assert!(
        out_by_id.contains("https://x.trycloudflare.com"),
        "expected the seeded public url, got: {out_by_id}"
    );

    // Name target resolves to the same entry.
    let (ok_by_name, out_by_name) = run_ft(dir.path(), &["detail", "seed-svc"]);
    assert!(ok_by_name, "`ft detail seed-svc` failed: {out_by_name}");
    assert!(
        out_by_name.contains("seed-svc"),
        "name target did not resolve to the entry: {out_by_name}"
    );
}

// --- `ft proxy` (pre-flight + seeded-fixture lifecycle; no cloudflared) ---

#[test]
fn proxy_dead_upstream_fails_friendly_and_leaves_no_state() {
    // The pre-flight runs before cloudflared is looked up and before ANY state
    // is created, so a dead port exercises the whole command through the real
    // binary with neither cloudflared nor network: friendly error, exit 1,
    // and a completely untouched state tree.
    let dir = TempDir::new().unwrap();
    let port = dead_loopback_port();
    let port_arg = port.to_string();

    // Background mode.
    let (ok, out) = run_ft(dir.path(), &["proxy", &port_arg]);
    assert!(!ok, "a dead upstream must fail `ft proxy`, got: {out}");
    assert!(
        out.contains(&format!("nothing is listening on 127.0.0.1:{port}")),
        "expected the friendly pre-flight error naming the port, got: {out}"
    );

    // Foreground mode: the pre-flight precedes the mode split, so it must
    // fail identically rather than attaching against a dead port.
    let (ok_fg, out_fg) = run_ft(dir.path(), &["proxy", &port_arg, "--foreground"]);
    assert!(
        !ok_fg,
        "foreground pre-flight must also fail, got: {out_fg}"
    );
    assert!(
        out_fg.contains(&format!("nothing is listening on 127.0.0.1:{port}")),
        "expected the same friendly error in foreground mode, got: {out_fg}"
    );

    // Zero state: no registry entry, no services/ dir, no lock file.
    assert!(
        tree_paths(dir.path()).is_empty(),
        "a failed proxy start must leave no state, found: {:?}",
        tree_paths(dir.path())
    );

    // And the registry still reads as empty afterwards.
    let (ok_ls, out_ls) = run_ft(dir.path(), &["ls"]);
    assert!(ok_ls, "`ft ls` after a failed proxy start failed: {out_ls}");
    assert!(
        out_ls.contains("(no services)"),
        "expected an untouched empty registry, got: {out_ls}"
    );
}

#[test]
fn proxy_help_documents_the_command() {
    let dir = TempDir::new().unwrap();
    let (ok, out) = run_ft(dir.path(), &["proxy", "--help"]);
    assert!(ok, "`ft proxy --help` failed: {out}");
    assert!(
        out.contains("Usage: ft proxy"),
        "missing the usage line in: {out}"
    );
    assert!(
        out.contains("<PORT>"),
        "missing the PORT argument in: {out}"
    );
    assert!(out.contains("--name"), "missing --name in: {out}");
    assert!(
        out.contains("--foreground"),
        "missing --foreground in: {out}"
    );
}

#[test]
fn proxy_rejects_missing_and_invalid_ports_with_usage_errors() {
    // Port validation is clap's (range 1..=65535), so every bad port is a
    // usage error (exit 2) before anything runs — and therefore also leaves
    // no state.
    let dir = TempDir::new().unwrap();
    for (args, expected) in [
        (&["proxy"][..], "required arguments were not provided"),
        (&["proxy", "abc"][..], "invalid digit found in string"),
        (&["proxy", "0"][..], "0 is not in 1..=65535"),
        (&["proxy", "70000"][..], "70000 is not in 1..=65535"),
    ] {
        let (ok, out) = run_ft(dir.path(), args);
        assert!(
            !ok,
            "expected a usage error for `ft {}`, got: {out}",
            args.join(" ")
        );
        assert!(
            out.contains(expected),
            "expected `{expected}` in the usage error for `ft {}`, got: {out}",
            args.join(" ")
        );
    }
    assert!(
        tree_paths(dir.path()).is_empty(),
        "usage errors must leave no state, found: {:?}",
        tree_paths(dir.path())
    );
}

#[test]
fn proxy_fixture_renders_in_ls_and_detail() {
    // Mixed registry — one static and one proxy entry, the state after
    // `ft ./dist` and `ft proxy 3000` coexist. Both pids are recorded-but-
    // dead (4_000_000 is far outside any real pid namespace) so the status
    // column is deterministic (`stale`) for both kinds.
    let dir = TempDir::new().unwrap();
    let body = r#"{
  "next_id": 3,
  "services": [
    {
      "id": 1,
      "name": "seed-svc",
      "kind": "static",
      "dir": "/tmp/seed-dir",
      "port": 8080,
      "local_url": "http://127.0.0.1:8080",
      "public_url": null,
      "worker_pid": 4000000,
      "tunnel_pid": null,
      "created_at": "2026-07-21T00:00:00Z",
      "state_dir": "/tmp/seed-state",
      "foreground": false
    },
    {
      "id": 2,
      "name": "seed-proxy",
      "kind": "proxy",
      "dir": null,
      "port": 3000,
      "local_url": "http://127.0.0.1:3000",
      "public_url": "https://x.trycloudflare.com",
      "worker_pid": 4000000,
      "tunnel_pid": null,
      "created_at": "2026-07-21T00:00:00Z",
      "state_dir": "/tmp/seed-proxy-state",
      "foreground": false
    }
  ]
}"#;
    seed_registry(dir.path(), body);

    // `ls` is kind-agnostic: both rows render, and the proxy's PORT column
    // carries its upstream port.
    let (ok_ls, out_ls) = run_ft(dir.path(), &["ls"]);
    assert!(ok_ls, "`ft ls` on a mixed registry failed: {out_ls}");
    assert!(
        out_ls.contains("seed-svc") && out_ls.contains("seed-proxy"),
        "expected both rows in the list, got: {out_ls}"
    );
    assert!(
        out_ls.contains("3000"),
        "expected the proxy's upstream port in its row, got: {out_ls}"
    );

    // `detail` is kind-aware for the proxy: Mode names the kind, Upstream
    // replaces Directory, and the Logs list has no server.log (a proxy runs
    // no static server, so its worker never creates one).
    let (ok, out) = run_ft(dir.path(), &["detail", "seed-proxy"]);
    assert!(ok, "`ft detail seed-proxy` failed: {out}");
    assert!(
        out.contains("Mode:         proxy"),
        "expected the proxy Mode row, got: {out}"
    );
    assert!(
        out.contains("Upstream:     http://127.0.0.1:3000"),
        "expected the Upstream row, got: {out}"
    );
    assert!(
        !out.contains("Directory:"),
        "a proxy entry must not render a Directory row: {out}"
    );
    assert!(
        out.contains("worker.log") && out.contains("tunnel.log"),
        "expected worker/tunnel logs listed, got: {out}"
    );
    assert!(
        !out.contains("server.log"),
        "a proxy entry must not list server.log: {out}"
    );
    assert!(
        out.contains("https://x.trycloudflare.com"),
        "expected the seeded public url, got: {out}"
    );

    // The static entry in the same registry keeps its historical shape.
    let (ok_static, out_static) = run_ft(dir.path(), &["detail", "seed-svc"]);
    assert!(ok_static, "`ft detail seed-svc` failed: {out_static}");
    assert!(
        out_static.contains("Directory:    /tmp/seed-dir"),
        "expected the static Directory row, got: {out_static}"
    );
    assert!(
        out_static.contains("server.log"),
        "a static entry still lists server.log, got: {out_static}"
    );
}

#[test]
fn kill_removes_a_stale_proxy_entry_like_a_static_one() {
    // kill is kind-agnostic (it targets pids): a recorded-but-dead worker pid
    // makes the entry stale, and killing it reports the stale removal and
    // persists the emptied registry — exactly like the static fixture test.
    let dir = TempDir::new().unwrap();
    let reg = seed_registry(
        dir.path(),
        &proxy_registry_json(4_000_000, "2026-07-21T00:00:00Z", None),
    );

    let (ok, out) = run_ft(dir.path(), &["kill", "seed-proxy"]);
    assert!(ok, "`ft kill` on a stale proxy entry failed: {out}");
    assert!(
        out.contains("Removed stale service seed-proxy."),
        "expected the stale-removal message, got: {out}"
    );

    let after = fs::read_to_string(&reg).unwrap();
    assert!(
        !after.contains("seed-proxy"),
        "kill should have removed the proxy entry, but registry is: {after}"
    );
}

#[test]
fn prune_reaps_a_stale_proxy_entry_and_persists() {
    let dir = TempDir::new().unwrap();
    let reg = seed_registry(
        dir.path(),
        &proxy_registry_json(4_000_000, "2026-07-21T00:00:00Z", None),
    );

    let (ok, out) = run_ft(dir.path(), &["prune"]);
    assert!(ok, "`ft prune` on a proxy registry failed: {out}");
    assert!(
        out.contains("Pruned 1 stale service"),
        "expected prune to report one reaped proxy service, got: {out}"
    );
    assert!(
        out.contains("seed-proxy"),
        "expected the pruned proxy service's name, got: {out}"
    );

    let after = fs::read_to_string(&reg).unwrap();
    assert!(
        !after.contains("seed-proxy"),
        "prune should have removed the stale proxy entry, but registry is: {after}"
    );
}

#[test]
fn kill_refuses_a_fresh_proxy_reservation_within_the_start_grace() {
    // M1 grace window, proxy flavour: a pid-0 reservation younger than
    // START_GRACE (60 s) reads as "still starting", so `ft kill` must refuse
    // with the friendly error and leave the entry for the parent's imminent
    // pid record. `created_at` has to be NOW (hence the hand-formatted
    // timestamp); the fixture date used elsewhere is long past the grace.
    let dir = TempDir::new().unwrap();
    let reg = seed_registry(dir.path(), &proxy_registry_json(0, &now_rfc3339(), None));

    let (ok, out) = run_ft(dir.path(), &["kill", "seed-proxy"]);
    assert!(
        !ok,
        "kill inside the start-grace window must fail, got: {out}"
    );
    assert!(
        out.contains("still starting"),
        "expected the still-starting refusal, got: {out}"
    );

    // The reserved entry survives the refused kill and still lists as starting.
    let after = fs::read_to_string(&reg).unwrap();
    assert!(
        after.contains("seed-proxy"),
        "the reserved proxy entry must survive a refused kill, registry: {after}"
    );
    let (ok_ls, out_ls) = run_ft(dir.path(), &["ls"]);
    assert!(ok_ls, "`ft ls` after a refused kill failed: {out_ls}");
    assert!(
        out_ls.contains("seed-proxy") && out_ls.contains("starting"),
        "expected the reserved proxy entry to still list as starting, got: {out_ls}"
    );
}

#[test]
fn prune_keeps_a_fresh_proxy_reservation_and_reaps_an_expired_one() {
    // Two pid-0 proxy reservations: one fresh (inside START_GRACE — a parent
    // may be mid reserve→spawn→record) and one expired (the parent died
    // mid-start). Prune must reap exactly the expired one; classification is
    // purely created_at-vs-grace, kind plays no role.
    let dir = TempDir::new().unwrap();
    let body = format!(
        r#"{{
  "next_id": 3,
  "services": [
    {{
      "id": 1,
      "name": "proxy-fresh",
      "kind": "proxy",
      "dir": null,
      "port": 3001,
      "local_url": "http://127.0.0.1:3001",
      "public_url": null,
      "worker_pid": 0,
      "tunnel_pid": null,
      "created_at": "{fresh}",
      "state_dir": "/tmp/proxy-fresh-state",
      "foreground": false
    }},
    {{
      "id": 2,
      "name": "proxy-expired",
      "kind": "proxy",
      "dir": null,
      "port": 3002,
      "local_url": "http://127.0.0.1:3002",
      "public_url": null,
      "worker_pid": 0,
      "tunnel_pid": null,
      "created_at": "2026-07-21T00:00:00Z",
      "state_dir": "/tmp/proxy-expired-state",
      "foreground": false
    }}
  ]
}}"#,
        fresh = now_rfc3339()
    );
    let reg = seed_registry(dir.path(), &body);

    let (ok, out) = run_ft(dir.path(), &["prune"]);
    assert!(ok, "`ft prune` failed: {out}");
    assert!(
        out.contains("Pruned 1 stale service") && out.contains("proxy-expired"),
        "expected exactly the expired reservation reaped, got: {out}"
    );
    assert!(
        !out.contains("proxy-fresh"),
        "the fresh reservation must not be reported stale, got: {out}"
    );

    let after = fs::read_to_string(&reg).unwrap();
    assert!(
        after.contains("proxy-fresh") && !after.contains("proxy-expired"),
        "prune must keep the fresh and drop the expired reservation, registry: {after}"
    );
}

// --- `ft run` (usage, occupied-port pre-flight, seeded fixtures; no cloudflared)
//
// Like the proxy section, only paths that stop BEFORE cloudflared is looked up
// are driven here: everything past `cloudflared::ensure_installed` would
// depend on whether this machine has cloudflared — and, worse, on machines
// that do, would really spawn workers + the command child + a live tunnel.
// The spawned flow itself is covered by the unit seams in cmd/run.rs,
// worker.rs, and spawn.rs.

#[test]
fn run_help_documents_the_command() {
    let dir = TempDir::new().unwrap();
    let (ok, out) = run_ft(dir.path(), &["run", "--help"]);
    assert!(ok, "`ft run --help` failed: {out}");
    assert!(
        out.contains("Usage: ft run"),
        "missing the usage line in: {out}"
    );
    assert!(out.contains("--port"), "missing --port in: {out}");
    assert!(
        out.contains("<COMMAND>"),
        "missing the COMMAND placeholder in: {out}"
    );
    assert!(out.contains("--name"), "missing --name in: {out}");
    assert!(
        out.contains("--foreground"),
        "missing --foreground in: {out}"
    );
}

#[test]
fn run_usage_errors_leave_no_state() {
    // Every rejected invocation must fail before the state tree exists: a
    // usage error (clap) or the empty-command check (runtime, deliberately
    // first in cmd::run) means nothing was reserved, spawned, or written.
    let dir = TempDir::new().unwrap();
    for (args, expected) in [
        (&["run"][..], "required arguments were not provided"),
        (
            &["run", "--port", "abc"][..],
            "invalid digit found in string",
        ),
        (
            &["run", "--port", "0", "--", "x"][..],
            "0 is not in 1..=65535",
        ),
        (
            &["run", "--port", "70000", "--", "x"][..],
            "70000 is not in 1..=65535",
        ),
        (
            &["run", "--port", "3000"][..],
            "no command given after `--`",
        ),
        (
            &["run", "--port", "3000", "--"][..],
            "no command given after `--`",
        ),
    ] {
        let (ok, out) = run_ft(dir.path(), args);
        assert!(
            !ok,
            "expected a failure for `ft {}`, got: {out}",
            args.join(" ")
        );
        assert!(
            out.contains(expected),
            "expected `{expected}` for `ft {}`, got: {out}",
            args.join(" ")
        );
    }
    assert!(
        tree_paths(dir.path()).is_empty(),
        "rejected runs must leave no state, found: {:?}",
        tree_paths(dir.path())
    );
}

#[test]
fn run_refuses_an_occupied_port_and_leaves_no_state() {
    // The child ft spawns must be able to BIND the port, so an occupied one
    // fails the pre-flight — before cloudflared is looked up and before any
    // state exists — with a message that names the port. This holds on every
    // machine regardless of cloudflared, because the check precedes that
    // lookup entirely.
    let dir = TempDir::new().unwrap();
    let listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind ephemeral loopback listener");
    let port = listener.local_addr().expect("local addr").port();
    let port_arg = port.to_string();

    let (ok, out) = run_ft(
        dir.path(),
        &["run", "--port", &port_arg, "--", "sleep", "30"],
    );
    // The listener must outlive the run: the probe happens inside it.
    drop(listener);

    assert!(!ok, "an occupied port must fail `ft run`, got: {out}");
    assert!(
        out.contains(&format!("port {port} is already in use")),
        "expected the occupied-port error naming the port, got: {out}"
    );
    assert!(
        tree_paths(dir.path()).is_empty(),
        "a refused run must leave no state, found: {:?}",
        tree_paths(dir.path())
    );
}

#[test]
fn run_accepts_a_port_a_just_stopped_server_left_in_time_wait() {
    // R3-2 end-to-end: `is_port_free` used to be a plain bind probe, so a
    // port still held by TIME_WAIT sockets after a server-side close read as
    // occupied and `ft run` refused the restart spuriously. Drive the real
    // binary against such a port: the pre-flight must NOT refuse with
    // "already in use".
    //
    // PATH is stripped so the run deterministically stops at the cloudflared
    // lookup — the gate right after the port pre-flight — on every machine:
    // with cloudflared installed, the run would otherwise proceed to spawn a
    // real worker and tunnel. Stopping there (with zero state, since
    // `ensure_installed` precedes `state.ensure`) proves the pre-flight let
    // the TIME_WAIT port through.
    let dir = TempDir::new().unwrap();
    let port = time_wait_loopback_port();
    let port_arg = port.to_string();

    let output = Command::new(ft_bin())
        .args(["run", "--port", &port_arg, "--", "sleep", "30"])
        .env("XDG_STATE_HOME", dir.path())
        .env("RUST_LOG", "")
        .env("PATH", "")
        .output()
        .expect("spawning `ft` binary");
    let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&output.stderr));

    assert!(
        !output.status.success(),
        "the run must stop at the cloudflared lookup, got: {combined}"
    );
    assert!(
        !combined.contains(&format!("port {port} is already in use")),
        "a TIME_WAIT-only port must not read as occupied, got: {combined}"
    );
    assert!(
        tree_paths(dir.path()).is_empty(),
        "a run stopped at the cloudflared lookup must leave no state, found: {:?}",
        tree_paths(dir.path())
    );
}

#[test]
fn run_fixture_renders_in_ls_and_detail() {
    // A seeded `"kind": "run"` entry (the on-disk shape `ft run` reserves,
    // including the run-only `command_pid`) must render through the same
    // lifecycle commands as any other kind: kind-agnostic in `ls`, kind-aware
    // in `detail` — Mode names the run, the Command PID row carries the
    // recorded child (the field orphan detection reads), there is no
    // Directory row (a run fronts a port, not a directory), and the Logs list
    // has no server.log (no ft-owned server exists; the command's output is
    // teed into worker.log).
    let dir = TempDir::new().unwrap();
    let body = r#"{
  "next_id": 3,
  "services": [
    {
      "id": 1,
      "name": "seed-run",
      "kind": "run",
      "dir": null,
      "port": 3000,
      "local_url": "http://127.0.0.1:3000",
      "public_url": "https://x.trycloudflare.com",
      "worker_pid": 4000000,
      "tunnel_pid": null,
      "command_pid": 4242,
      "created_at": "2026-07-21T00:00:00Z",
      "state_dir": "/tmp/seed-run-state",
      "foreground": false
    }
  ]
}"#;
    seed_registry(dir.path(), body);

    let (ok_ls, out_ls) = run_ft(dir.path(), &["ls"]);
    assert!(ok_ls, "`ft ls` on a run registry failed: {out_ls}");
    assert!(
        out_ls.contains("seed-run") && out_ls.contains("stale") && out_ls.contains("3000"),
        "expected the run entry listed with its recorded-but-dead worker status \
         and port, got: {out_ls}"
    );

    let (ok, out) = run_ft(dir.path(), &["detail", "seed-run"]);
    assert!(ok, "`ft detail seed-run` failed: {out}");
    assert!(
        out.contains("Mode:         run"),
        "expected the run Mode row, got: {out}"
    );
    assert!(
        out.contains("Command PID:  4242"),
        "expected the recorded command pid, got: {out}"
    );
    assert!(
        !out.contains("Directory:"),
        "a run entry must not render a Directory row: {out}"
    );
    assert!(
        !out.contains("Upstream:"),
        "a run entry is not a proxy and must not render an Upstream row: {out}"
    );
    assert!(
        out.contains("worker.log") && out.contains("tunnel.log"),
        "expected worker/tunnel logs listed, got: {out}"
    );
    assert!(
        !out.contains("server.log"),
        "a run entry must not list server.log: {out}"
    );
    assert!(
        out.contains("https://x.trycloudflare.com"),
        "expected the seeded public url, got: {out}"
    );

    // kill is kind-agnostic (it targets pids): a recorded-but-dead worker pid
    // makes the entry stale, and killing it reports the stale removal and
    // persists the emptied registry.
    let reg = registry_path(dir.path());
    let (ok_kill, out_kill) = run_ft(dir.path(), &["kill", "seed-run"]);
    assert!(ok_kill, "`ft kill seed-run` failed: {out_kill}");
    assert!(
        out_kill.contains("Removed stale service seed-run."),
        "expected the stale-removal message, got: {out_kill}"
    );
    let after = fs::read_to_string(&reg).unwrap();
    assert!(
        !after.contains("seed-run"),
        "kill should have removed the run entry, but registry is: {after}"
    );
}

// --- `ft drop` (usage, pre-flights, seeded fixtures; no cloudflared) --------
//
// Like the hook section, only paths that stop BEFORE cloudflared is looked up
// are driven here: `ft drop` is ft's own origin, so its pre-flights (upload
// target resolution/sensitivity, occupied port, empty token) all run ahead of
// that lookup, and everything past it would depend on whether this machine
// has cloudflared. The origin itself (token auth, caps, sanitization,
// confinement on the GET side) is covered by the drop_server unit tests
// driving the Router directly with tower::oneshot.

#[test]
fn drop_help_documents_the_command() {
    let dir = TempDir::new().unwrap();
    let (ok, out) = run_ft(dir.path(), &["drop", "--help"]);
    assert!(ok, "`ft drop --help` failed: {out}");
    assert!(
        out.contains("Usage: ft drop"),
        "missing the usage line in: {out}"
    );
    assert!(
        out.contains("<DIR>"),
        "missing the DIR positional in: {out}"
    );
    assert!(out.contains("--port"), "missing --port in: {out}");
    assert!(out.contains("--name"), "missing --name in: {out}");
    assert!(
        out.contains("--foreground"),
        "missing --foreground in: {out}"
    );
    assert!(out.contains("--token"), "missing --token in: {out}");
    assert!(out.contains("--max-size"), "missing --max-size in: {out}");
    // The token is the bucket's write credential and its flag is the
    // command's public surface: the help must explain that uploads REQUIRE
    // it and that one is minted and printed when omitted.
    assert!(
        out.contains("token"),
        "the help must mention the token in: {out}"
    );
    assert!(
        out.to_lowercase().contains("printed"),
        "the help must say the generated token is printed: {out}"
    );
}

#[test]
fn drop_usage_errors_and_preflight_refusals_leave_no_state() {
    // Every rejected invocation must fail before the state tree exists: clap
    // usage errors (missing positional, port/cap ranges) and the command's
    // own pre-flights (nonexistent target, sensitive target, empty token)
    // all precede any reservation or spawn.
    let dir = TempDir::new().unwrap();
    let missing = dir.path().join("does-not-exist");
    let missing = missing.to_string_lossy().into_owned();
    // A neutral EXISTING directory for the token-refusal cases: it must not
    // be an ancestor of ft's state root (pinned under `dir`), because serving
    // an ancestor of the state tree would expose registry.json via subpaths
    // and is — correctly — refused as sensitive (R3-7). A second tempdir is
    // a sibling, not an ancestor.
    let neutral = TempDir::new().unwrap();
    let neutral_arg = neutral.path().to_string_lossy().into_owned();
    for (args, expected) in [
        // clap: the DIR positional is required.
        (&["drop"][..], "required arguments were not provided"),
        (
            &["drop", "inbox", "--port", "abc"][..],
            "invalid digit found in string",
        ),
        (
            &["drop", "inbox", "--port", "0"][..],
            "0 is not in 1..=65535",
        ),
        (
            &["drop", "inbox", "--max-size", "0"][..],
            "0 is not in 1..=1073741824",
        ),
        (
            &["drop", "inbox", "--max-size", "1073741825"][..],
            "1073741825 is not in 1..=1073741824",
        ),
        // Runtime pre-flights (before any state): the target must exist, must
        // not be sensitive, and an explicit token must be non-empty.
        (&["drop", &missing][..], "does not exist"),
        (&["drop", "/"][..], "sensitive directory"),
        (
            &["drop", &neutral_arg, "--token", ""][..],
            "--token must be a non-empty secret",
        ),
        // R3-9's flip side at the CLI boundary: a WHITESPACE-ONLY token is
        // refused (not silently accepted untrimmed) — the trim happens once,
        // at token resolution, before anything is stored or printed.
        (
            &["drop", &neutral_arg, "--token", "   "][..],
            "--token must be a non-empty secret",
        ),
    ] {
        let (ok, out) = run_ft(dir.path(), args);
        assert!(
            !ok,
            "expected a failure for `ft {}`, got: {out}",
            args.join(" ")
        );
        assert!(
            out.contains(expected),
            "expected `{expected}` for `ft {}`, got: {out}",
            args.join(" ")
        );
    }
    assert!(
        tree_paths(dir.path()).is_empty(),
        "rejected drops must leave no state, found: {:?}",
        tree_paths(dir.path())
    );
}

#[test]
fn drop_refuses_an_occupied_port_and_leaves_no_state() {
    // The drop origin is ft's OWN server, so an occupied port fails the
    // pre-flight — before cloudflared is looked up and before any state
    // exists — with a message that names the port (same as `ft hook`, the
    // inverse of `ft proxy`'s dead-upstream pre-flight).
    let dir = TempDir::new().unwrap();
    let bucket = TempDir::new().unwrap();
    let bucket_arg = bucket.path().to_string_lossy().into_owned();
    let listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind ephemeral loopback listener");
    let port = listener.local_addr().expect("local addr").port();
    let port_arg = port.to_string();

    let (ok, out) = run_ft(
        dir.path(),
        &[
            "drop",
            &bucket_arg,
            "--port",
            &port_arg,
            "--token",
            "sekrit",
        ],
    );
    // The listener must outlive the run: the probe happens inside it.
    drop(listener);

    assert!(!ok, "an occupied port must fail `ft drop`, got: {out}");
    assert!(
        out.contains(&format!("port {port} is already in use")),
        "expected the occupied-port error naming the port, got: {out}"
    );
    assert!(
        tree_paths(dir.path()).is_empty(),
        "a refused drop must leave no state, found: {:?}",
        tree_paths(dir.path())
    );
}

#[test]
fn drop_refuses_fts_own_state_tree_in_every_overlap() {
    // R3-7: ft's state root ($XDG_STATE_HOME/freeoxide/tunnel) holds
    // registry.json, worker/tunnel logs, hook request records, and every
    // service's drop-token file — all non-dotfile, so a drop bucket placed ON
    // the state root made them publicly readable via unauthenticated GETs
    // (and a bucket WRITE-touches the tree on top of that). The shared
    // sensitive-dir check must refuse every overlap with the state tree: the
    // root itself, a subtree (services/ — the token files live there), and an
    // ancestor (which would serve the tree via subpaths) — before any state
    // is touched. The plain-bucket counterpart
    // (`drop_refuses_an_occupied_port_and_leaves_no_state`) already pins that
    // a NON-state dir still passes this pre-flight and fails later, at the
    // port check.
    let dir = TempDir::new().unwrap();
    let state_root = dir.path().join("freeoxide").join("tunnel");
    let services = state_root.join("services");
    let ancestor = dir.path().join("freeoxide");
    fs::create_dir_all(&services).unwrap();

    // The bucket argument accepts any of the three overlap shapes; each must
    // be refused with the sensitive-directory message.
    for bucket in [state_root.clone(), services.clone(), ancestor.clone()] {
        let arg = bucket.to_string_lossy().into_owned();
        let (ok, out) = run_ft(dir.path(), &["drop", &arg]);
        assert!(
            !ok,
            "dropping onto ft's state tree at {} must be refused: {out}",
            bucket.display()
        );
        assert!(
            out.contains("sensitive directory"),
            "expected the sensitive-dir refusal for {}, got: {out}",
            bucket.display()
        );
    }

    // Refusal happened before any state: no registry, and the pre-created
    // (test-fixture) services dir gained nothing.
    assert!(
        !registry_path(dir.path()).exists(),
        "a refused drop must not create a registry"
    );
    assert!(
        tree_paths(&services).is_empty(),
        "a refused drop must not touch the state tree, found: {:?}",
        tree_paths(&services)
    );
}

#[test]
fn start_refuses_fts_own_state_dir_noninteractively() {
    // R3-7 tightens the START caller too (the check is shared): `ft <state-
    // dir>` without --yes and without a TTY must refuse with the sensitive-
    // directory error, like $HOME does. (--yes keeps its existing
    // confirmed-sensitive override semantics, as for $HOME itself — the fix
    // is the denylist entry, not a new refusal class.)
    let dir = TempDir::new().unwrap();
    let state_root = dir.path().join("freeoxide").join("tunnel");
    fs::create_dir_all(&state_root).unwrap();
    let arg = state_root.to_string_lossy().into_owned();

    let (ok, out) = run_ft(dir.path(), &[arg.as_str()]);

    assert!(
        !ok,
        "starting a tunnel on ft's own state dir must be refused: {out}"
    );
    assert!(
        out.contains("refusing to publish a sensitive directory"),
        "expected the non-interactive sensitive-dir refusal, got: {out}"
    );
    assert!(
        !registry_path(dir.path()).exists(),
        "a refused start must not create a registry"
    );
}

#[test]
fn drop_fixture_renders_in_ls_detail_and_kill() {
    // A seeded `"kind": "drop"` entry (the on-disk shape `ft drop` reserves —
    // note `dir` IS carried, like static, because the bucket is a real
    // directory) must render through the same lifecycle commands as any other
    // kind: kind-agnostic in `ls`, kind-aware in `detail` — Mode names the
    // drop, the Directory row names the upload target, the Token row reads
    // the service's private token file (here seeded so the display contract
    // is pinned end-to-end), and the Logs list has no server.log (the drop
    // origin's record is the bucket directory itself). kill stays
    // kind-agnostic: a dead worker pid makes the entry stale and removable.
    let dir = TempDir::new().unwrap();
    // Anchor the service's state_dir inside the test's tempdir so the token
    // file the detail command reads is private to this test.
    let state_dir = dir.path().join("seed-drop-state");
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(state_dir.join("drop-token"), "tok-seeded-abc\n").unwrap();
    let state_dir_arg = state_dir.to_string_lossy().into_owned();
    let body = format!(
        r#"{{
  "next_id": 3,
  "services": [
    {{
      "id": 1,
      "name": "seed-drop",
      "kind": "drop",
      "dir": "/tmp/seed-bucket",
      "port": 9100,
      "local_url": "http://127.0.0.1:9100",
      "public_url": "https://x.trycloudflare.com",
      "worker_pid": 4000000,
      "tunnel_pid": null,
      "created_at": "2026-07-21T00:00:00Z",
      "state_dir": "{state_dir_arg}",
      "foreground": false
    }}
  ]
}}"#
    );
    seed_registry(dir.path(), &body);

    let (ok_ls, out_ls) = run_ft(dir.path(), &["ls"]);
    assert!(ok_ls, "`ft ls` on a drop registry failed: {out_ls}");
    assert!(
        out_ls.contains("seed-drop") && out_ls.contains("stale") && out_ls.contains("9100"),
        "expected the drop entry listed with its recorded-but-dead worker status \
         and port, got: {out_ls}"
    );

    let (ok, out) = run_ft(dir.path(), &["detail", "seed-drop"]);
    assert!(ok, "`ft detail seed-drop` failed: {out}");
    assert!(
        out.contains("Mode:         drop"),
        "expected the drop Mode row, got: {out}"
    );
    assert!(
        out.contains("Directory:    /tmp/seed-bucket"),
        "expected the bucket Directory row, got: {out}"
    );
    assert!(
        out.contains("Token:        tok-seeded-abc"),
        "expected the token row reading the private token file, got: {out}"
    );
    assert!(
        !out.contains("Upstream:"),
        "a drop entry is not a proxy and must not render an Upstream row: {out}"
    );
    assert!(
        out.contains("worker.log") && out.contains("tunnel.log"),
        "expected worker/tunnel logs listed, got: {out}"
    );
    assert!(
        !out.contains("server.log"),
        "a drop entry must not list server.log: {out}"
    );
    assert!(
        out.contains("https://x.trycloudflare.com"),
        "expected the seeded public url, got: {out}"
    );

    // kill is kind-agnostic (it targets pids): a recorded-but-dead worker pid
    // makes the entry stale, and killing it reports the stale removal and
    // persists the emptied registry.
    let reg = registry_path(dir.path());
    let (ok_kill, out_kill) = run_ft(dir.path(), &["kill", "seed-drop"]);
    assert!(ok_kill, "`ft kill seed-drop` failed: {out_kill}");
    assert!(
        out_kill.contains("Removed stale service seed-drop."),
        "expected the stale-removal message, got: {out_kill}"
    );
    let after = fs::read_to_string(&reg).unwrap();
    assert!(
        !after.contains("seed-drop"),
        "kill should have removed the drop entry, but registry is: {after}"
    );
}

// --- `ft doctor` (read-only diagnosis; no cloudflared needed) ---------------

#[test]
fn doctor_on_a_missing_registry_exits_zero_with_no_service_checks() {
    // Fresh install: no registry file at all is the ordinary "no services
    // yet" state — NOT a finding (only an unloadable registry is). Doctor
    // must run, exit 0, print the cloudflared check (whatever it found on
    // this machine — CI has no cloudflared, and its absence is a finding,
    // not an error), print a summary line, and run no per-service checks.
    let dir = TempDir::new().unwrap();
    let (ok, out) = run_ft(dir.path(), &["doctor"]);
    assert!(
        ok,
        "`ft doctor` must exit 0 — findings are informational, got: {out}"
    );
    assert!(
        out.contains("cloudflared"),
        "expected the cloudflared check line, got: {out}"
    );
    assert!(
        !out.contains("worker "),
        "no service checks may run without services, got: {out}"
    );
    assert!(
        out.contains("all checks passed") || out.contains("problem(s)"),
        "expected a summary line (which one depends on cloudflared), got: {out}"
    );
    // Read-only: even after running, the state tree is still empty.
    assert!(
        tree_paths(dir.path()).is_empty(),
        "doctor must create nothing, found: {:?}",
        tree_paths(dir.path())
    );
}

#[test]
fn doctor_flags_a_live_proxy_whose_upstream_port_is_dead() {
    // The motivating case end-to-end: the worker reads Running through the
    // real foreground liveness probe (the test's own pid with `foreground:
    // true` and a published URL — the same trick as the model.rs unit
    // tests), while the port it fronts has nothing listening. Doctor must
    // still exit 0 and report the 502 finding with its remediation hint.
    let dir = TempDir::new().unwrap();
    let port = dead_loopback_port();
    let body = format!(
        r#"{{
  "next_id": 2,
  "services": [
    {{
      "id": 1,
      "name": "seed-proxy",
      "kind": "proxy",
      "dir": null,
      "port": {port},
      "local_url": "http://127.0.0.1:{port}",
      "public_url": "https://x.trycloudflare.com",
      "worker_pid": {pid},
      "tunnel_pid": null,
      "created_at": "2026-07-21T00:00:00Z",
      "state_dir": "/tmp/seed-proxy-state",
      "foreground": true
    }}
  ]
}}"#,
        pid = std::process::id()
    );
    seed_registry(dir.path(), &body);

    let (ok, out) = run_ft(dir.path(), &["doctor"]);
    assert!(
        ok,
        "a finding is not a command failure — doctor exits 0, got: {out}"
    );
    assert!(
        out.contains(&format!("proxying {port} but nothing is listening")),
        "expected the dead-upstream finding naming the port, got: {out}"
    );
    assert!(
        out.contains("502"),
        "expected the 502 explanation, got: {out}"
    );
    assert!(
        out.contains(
            "hint: start the upstream server, or stop the service (`ft kill seed-proxy` — `ft \
             sanitize` cleans background dead-upstream tunnels; stop a foreground one with \
             Ctrl-C in its terminal)"
        ),
        "expected the remediation hint verbatim, got: {out}"
    );
    assert!(
        out.contains("problem(s)"),
        "the summary must count the finding, got: {out}"
    );
    // The worker itself is healthy: only its origin check fails.
    assert!(
        out.contains("worker seed-proxy: worker pid") && out.contains("fail origin seed-proxy:"),
        "expected an ok worker line and a fail origin line, got: {out}"
    );
    // Read-only: doctor seeded nothing, changed nothing.
    let after = fs::read_to_string(registry_path(dir.path())).unwrap();
    assert!(
        after.contains("seed-proxy"),
        "doctor must not mutate the registry, got: {after}"
    );
}

#[test]
fn doctor_flags_a_stale_run_service_whose_command_is_still_running() {
    // The Run orphan finding, end to end (the one doctor surface A2 could not
    // reach from its unit-only paths): a stale run entry — dead worker pid,
    // so its tunnel is gone — carrying a command_pid that IS alive (this test
    // process's own pid, probed by the doctor child as plain existence) plus
    // a run port that still answers (a real listener the test holds). That is
    // the confident "tunnel dead, command still running" signature. Doctor
    // must exit 0, flag the `command <name>` check with its verify-first
    // hint, and stay read-only.
    let dir = TempDir::new().unwrap();
    let listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind ephemeral loopback listener");
    let port = listener.local_addr().expect("local addr").port();
    let body = format!(
        r#"{{
  "next_id": 2,
  "services": [
    {{
      "id": 1,
      "name": "seed-run",
      "kind": "run",
      "dir": null,
      "port": {port},
      "local_url": "http://127.0.0.1:{port}",
      "public_url": "https://x.trycloudflare.com",
      "worker_pid": 4000000,
      "tunnel_pid": null,
      "command_pid": {pid},
      "created_at": "2026-07-21T00:00:00Z",
      "state_dir": "/tmp/seed-run-state",
      "foreground": false
    }}
  ]
}}"#,
        pid = std::process::id()
    );
    seed_registry(dir.path(), &body);

    let (ok, out) = run_ft(dir.path(), &["doctor"]);
    // The listener must outlive the run: the orphan cross-check probes it.
    drop(listener);

    assert!(
        ok,
        "a finding is not a command failure — doctor exits 0, got: {out}"
    );
    assert!(
        out.contains("command seed-run: tunnel dead, command still running"),
        "expected the orphan finding for the run command, got: {out}"
    );
    assert!(
        out.contains(&format!("pid {} is alive", std::process::id()))
            && out.contains(&format!("127.0.0.1:{port} still answers")),
        "expected the confident branch's evidence (live pid + answering port), got: {out}"
    );
    assert!(
        out.contains("stop it if it is the command") && out.contains("`ft kill seed-run`"),
        "expected the shared verify-first hint naming the kill, got: {out}"
    );
    // Read-only: doctor reports the orphan but never touches the entry.
    let after = fs::read_to_string(registry_path(dir.path())).unwrap();
    assert!(
        after.contains("seed-run"),
        "doctor must not mutate the registry, got: {after}"
    );
}

// --- `ft sanitize` (the cleanup counterpart; no cloudflared needed) ----------

#[test]
fn sanitize_on_a_missing_registry_reports_nothing_and_creates_no_state() {
    // Fresh machine: no registry file at all is the ordinary "no services"
    // state, not an error. Sanitize must exit 0 with the nothing-to-do
    // message and — like doctor, and unlike a seeded prune — must not even
    // create the state tree: nothing was judged, so no lock is ever taken.
    let dir = TempDir::new().unwrap();
    let (ok, out) = run_ft(dir.path(), &["sanitize"]);
    assert!(ok, "`ft sanitize` on a fresh machine failed: {out}");
    assert!(
        out.contains("Nothing to clean."),
        "expected the nothing-to-clean message, got: {out}"
    );
    assert!(
        tree_paths(dir.path()).is_empty(),
        "a no-op sanitize must create nothing, found: {:?}",
        tree_paths(dir.path())
    );
}

#[test]
fn sanitize_keeps_a_healthy_live_service() {
    // A foreground service reading Running through sanitize's REAL probes:
    // a decoy worker carrying the `--foreground` cmdline token plus a
    // published URL, and a REAL loopback listener bound on the fronted port
    // so the origin double-probe finds it answering. Nothing is dangling —
    // the entry must survive, the report must say there was nothing to do,
    // and the command exits 0.
    let dir = TempDir::new().unwrap();
    let worker = spawn_foreground_worker();
    let listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind ephemeral loopback listener");
    let port = listener.local_addr().expect("local addr").port();
    seed_registry(dir.path(), &foreground_proxy_json(worker.pid(), port));

    let (ok, out) = run_ft(dir.path(), &["sanitize"]);
    // The listener (and worker) must outlive the run: the probes happen
    // inside it. Dropping the DecoyWorker guard kills and reaps the decoy.
    drop(listener);
    drop(worker);

    assert!(ok, "`ft sanitize` on a healthy registry failed: {out}");
    assert!(
        out.contains("Nothing to clean."),
        "expected the nothing-to-clean message, got: {out}"
    );
    assert!(
        !out.contains("Sanitized") && !out.contains("Left"),
        "nothing may be reported removed or skipped, got: {out}"
    );
    let after = fs::read_to_string(registry_path(dir.path())).unwrap();
    assert!(
        after.contains("seed-proxy"),
        "the healthy entry must survive untouched, registry: {after}"
    );
}

#[test]
fn sanitize_reports_but_never_removes_a_foreground_zombie() {
    // The motivating zombie, in the one shape black-box tests can drive: a
    // foreground service whose decoy worker (cmdline: `--foreground`) is
    // alive and Running while its port is freshly dead. Sanitize must NEVER
    // kill or remove a foreground service — its worker is an `ft` attached
    // to the operator's terminal — so the expectation is the left-alone
    // note, the entry still on disk, and exit 0. (A live BACKGROUND zombie
    // needs a real run-worker process; the pure decision table in
    // cmd/sanitize.rs covers that arm instead.)
    let dir = TempDir::new().unwrap();
    let worker = spawn_foreground_worker();
    let port = dead_loopback_port();
    seed_registry(dir.path(), &foreground_proxy_json(worker.pid(), port));

    let (ok, out) = run_ft(dir.path(), &["sanitize"]);
    // The decoy only needs to outlive the run itself; the guard reaps it.
    drop(worker);

    assert!(ok, "a skipped foreground zombie is not a failure: {out}");
    assert!(
        out.contains("Left 1 foreground service"),
        "expected the left-alone note, got: {out}"
    );
    assert!(
        out.contains("seed-proxy"),
        "the skipped service must be named, got: {out}"
    );
    assert!(
        !out.contains("Sanitized"),
        "nothing may be reported removed, got: {out}"
    );
    let after = fs::read_to_string(registry_path(dir.path())).unwrap();
    assert!(
        after.contains("seed-proxy"),
        "a foreground zombie must never be removed, registry: {after}"
    );
}

#[test]
fn sanitize_reaps_a_stale_proxy_entry() {
    // Through the `clean` alias, to prove the alias routes end-to-end: a
    // recorded-but-dead worker pid (4_000_000 is far outside any real pid
    // namespace) makes the entry stale, and sanitize — a superset of prune —
    // removes it with its per-entry reason bullet and persists the empty
    // registry.
    let dir = TempDir::new().unwrap();
    let reg = seed_registry(
        dir.path(),
        &proxy_registry_json(4_000_000, "2026-07-21T00:00:00Z", None),
    );

    let (ok, out) = run_ft(dir.path(), &["clean"]);

    assert!(ok, "`ft clean` on a stale proxy registry failed: {out}");
    assert!(
        out.contains("Sanitized 1 service(s)"),
        "expected one reaped service, got: {out}"
    );
    assert!(
        out.contains("- seed-proxy (worker no longer running)"),
        "expected the per-entry reason bullet, got: {out}"
    );
    let after = fs::read_to_string(&reg).unwrap();
    assert!(
        !after.contains("seed-proxy"),
        "sanitize should have removed the stale entry, registry: {after}"
    );
}

#[test]
fn sanitize_keeps_a_fresh_reservation_and_reaps_an_expired_one() {
    // The pid-0 grace split, end to end: a fresh reservation (inside
    // START_GRACE — a parent may be mid reserve→spawn→record) is kept, while
    // an expired one (the parent died mid-start) is removed with the
    // abandoned-reservation reason. Classification is purely
    // created_at-vs-grace; kind plays no role.
    let dir = TempDir::new().unwrap();
    let body = format!(
        r#"{{
  "next_id": 3,
  "services": [
    {{
      "id": 1,
      "name": "proxy-fresh",
      "kind": "proxy",
      "dir": null,
      "port": 3001,
      "local_url": "http://127.0.0.1:3001",
      "public_url": null,
      "worker_pid": 0,
      "tunnel_pid": null,
      "created_at": "{fresh}",
      "state_dir": "/tmp/proxy-fresh-state",
      "foreground": false
    }},
    {{
      "id": 2,
      "name": "proxy-expired",
      "kind": "proxy",
      "dir": null,
      "port": 3002,
      "local_url": "http://127.0.0.1:3002",
      "public_url": null,
      "worker_pid": 0,
      "tunnel_pid": null,
      "created_at": "2026-07-21T00:00:00Z",
      "state_dir": "/tmp/proxy-expired-state",
      "foreground": false
    }}
  ]
}}"#,
        fresh = now_rfc3339()
    );
    let reg = seed_registry(dir.path(), &body);

    let (ok, out) = run_ft(dir.path(), &["sanitize"]);

    assert!(ok, "`ft sanitize` on the reservations failed: {out}");
    assert!(
        out.contains("Sanitized 1 service(s)") && out.contains("proxy-expired"),
        "expected exactly the expired reservation reaped, got: {out}"
    );
    assert!(
        out.contains("(worker pid was never recorded"),
        "expected the abandoned-reservation reason, got: {out}"
    );
    assert!(
        !out.contains("proxy-fresh"),
        "the fresh reservation must not be reported, got: {out}"
    );
    let after = fs::read_to_string(&reg).unwrap();
    assert!(
        after.contains("proxy-fresh") && !after.contains("proxy-expired"),
        "sanitize must keep the fresh and drop the expired reservation, registry: {after}"
    );
}

// --- `ft hook` (usage, occupied-port pre-flight, seeded fixtures; no cloudflared)
//
// Like the proxy/run sections, only paths that stop BEFORE cloudflared is
// looked up are driven here: `ft hook` is ft's own origin, so an occupied
// port fails the pre-flight ahead of that lookup, and everything past it
// would depend on whether this machine has cloudflared. The origin itself
// (recording, /__inspect HTML + JSON views, retention, body cap) is covered
// by the hook_server unit tests driving the Router directly with
// tower::oneshot.

#[test]
fn hook_help_documents_the_command() {
    let dir = TempDir::new().unwrap();
    let (ok, out) = run_ft(dir.path(), &["hook", "--help"]);
    assert!(ok, "`ft hook --help` failed: {out}");
    assert!(
        out.contains("Usage: ft hook"),
        "missing the usage line in: {out}"
    );
    assert!(out.contains("--port"), "missing --port in: {out}");
    assert!(out.contains("--name"), "missing --name in: {out}");
    assert!(
        out.contains("--foreground"),
        "missing --foreground in: {out}"
    );
    assert!(out.contains("--keep"), "missing --keep in: {out}");
    assert!(
        out.contains("/__inspect"),
        "the help must document the inspection paths in: {out}"
    );
}

#[test]
fn hook_usage_errors_leave_no_state() {
    // Every rejected invocation must fail before the state tree exists: a
    // usage error (clap value-parser ranges) means nothing was reserved,
    // spawned, or written.
    let dir = TempDir::new().unwrap();
    for (args, expected) in [
        (
            &["hook", "--port", "abc"][..],
            "invalid digit found in string",
        ),
        (&["hook", "--port", "0"][..], "0 is not in 1..=65535"),
        (
            &["hook", "--port", "70000"][..],
            "70000 is not in 1..=65535",
        ),
        (&["hook", "--keep", "0"][..], "0 is not in 1..=1000"),
        (&["hook", "--keep", "1001"][..], "1001 is not in 1..=1000"),
    ] {
        let (ok, out) = run_ft(dir.path(), args);
        assert!(
            !ok,
            "expected a failure for `ft {}`, got: {out}",
            args.join(" ")
        );
        assert!(
            out.contains(expected),
            "expected `{expected}` for `ft {}`, got: {out}",
            args.join(" ")
        );
    }
    assert!(
        tree_paths(dir.path()).is_empty(),
        "rejected hooks must leave no state, found: {:?}",
        tree_paths(dir.path())
    );
}

#[test]
fn hook_refuses_an_occupied_port_and_leaves_no_state() {
    // The hook origin is ft's OWN server, so an occupied port fails the
    // pre-flight — before cloudflared is looked up and before any state
    // exists — with a message that names the port. This holds on every
    // machine regardless of cloudflared, because the check precedes that
    // lookup entirely (the inverse of proxy's dead-upstream pre-flight).
    let dir = TempDir::new().unwrap();
    let listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind ephemeral loopback listener");
    let port = listener.local_addr().expect("local addr").port();
    let port_arg = port.to_string();

    let (ok, out) = run_ft(dir.path(), &["hook", "--port", &port_arg]);
    // The listener must outlive the run: the probe happens inside it.
    drop(listener);

    assert!(!ok, "an occupied port must fail `ft hook`, got: {out}");
    assert!(
        out.contains(&format!("port {port} is already in use")),
        "expected the occupied-port error naming the port, got: {out}"
    );
    assert!(
        tree_paths(dir.path()).is_empty(),
        "a refused hook must leave no state, found: {:?}",
        tree_paths(dir.path())
    );
}

#[test]
fn hook_fixture_renders_in_ls_and_detail() {
    // A seeded `"kind": "hook"` entry (the on-disk shape `ft hook` reserves)
    // must render through the same lifecycle commands as any other kind:
    // kind-agnostic in `ls`, kind-aware in `detail` — Mode names the hook,
    // there is no Directory/Upstream row (a hook serves no directory and
    // fronts no operator upstream), and the Logs list carries the hook's
    // request store (requests.json) but no server.log (the hook origin's
    // record IS requests.json — there is no traced static server).
    let dir = TempDir::new().unwrap();
    let body = r#"{
  "next_id": 3,
  "services": [
    {
      "id": 1,
      "name": "seed-hook",
      "kind": "hook",
      "dir": null,
      "port": 9000,
      "local_url": "http://127.0.0.1:9000",
      "public_url": "https://x.trycloudflare.com",
      "worker_pid": 4000000,
      "tunnel_pid": null,
      "created_at": "2026-07-21T00:00:00Z",
      "state_dir": "/tmp/seed-hook-state",
      "foreground": false
    }
  ]
}"#;
    seed_registry(dir.path(), body);

    let (ok_ls, out_ls) = run_ft(dir.path(), &["ls"]);
    assert!(ok_ls, "`ft ls` on a hook registry failed: {out_ls}");
    assert!(
        out_ls.contains("seed-hook") && out_ls.contains("stale") && out_ls.contains("9000"),
        "expected the hook entry listed with its recorded-but-dead worker status \
         and port, got: {out_ls}"
    );

    let (ok, out) = run_ft(dir.path(), &["detail", "seed-hook"]);
    assert!(ok, "`ft detail seed-hook` failed: {out}");
    assert!(
        out.contains("Mode:         hook"),
        "expected the hook Mode row, got: {out}"
    );
    assert!(
        !out.contains("Directory:"),
        "a hook entry must not render a Directory row: {out}"
    );
    assert!(
        !out.contains("Upstream:"),
        "a hook entry is not a proxy and must not render an Upstream row: {out}"
    );
    assert!(
        out.contains("requests.json"),
        "expected the hook request store listed, got: {out}"
    );
    assert!(
        out.contains("worker.log") && out.contains("tunnel.log"),
        "expected worker/tunnel logs listed, got: {out}"
    );
    assert!(
        !out.contains("server.log"),
        "a hook entry must not list server.log: {out}"
    );
    assert!(
        out.contains("https://x.trycloudflare.com"),
        "expected the seeded public url, got: {out}"
    );

    // kill is kind-agnostic (it targets pids): a recorded-but-dead worker pid
    // makes the entry stale, and killing it reports the stale removal and
    // persists the emptied registry.
    let reg = registry_path(dir.path());
    let (ok_kill, out_kill) = run_ft(dir.path(), &["kill", "seed-hook"]);
    assert!(ok_kill, "`ft kill seed-hook` failed: {out_kill}");
    assert!(
        out_kill.contains("Removed stale service seed-hook."),
        "expected the stale-removal message, got: {out_kill}"
    );
    let after = fs::read_to_string(&reg).unwrap();
    assert!(
        !after.contains("seed-hook"),
        "kill should have removed the hook entry, but registry is: {after}"
    );
}

// --- static-origin flags on `ft <dir>` (A5): CLI surface, never-on-proxy,
// --- registry persistence + detail rendering. No cloudflared: the origin
// --- behaviour itself (SPA fallback, CORS headers, 401 token gate) is covered
// --- by the static_server unit tests driving `router_with` directly; these
// --- binary-level tests pin the plumbing around it.

#[test]
fn start_help_documents_the_static_origin_flags() {
    // The implicit START's help is the flags' only documentation surface at
    // the CLI level (README is A6's sweep): all three must be listed.
    let dir = TempDir::new().unwrap();
    let (ok, out) = run_ft(dir.path(), &["--help"]);
    assert!(ok, "`ft --help` failed: {out}");
    assert!(out.contains("--spa"), "missing --spa in: {out}");
    assert!(out.contains("--cors"), "missing --cors in: {out}");
    assert!(out.contains("--token"), "missing --token in: {out}");
}

#[test]
fn proxy_takes_no_static_origin_flags() {
    // NEVER-ON-PROXY (hard exclusion, binary level): the static-origin flags
    // exist only on the implicit START, so `ft proxy` with any of them is a
    // clap usage error — before any preflight, state, or cloudflared lookup —
    // and `ft proxy --help` does not even advertise them. A proxy fronts the
    // operator's own server; ft-owned origin policy must be unparsable there,
    // not silently ignored.
    let dir = TempDir::new().unwrap();
    for args in [
        vec!["proxy", "--help"],
        vec!["proxy", "3000", "--spa"],
        vec!["proxy", "3000", "--cors"],
        vec!["proxy", "3000", "--token", "sekrit"],
    ] {
        let (ok, out) = run_ft(dir.path(), &args);
        if args == vec!["proxy", "--help"] {
            assert!(ok, "`ft proxy --help` failed: {out}");
            assert!(
                !out.contains("--spa") && !out.contains("--cors") && !out.contains("--token"),
                "proxy help must not advertise static-origin flags: {out}"
            );
        } else {
            assert!(
                !ok,
                "expected a usage error for `ft {}`, got: {out}",
                args.join(" ")
            );
            assert!(
                out.contains("unexpected argument"),
                "expected a clap unknown-argument error for `ft {}`, got: {out}",
                args.join(" ")
            );
        }
    }
    assert!(
        tree_paths(dir.path()).is_empty(),
        "rejected proxy invocations must leave no state, found: {:?}",
        tree_paths(dir.path())
    );
}

#[test]
fn static_flags_fixture_renders_in_detail() {
    // A seeded static entry carrying `static_flags` (the on-disk shape `ft
    // <dir> --spa --cors --token s` reserves) must render the flags in `ft
    // detail` — SPA/CORS always (on/off) and the token only when configured —
    // while a plain static entry in the same registry keeps the historical
    // shape (SPA/CORS off, no Token row).
    let dir = TempDir::new().unwrap();
    let body = r#"{
  "next_id": 3,
  "services": [
    {
      "id": 1,
      "name": "flagged-svc",
      "kind": "static",
      "dir": "/tmp/seed-dir",
      "port": 8080,
      "local_url": "http://127.0.0.1:8080",
      "public_url": "https://x.trycloudflare.com",
      "worker_pid": 4000000,
      "tunnel_pid": null,
      "static_flags": { "spa": true, "cors": true, "token": "hunter2" },
      "created_at": "2026-07-21T00:00:00Z",
      "state_dir": "/tmp/seed-state",
      "foreground": false
    },
    {
      "id": 2,
      "name": "plain-svc",
      "kind": "static",
      "dir": "/tmp/plain-dir",
      "port": 8081,
      "local_url": "http://127.0.0.1:8081",
      "public_url": null,
      "worker_pid": 4000000,
      "tunnel_pid": null,
      "created_at": "2026-07-21T00:00:00Z",
      "state_dir": "/tmp/plain-state",
      "foreground": false
    }
  ]
}"#;
    seed_registry(dir.path(), body);

    let (ok, out) = run_ft(dir.path(), &["detail", "flagged-svc"]);
    assert!(ok, "`ft detail flagged-svc` failed: {out}");
    assert!(
        out.contains("SPA:          on"),
        "expected the SPA row on, got: {out}"
    );
    assert!(
        out.contains("CORS:         on"),
        "expected the CORS row on, got: {out}"
    );
    assert!(
        out.contains("Token:        hunter2"),
        "expected the configured token row, got: {out}"
    );

    let (ok_plain, out_plain) = run_ft(dir.path(), &["detail", "plain-svc"]);
    assert!(ok_plain, "`ft detail plain-svc` failed: {out_plain}");
    assert!(
        out_plain.contains("SPA:          off") && out_plain.contains("CORS:         off"),
        "a plain static entry must render both flags off, got: {out_plain}"
    );
    assert!(
        !out_plain.contains("Token:"),
        "a plain static entry must not render a Token row: {out_plain}"
    );
}

#[test]
fn static_flags_persist_through_a_full_registry_rewrite() {
    // The re-apply story end to end at the registry layer: the detached worker
    // re-applies the flags by reading them off the entry, so they must survive
    // a real load → update → save cycle through the binary. Prune reaps the
    // EXPIRED pid-0 reservation but keeps the FRESH one (M1 grace) — and the
    // kept entry must come out of the rewrite with its static_flags intact,
    // byte-identical in meaning, in the compact JSON the save path writes.
    let dir = TempDir::new().unwrap();
    let body = format!(
        r#"{{
  "next_id": 3,
  "services": [
    {{
      "id": 1,
      "name": "flagged-fresh",
      "kind": "static",
      "dir": "/tmp/seed-dir",
      "port": 8080,
      "local_url": "http://127.0.0.1:8080",
      "public_url": null,
      "worker_pid": 0,
      "tunnel_pid": null,
      "static_flags": {{ "spa": true, "cors": true, "token": "hunter2" }},
      "created_at": "{fresh}",
      "state_dir": "/tmp/seed-state",
      "foreground": false
    }},
    {{
      "id": 2,
      "name": "expired-reservation",
      "kind": "static",
      "dir": "/tmp/old-dir",
      "port": 8081,
      "local_url": "http://127.0.0.1:8081",
      "public_url": null,
      "worker_pid": 0,
      "tunnel_pid": null,
      "created_at": "2026-07-21T00:00:00Z",
      "state_dir": "/tmp/old-state",
      "foreground": false
    }}
  ]
}}"#,
        fresh = now_rfc3339()
    );
    let reg = seed_registry(dir.path(), &body);

    let (ok, out) = run_ft(dir.path(), &["prune"]);
    assert!(ok, "`ft prune` failed: {out}");
    assert!(
        out.contains("Pruned 1 stale service") && out.contains("expired-reservation"),
        "expected exactly the expired reservation reaped, got: {out}"
    );

    // The rewrite kept the flagged entry WITH its flags (so a re-started or
    // inspected service still re-applies them), through the real save path.
    let after = fs::read_to_string(&reg).unwrap();
    assert!(
        after.contains("flagged-fresh")
            && after.contains("static_flags")
            && after.contains("\"spa\":true")
            && after.contains("\"cors\":true")
            && after.contains("\"token\":\"hunter2\""),
        "the flagged entry must survive the rewrite with its flags, registry: {after}"
    );
    assert!(
        !after.contains("expired-reservation"),
        "the expired reservation must be gone, registry: {after}"
    );
}
