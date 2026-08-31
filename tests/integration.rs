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
