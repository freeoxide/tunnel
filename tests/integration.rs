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

#![cfg(unix)] // proc::pid_alive uses a Unix-only cmdline identity probe.

use std::fs;
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
