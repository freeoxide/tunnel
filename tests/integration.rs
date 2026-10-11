//! End-to-end black-box tests for the `ft` binary via `CARGO_BIN_EXE_ft`,
//! each pinned to a private `XDG_STATE_HOME` tempdir; cloudflared-bound
//! paths are out of scope (origin behaviour lives in the server unit tests).

#![cfg(unix)] // proc::pid_alive uses a Unix-only cmdline identity probe.

use std::fs;
use std::io::Write;
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use tempfile::TempDir;

fn ft_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ft"))
}

fn registry_path(xdg_root: &std::path::Path) -> PathBuf {
    xdg_root
        .join("freeoxide")
        .join("tunnel")
        .join("registry.json")
}

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

/// The pid must come from [`spawn_foreground_worker`]: sanitize probes foreground
/// liveness via the `--foreground` cmdline token, so a bare own-pid fixture reads stale.
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

/// Dropping the guard kills and reaps the decoy shell; its in-flight `sleep 30`
/// child can orphan for up to 30 s (killing the shell does not reach children).
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
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Readiness barrier: the cmdline the probe reads can lag the fork (platform
/// quirk); losing that race makes the probe correctly read the decoy as stale.
fn wait_for_foreground_token(pid: u32) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut last_seen = String::from("`ps` has not completed a poll yet");
    while std::time::Instant::now() < deadline {
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

/// A decoy whose cmdline carries `--foreground` (the identity probe's needle);
/// the guard reaps it on drop. The `-c` body must stay an endless LOOP — shells
/// tail-exec a final `-c` command, replacing argv and dropping the token.
fn spawn_foreground_worker() -> DecoyWorker {
    // Build the guard BEFORE the barrier: if the barrier panics, unwinding
    // reaps the decoy — a bare `Child`'s Drop is a no-op and would leak the loop.
    let worker = DecoyWorker {
        child: Command::new("sh")
            .arg("-c")
            .arg("while :; do sleep 30; done")
            .arg("--foreground")
            .spawn()
            .expect("spawning decoy foreground worker"),
    };
    wait_for_foreground_token(worker.pid());
    worker
}

fn seed_registry(xdg_root: &std::path::Path, body: &str) -> PathBuf {
    let path = registry_path(xdg_root);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, body).unwrap();
    path
}

fn run_ft(xdg_root: &std::path::Path, args: &[&str]) -> (bool, String) {
    let output = Command::new(ft_bin())
        .args(args)
        // Child-only env: mutating the test process's env would be `unsafe`
        // in edition 2024.
        .env("XDG_STATE_HOME", xdg_root)
        // Hermeticity: a stray RUST_LOG would pollute the asserted-on stdout.
        .env("RUST_LOG", "")
        .output()
        .expect("spawning `ft` binary");
    let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&output.stderr));
    (output.status.success(), combined)
}

fn run_ft_with_env(
    xdg_root: &std::path::Path,
    args: &[&str],
    env: &[(&str, &str)],
) -> (bool, String) {
    let mut cmd = Command::new(ft_bin());
    cmd.args(args)
        .env("XDG_STATE_HOME", xdg_root)
        .env("RUST_LOG", "");
    for (k, v) in env {
        cmd.env(k, v);
    }
    let output = cmd.output().expect("spawning `ft` binary");
    let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&output.stderr));
    (output.status.success(), combined)
}

/// Bind an ephemeral listener, drop it. Another process could re-grab the port
/// before `ft` probes it — accepted risk.
fn dead_loopback_port() -> u16 {
    let listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind ephemeral loopback listener");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    port
}

/// Close the server side first (listener, then accepted stream, while the
/// client is open): the active close leaves the port in FIN_WAIT/TIME_WAIT.
fn time_wait_loopback_port() -> u16 {
    let listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind ephemeral loopback listener");
    let port = listener.local_addr().expect("local addr").port();
    let client = std::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port)).expect("connect");
    let accepted = listener.accept().expect("accept").0;
    drop(listener);
    drop(accepted);
    drop(client);
    port
}

const PUBLISHING_CLOUDFLARED: &str =
    "#!/bin/sh\necho https://fake-e2e-words.trycloudflare.com\nexec sleep 300\n";
const DYING_CLOUDFLARED: &str = "#!/bin/sh\necho fake cloudflared failed\nexit 1\n";
const DELAYED_PUBLISHING_CLOUDFLARED: &str =
    "#!/bin/sh\nsleep 4\necho https://fake-e2e-words.trycloudflare.com\nexec sleep 300\n";

fn install_fake_cloudflared(bin_dir: &std::path::Path, script: &str) {
    fs::create_dir_all(bin_dir).unwrap();
    let fake = bin_dir.join("cloudflared");
    fs::write(&fake, script).unwrap();
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(bin_dir, fs::Permissions::from_mode(0o700)).unwrap();
}

fn path_env_prepending(bin_dir: &std::path::Path) -> String {
    format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    )
}

fn process_alive_zombie_aware(pid: u32) -> bool {
    #[cfg(target_os = "linux")]
    {
        let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
            return false;
        };
        match stat
            .rfind(')')
            .and_then(|close| stat[close + 1..].trim_start().chars().next())
        {
            None | Some('Z') => false,
            Some(_) => true,
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        Command::new("sh")
            .arg("-c")
            .arg(format!("kill -0 {pid}"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }
}

fn wait_for_process_death(pid: u32) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        if !process_alive_zombie_aware(pid) {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    !process_alive_zombie_aware(pid)
}

fn wait_for_registry_entry(xdg_root: &std::path::Path, needle: &str) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        let seeded = fs::read_to_string(registry_path(xdg_root))
            .map(|body| body.contains(needle))
            .unwrap_or(false);
        if seeded {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    false
}

fn wait_for_recorded_worker_pid(xdg_root: &std::path::Path, name: &str) -> bool {
    let needle = format!("\"{name}\"");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        let recorded = fs::read_to_string(registry_path(xdg_root))
            .ok()
            .and_then(|body| {
                body.find(&needle)
                    .and_then(|at| json_u64_field(&body[at..], "worker_pid"))
            })
            .is_some_and(|pid| pid > 0);
        if recorded {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    false
}

fn wait_for_port_accept(port: u16) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while std::time::Instant::now() < deadline {
        if TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_ok() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    false
}

fn wait_for_port_refusal(port: u16) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_err() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_err()
}

fn json_u64_field(body: &str, field: &str) -> Option<u64> {
    let needle = format!("\"{field}\":");
    let rest = &body[body.find(&needle)? + needle.len()..];
    let digits = &rest[..rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len())];
    digits.parse().ok()
}

fn json_str_field(body: &str, field: &str) -> Option<String> {
    let needle = format!("\"{field}\":\"");
    let start = body.find(&needle)? + needle.len();
    let end = start + body[start..].find('"')?;
    Some(body[start..end].to_string())
}

/// Files AND directories, recursively: `StateDir::ensure` creates an empty
/// root + `services/`, so a files-only walk could not pin "zero state".
fn tree_paths(root: &std::path::Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
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
    // 4_000_000 is far outside any real pid namespace, so the worker reads dead.
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

    let after = fs::read_to_string(&reg).unwrap();
    assert!(
        !after.contains("seed-svc"),
        "prune should have removed the stale entry, but registry is still: {after}"
    );

    let (ok2, out2) = run_ft(dir.path(), &["prune"]);
    assert!(ok2, "second `ft prune` failed: {out2}");
    assert!(
        out2.contains("No stale services"),
        "expected idempotent empty prune, got: {out2}"
    );
}

// Linux/macOS only: the "stale" expectation hinges on pid_alive's cmdline
// needle; other Unix falls back to signal-0 and reads the live child as alive.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn ls_reports_status_through_real_proc_probe() {
    // The live `sleep` child's cmdline lacks the `run-worker` needle, so the
    // cmdline-aware probe reads it as foreign (PID-reused) -> "stale".
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

    let (ok_by_name, out_by_name) = run_ft(dir.path(), &["detail", "seed-svc"]);
    assert!(ok_by_name, "`ft detail seed-svc` failed: {out_by_name}");
    assert!(
        out_by_name.contains("seed-svc"),
        "name target did not resolve to the entry: {out_by_name}"
    );
}

#[test]
fn proxy_dead_upstream_fails_friendly_and_leaves_no_state() {
    let dir = TempDir::new().unwrap();
    let port = dead_loopback_port();
    let port_arg = port.to_string();

    let (ok, out) = run_ft(dir.path(), &["proxy", &port_arg]);
    assert!(!ok, "a dead upstream must fail `ft proxy`, got: {out}");
    assert!(
        out.contains(&format!("nothing is listening on 127.0.0.1:{port}")),
        "expected the friendly pre-flight error naming the port, got: {out}"
    );

    let (ok_fg, out_fg) = run_ft(dir.path(), &["proxy", &port_arg, "--foreground"]);
    assert!(
        !ok_fg,
        "foreground pre-flight must also fail, got: {out_fg}"
    );
    assert!(
        out_fg.contains(&format!("nothing is listening on 127.0.0.1:{port}")),
        "expected the same friendly error in foreground mode, got: {out_fg}"
    );

    assert!(
        tree_paths(dir.path()).is_empty(),
        "a failed proxy start must leave no state, found: {:?}",
        tree_paths(dir.path())
    );

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
fn kill_refuses_a_fresh_proxy_reservation_within_the_start_grace() {
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
    // Empty PATH stops the run at the cloudflared lookup (right after the
    // port pre-flight); with cloudflared installed it would spawn a real worker.
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
    assert!(
        out.contains("[env: FT_TOKEN]"),
        "missing the FT_TOKEN env pin in: {out}"
    );
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
    let dir = TempDir::new().unwrap();
    let missing = dir.path().join("does-not-exist");
    let missing = missing.to_string_lossy().into_owned();
    // A sibling tempdir, not an ancestor of ft's state root — an ancestor
    // would (correctly) be refused as sensitive.
    let neutral = TempDir::new().unwrap();
    let neutral_arg = neutral.path().to_string_lossy().into_owned();
    for (args, expected) in [
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
        (&["drop", &missing][..], "does not exist"),
        (&["drop", "/"][..], "sensitive directory"),
        (
            &["drop", &neutral_arg, "--token", ""][..],
            "--token must be a non-empty secret",
        ),
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
    // SECURITY: a bucket on ft's own state tree would expose registry.json,
    // logs, and token files via unauthenticated GETs — refuse every overlap.
    let dir = TempDir::new().unwrap();
    let state_root = dir.path().join("freeoxide").join("tunnel");
    let services = state_root.join("services");
    let ancestor = dir.path().join("freeoxide");
    fs::create_dir_all(&services).unwrap();

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
    let dir = TempDir::new().unwrap();
    // state_dir anchors in the tempdir: `ft detail` reads the token file from it.
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

#[test]
fn doctor_on_a_missing_registry_exits_zero_with_no_service_checks() {
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
    assert!(
        tree_paths(dir.path()).is_empty(),
        "doctor must create nothing, found: {:?}",
        tree_paths(dir.path())
    );
}

#[test]
fn doctor_flags_a_live_proxy_whose_upstream_port_is_dead() {
    // Doctor's worker check is plain existence, so the test's own pid reads
    // Running here — unlike sanitize's `--foreground` cmdline probe.
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
    assert!(
        out.contains("worker seed-proxy: worker pid") && out.contains("fail origin seed-proxy:"),
        "expected an ok worker line and a fail origin line, got: {out}"
    );
    let after = fs::read_to_string(registry_path(dir.path())).unwrap();
    assert!(
        after.contains("seed-proxy"),
        "doctor must not mutate the registry, got: {after}"
    );
}

#[test]
fn doctor_flags_a_stale_run_service_whose_command_is_still_running() {
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
    let after = fs::read_to_string(registry_path(dir.path())).unwrap();
    assert!(
        after.contains("seed-run"),
        "doctor must not mutate the registry, got: {after}"
    );
}

#[test]
fn sanitize_on_a_missing_registry_reports_nothing_and_creates_no_state() {
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
    let dir = TempDir::new().unwrap();
    let worker = spawn_foreground_worker();
    let listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind ephemeral loopback listener");
    let port = listener.local_addr().expect("local addr").port();
    seed_registry(dir.path(), &foreground_proxy_json(worker.pid(), port));

    let (ok, out) = run_ft(dir.path(), &["sanitize"]);
    // The listener (and worker) must outlive the run: the probes happen inside it.
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
    let dir = TempDir::new().unwrap();
    let worker = spawn_foreground_worker();
    let port = dead_loopback_port();
    seed_registry(dir.path(), &foreground_proxy_json(worker.pid(), port));

    let (ok, out) = run_ft(dir.path(), &["sanitize"]);
    // The decoy must outlive the run: the liveness probe reads its cmdline
    // inside it.
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

#[test]
fn start_help_documents_the_static_origin_flags() {
    let dir = TempDir::new().unwrap();
    let (ok, out) = run_ft(dir.path(), &["--help"]);
    assert!(ok, "`ft --help` failed: {out}");
    assert!(out.contains("--spa"), "missing --spa in: {out}");
    assert!(out.contains("--cors"), "missing --cors in: {out}");
    assert!(out.contains("--token"), "missing --token in: {out}");
    assert!(
        out.contains("[env: FT_TOKEN]"),
        "missing the FT_TOKEN env pin in: {out}"
    );
}

#[test]
fn token_flags_read_the_ft_token_env() {
    let dir = TempDir::new().unwrap();
    let site = dir.path().join("site");
    fs::create_dir_all(&site).unwrap();
    let inbox = dir.path().join("inbox");
    fs::create_dir_all(&inbox).unwrap();
    let site = site.to_string_lossy().into_owned();
    let inbox = inbox.to_string_lossy().into_owned();

    let (ok, out) = run_ft_with_env(dir.path(), &[&site], &[("FT_TOKEN", "   ")]);
    assert!(
        !ok,
        "a whitespace-only FT_TOKEN must fail the static start: {out}"
    );
    assert!(
        out.contains("--token must be a non-empty secret"),
        "the static origin must surface the env-fed token refusal, got: {out}"
    );

    let (ok, out) = run_ft_with_env(dir.path(), &["drop", &inbox], &[("FT_TOKEN", "   ")]);
    assert!(
        !ok,
        "a whitespace-only FT_TOKEN must fail the drop start: {out}"
    );
    assert!(
        out.contains("--token must be a non-empty secret"),
        "the drop origin must surface the env-fed token refusal, got: {out}"
    );

    // argv beats env (clap precedence): the whitespace-only --token wins over
    // a valid FT_TOKEN.
    for args in [
        vec![&site, "--token", "  "],
        vec!["drop", &inbox, "--token", "  "],
    ] {
        let (ok, out) = run_ft_with_env(dir.path(), &args, &[("FT_TOKEN", "a-valid-env-secret")]);
        assert!(
            !ok,
            "the argv --token must take precedence over FT_TOKEN for `ft {}`: {out}",
            args.join(" ")
        );
        assert!(
            out.contains("--token must be a non-empty secret"),
            "expected the argv value (not the env one) to be checked for `ft {}`, got: {out}",
            args.join(" ")
        );
    }
}

#[test]
fn printing_commands_piped_to_head_exit_quietly() {
    // Rust ignores SIGPIPE, so `ft logs | head` used to panic with
    // "Broken pipe"; printing commands restore the default disposition.
    let dir = TempDir::new().unwrap();
    seed_registry(
        dir.path(),
        &registry_json(4000000, false, Some("https://x.trycloudflare.com")),
    );
    // Logs exceed the 64 KiB pipe buffer so writes continue past `head`
    // exiting — the broken pipe is actually hit.
    let svc = dir.path().join("freeoxide/tunnel/services/seed-svc");
    fs::create_dir_all(&svc).unwrap();
    let fat_line = format!("{}\n", "x".repeat(2048));
    for log in ["tunnel.log", "worker.log"] {
        let mut body = String::new();
        while body.len() < 96 * 1024 {
            body.push_str(&fat_line);
        }
        fs::write(svc.join(log), body).unwrap();
    }
    let out = Command::new("sh")
        .arg("-c")
        .arg("\"$1\" logs seed-svc | head -1")
        .arg("ft")
        .arg(ft_bin())
        .env("XDG_STATE_HOME", dir.path())
        .env("RUST_LOG", "")
        .output()
        .expect("spawning the piped ft command");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("panicked") && !stderr.contains("Broken pipe"),
        "a printing command piped to head must not panic, stderr: {stderr}"
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("--- tunnel ---"),
        "head should have received the first line, stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn proxy_takes_no_static_origin_flags() {
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

#[test]
fn start_fails_fast_when_cloudflared_dies_first_and_publishes_when_the_url_lands() {
    let dir = TempDir::new().unwrap();
    let site_a = dir.path().join("site-a");
    let site_b = dir.path().join("site-b");
    fs::create_dir_all(&site_a).unwrap();
    fs::create_dir_all(&site_b).unwrap();
    let bin_dir = dir.path().join("bin");
    install_fake_cloudflared(&bin_dir, DYING_CLOUDFLARED);
    let path_env = path_env_prepending(&bin_dir);
    let site_a_arg = site_a.to_string_lossy().into_owned();

    let fail_started = std::time::Instant::now();
    let (ok_fail, out_fail) = run_ft_with_env(dir.path(), &[&site_a_arg], &[("PATH", &path_env)]);
    let fail_elapsed = fail_started.elapsed();
    assert!(
        !ok_fail,
        "a cloudflared dying before the URL must fail the start, got: {out_fail}"
    );
    assert!(
        out_fail.contains("exited before the tunnel came up"),
        "expected the fail-fast message, got: {out_fail}"
    );
    assert!(
        out_fail.contains("fake cloudflared failed"),
        "expected the fake's last log line surfaced as the inline reason, got: {out_fail}"
    );
    assert!(
        fail_elapsed < std::time::Duration::from_secs(10),
        "the dead-worker failure must be fail-fast, not a poll timeout, took {fail_elapsed:?}"
    );
    let after_fail = fs::read_to_string(registry_path(dir.path())).unwrap_or_default();
    assert!(
        !after_fail.contains("site-a"),
        "the failed start must tear its reservation down, registry: {after_fail}"
    );

    install_fake_cloudflared(&bin_dir, DELAYED_PUBLISHING_CLOUDFLARED);
    seed_registry(dir.path(), &registry_json(4_000_000, false, None));
    let site_b_arg = site_b.to_string_lossy().into_owned();
    let start_child = Command::new(ft_bin())
        .arg(&site_b_arg)
        .env("XDG_STATE_HOME", dir.path())
        .env("RUST_LOG", "")
        .env("PATH", &path_env)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawning the delayed start");
    assert!(
        wait_for_recorded_worker_pid(dir.path(), "site-b"),
        "the start must reserve its entry and record the worker pid"
    );
    let (ok_prune, out_prune) = run_ft(dir.path(), &["prune"]);
    let start_output = start_child
        .wait_with_output()
        .expect("waiting for the delayed start");
    let ok_start = start_output.status.success();
    let mut out_start = String::from_utf8_lossy(&start_output.stdout).into_owned();
    out_start.push_str(&String::from_utf8_lossy(&start_output.stderr));
    let registry_at_start = fs::read_to_string(registry_path(dir.path())).unwrap_or_default();
    let worker_pid = json_u64_field(&registry_at_start, "worker_pid").unwrap_or(0);
    let worker_live_at_start =
        process_alive_zombie_aware(u32::try_from(worker_pid).unwrap_or(u32::MAX));
    let (ok_kill, out_kill) = run_ft(dir.path(), &["kill", "site-b"]);

    assert!(
        ok_prune && out_prune.contains("Pruned 1 stale service"),
        "a concurrent registry rewrite (prune) must not disturb the start, got: {out_prune}"
    );
    assert!(
        ok_start,
        "a publishing cloudflared must start the service, got: {out_start}"
    );
    assert!(
        out_start.contains("Started site-b"),
        "expected the service name line, got: {out_start}"
    );
    assert!(
        out_start.contains("Public:  https://fake-e2e-words.trycloudflare.com"),
        "expected the discovered public URL in the start output, got: {out_start}"
    );
    assert!(
        registry_at_start.contains("\"kind\":\"static\"")
            && registry_at_start.contains("https://fake-e2e-words.trycloudflare.com"),
        "expected the entry with its public URL, registry: {registry_at_start}"
    );
    assert!(
        worker_pid > 1,
        "the entry must record a real worker pid, registry: {registry_at_start}"
    );
    assert!(
        worker_live_at_start,
        "the recorded worker pid {worker_pid} must belong to a live process at start time"
    );
    assert!(ok_kill, "`ft kill site-b` failed: {out_kill}");
    let after_kill = fs::read_to_string(registry_path(dir.path())).unwrap();
    assert!(
        after_kill.contains("\"services\":[]"),
        "kill must empty the registry, got: {after_kill}"
    );
    assert!(
        wait_for_process_death(u32::try_from(worker_pid).unwrap_or(u32::MAX)),
        "worker pid {worker_pid} must be dead after `ft kill`"
    );
}

#[test]
fn run_publishes_the_tunnel_once_the_origin_accepts_and_kill_stops_the_whole_tree() {
    let dir = TempDir::new().unwrap();
    let bin_dir = dir.path().join("bin");
    seed_registry(dir.path(), &registry_json(4_000_000, false, None));
    install_fake_cloudflared(&bin_dir, DELAYED_PUBLISHING_CLOUDFLARED);
    let path_env = path_env_prepending(&bin_dir);
    let port = dead_loopback_port();
    let port_arg = port.to_string();

    let run_child = Command::new(ft_bin())
        .args(["run", "--port", &port_arg, "--", "sleep", "30"])
        .env("XDG_STATE_HOME", dir.path())
        .env("RUST_LOG", "")
        .env("PATH", &path_env)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawning the delayed run");
    assert!(
        wait_for_registry_entry(dir.path(), "\"kind\":\"run\""),
        "the run must reserve its entry"
    );
    let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).expect("bind the origin port");
    assert!(
        wait_for_port_accept(port),
        "the origin must be accepting before the URL lands"
    );
    let (ok_prune, out_prune) = run_ft(dir.path(), &["prune"]);
    let run_output = run_child
        .wait_with_output()
        .expect("waiting for the delayed run");
    let ok = run_output.status.success();
    let mut out = String::from_utf8_lossy(&run_output.stdout).into_owned();
    out.push_str(&String::from_utf8_lossy(&run_output.stderr));
    let registry_at_start = fs::read_to_string(registry_path(dir.path())).unwrap_or_default();
    let worker_pid = json_u64_field(&registry_at_start, "worker_pid").unwrap_or(0);
    let command_pid = json_u64_field(&registry_at_start, "command_pid").unwrap_or(0);
    let tunnel_pid = json_u64_field(&registry_at_start, "tunnel_pid").unwrap_or(0);
    let name = json_str_field(&registry_at_start, "name").unwrap_or_default();
    let worker_live_at_start =
        process_alive_zombie_aware(u32::try_from(worker_pid).unwrap_or(u32::MAX));
    let (ok_kill, out_kill) = run_ft(dir.path(), &["kill", &name]);

    assert!(
        ok_prune && out_prune.contains("Pruned 1 stale service"),
        "a concurrent registry rewrite (prune) must not disturb the run, got: {out_prune}"
    );
    assert!(
        ok,
        "the run must succeed once the origin accepts, got: {out}"
    );
    assert!(
        out.contains("https://fake-e2e-words.trycloudflare.com"),
        "expected the fake tunnel URL in the run output, got: {out}"
    );
    assert!(
        registry_at_start.contains("\"kind\":\"run\"")
            && registry_at_start.contains("https://fake-e2e-words.trycloudflare.com"),
        "expected a run-kind entry with its public URL, registry: {registry_at_start}"
    );
    assert!(
        worker_pid > 1,
        "the entry must record the worker pid, registry: {registry_at_start}"
    );
    assert!(
        worker_live_at_start,
        "the recorded worker pid {worker_pid} must belong to a live process at start time"
    );
    assert!(
        command_pid > 0,
        "the entry must record the spawned command pid, registry: {registry_at_start}"
    );
    assert!(
        tunnel_pid > 0,
        "the entry must record the tunnel pid, registry: {registry_at_start}"
    );
    assert!(ok_kill, "`ft kill {name}` failed: {out_kill}");
    let after_kill = fs::read_to_string(registry_path(dir.path())).unwrap();
    assert!(
        after_kill.contains("\"services\":[]"),
        "kill must empty the registry, got: {after_kill}"
    );
    assert!(
        wait_for_process_death(u32::try_from(worker_pid).unwrap_or(u32::MAX)),
        "worker pid {worker_pid} must be dead after `ft kill`"
    );
    drop(origin);
    assert!(
        wait_for_port_refusal(port),
        "the command's origin port must stop accepting after `ft kill`"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn start_answering_no_to_the_sensitive_prompt_aborts_without_publishing() {
    let dir = TempDir::new().unwrap();
    let bin_dir = dir.path().join("bin");
    install_fake_cloudflared(&bin_dir, PUBLISHING_CLOUDFLARED);
    let path_env = path_env_prepending(&bin_dir);
    let home = dir.path().join("home");
    fs::create_dir_all(&home).unwrap();
    let ft_arg = ft_bin().to_string_lossy().into_owned();
    let home_arg = home.to_string_lossy().into_owned();

    let mut script = Command::new("script");
    if cfg!(target_os = "macos") {
        script.args(["-q", "/dev/null"]).arg(&ft_arg).arg(&home_arg);
    } else {
        script
            .arg("-qec")
            .arg(format!("'{ft_arg}' '{home_arg}'"))
            .arg("/dev/null");
    }
    let mut child = script
        .env("HOME", &home)
        .env("XDG_STATE_HOME", dir.path())
        .env("RUST_LOG", "")
        .env("PATH", &path_env)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawning the pty session");
    let mut stdin = child.stdin.take().expect("the pty session's stdin");
    let _ = stdin.write_all(b"n\n");
    drop(stdin);
    let output = child
        .wait_with_output()
        .expect("waiting for the pty session");
    let mut pty_out = String::from_utf8_lossy(&output.stdout).into_owned();
    pty_out.push_str(&String::from_utf8_lossy(&output.stderr));

    let seeded = fs::read_to_string(registry_path(dir.path())).unwrap_or_default();
    if let Some(name) = json_str_field(&seeded, "name") {
        let _ = run_ft(dir.path(), &["kill", &name]);
    }

    assert!(
        !output.status.success(),
        "answering n to the sensitive prompt must abort the start, got: {pty_out}"
    );
    assert!(
        pty_out.contains("Proceed? [y/N]"),
        "the pty must deliver the interactive prompt, got: {pty_out}"
    );
    assert!(
        pty_out.contains("aborted"),
        "expected the abort notice, got: {pty_out}"
    );
    assert!(
        !registry_path(dir.path()).exists(),
        "an aborted start must not create a registry"
    );
}

#[test]
fn open_refuses_a_tampered_public_url() {
    let dir = TempDir::new().unwrap();
    seed_registry(
        dir.path(),
        &registry_json(4_000_000, false, Some("https://evil.example.com")),
    );

    let (ok, out) = run_ft(dir.path(), &["open", "seed-svc"]);
    assert!(!ok, "a tampered public URL must fail `ft open`, got: {out}");
    assert!(
        out.contains("malformed public URL"),
        "expected the malformed-URL refusal, got: {out}"
    );
    assert!(
        !out.contains("evil.example.com"),
        "the tampered URL must never be printed as opened, got: {out}"
    );
}

#[test]
fn logs_prints_each_tail_with_the_missing_notice_and_follows_appends() {
    use std::io::BufRead;

    let dir = TempDir::new().unwrap();
    seed_registry(dir.path(), &registry_json(4_000_000, false, None));
    let svc = dir.path().join("freeoxide/tunnel/services/seed-svc");
    fs::create_dir_all(&svc).unwrap();
    let mut tunnel_body = String::from("tunnel-first-line-marker\n");
    let mut line_no = 0;
    while tunnel_body.len() < 100 * 1024 {
        line_no += 1;
        tunnel_body.push_str(&format!("tunnel-line-{line_no:06}\n"));
    }
    tunnel_body.push_str("tunnel-final-line-marker\n");
    fs::write(svc.join("tunnel.log"), &tunnel_body).unwrap();

    let (ok, out) = run_ft(dir.path(), &["logs", "seed-svc"]);
    assert!(ok, "`ft logs seed-svc` failed: {out}");
    assert!(
        out.contains("--- tunnel ---"),
        "expected the tunnel section header, got: {out}"
    );
    assert!(
        out.contains("tunnel-final-line-marker"),
        "expected the log's last line tailed, got: {out}"
    );
    assert!(
        !out.contains("tunnel-first-line-marker"),
        "a 100 KiB log's first line must fall outside the tail window, got: {out}"
    );
    assert!(
        out.contains("(no worker.log yet)"),
        "expected the missing worker.log notice, got: {out}"
    );

    fs::create_dir_all(svc.join("worker.log")).unwrap();
    let (ok_dir, out_dir) = run_ft(dir.path(), &["logs", "seed-svc"]);
    assert!(
        !ok_dir,
        "a directory at the worker.log path must fail `ft logs`, got: {out_dir}"
    );
    assert!(
        out_dir.contains("reading log file"),
        "expected the read failure surfaced, got: {out_dir}"
    );
    assert!(
        !out_dir.contains("(no worker.log yet)"),
        "a directory must not be confused with an absent log, got: {out_dir}"
    );
    fs::remove_dir(svc.join("worker.log")).unwrap();

    let mut child = Command::new(ft_bin())
        .args(["logs", "seed-svc", "-f"])
        .env("XDG_STATE_HOME", dir.path())
        .env("RUST_LOG", "")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawning `ft logs seed-svc -f`");
    let stdout = child.stdout.take().expect("the followed logs stdout");
    let seen = Arc::new(Mutex::new(String::new()));
    let reader_seen = Arc::clone(&seen);
    let reader = std::thread::spawn(move || {
        for line in std::io::BufReader::new(stdout).lines() {
            match line {
                Ok(l) => reader_seen.lock().unwrap().push_str(&l),
                Err(_) => break,
            }
        }
    });

    let mut reached_follow = false;
    let tail_deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::time::Instant::now() < tail_deadline {
        if seen.lock().unwrap().contains("(no worker.log yet)") {
            reached_follow = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    std::thread::sleep(std::time::Duration::from_millis(500));

    let mut tunnel_log = fs::OpenOptions::new()
        .append(true)
        .open(svc.join("tunnel.log"))
        .unwrap();
    tunnel_log.write_all(b"a-late-appended-line\n").unwrap();
    drop(tunnel_log);

    let mut followed = false;
    let follow_deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::time::Instant::now() < follow_deadline {
        if seen.lock().unwrap().contains("a-late-appended-line") {
            followed = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let _ = child.kill();
    let _ = child.wait();
    let _ = reader.join();

    assert!(
        reached_follow,
        "the followed child never finished its initial tails, stdout so far: {}",
        seen.lock().unwrap()
    );
    assert!(
        followed,
        "an appended tunnel.log line must arrive on the followed stdout, stdout so far: {}",
        seen.lock().unwrap()
    );
}

fn wait_for_cmdline_token(pid: u32, token: &str) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut last_seen = String::from("`ps` has not completed a poll yet");
    while std::time::Instant::now() < deadline {
        let poll = Command::new("ps")
            .arg("-o")
            .arg("command=")
            .arg("-p")
            .arg(pid.to_string())
            .output();
        match poll {
            Ok(out) => {
                let command = String::from_utf8_lossy(&out.stdout).into_owned();
                if command.contains(token) {
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

struct RunWorkerGroupDecoy {
    child: std::process::Child,
}

impl RunWorkerGroupDecoy {
    fn pid(&self) -> u32 {
        self.child.id()
    }
}

impl Drop for RunWorkerGroupDecoy {
    fn drop(&mut self) {
        let pgid = self.child.id();
        let _ = Command::new("sh")
            .arg("-c")
            .arg(format!("kill -9 -{pgid}"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = self.child.wait();
    }
}

fn spawn_run_worker_group() -> RunWorkerGroupDecoy {
    use std::os::unix::process::CommandExt;
    let child = Command::new("sh")
        .args(["-c", "while :; do sleep 30; done", "run-worker"])
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawning decoy run-worker group");
    let decoy = RunWorkerGroupDecoy { child };
    wait_for_cmdline_token(decoy.pid(), "run-worker");
    decoy
}

fn wait_for_decoy_exit(child: &mut std::process::Child) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        if child.try_wait().expect("try_wait the decoy").is_some() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    child.try_wait().expect("try_wait the decoy").is_some()
}

#[test]
fn kill_and_sanitize_tear_down_a_live_run_worker_group() {
    let dir_a = TempDir::new().unwrap();
    let mut decoy_a = spawn_run_worker_group();
    seed_registry(
        dir_a.path(),
        &registry_json(decoy_a.pid(), false, Some("https://x.trycloudflare.com")),
    );

    let (ok_kill, out_kill) = run_ft(dir_a.path(), &["kill", "seed-svc"]);
    let kill_reaped = wait_for_decoy_exit(&mut decoy_a.child);
    let after_kill = fs::read_to_string(registry_path(dir_a.path())).unwrap_or_default();

    assert!(ok_kill, "`ft kill seed-svc` failed: {out_kill}");
    assert!(
        out_kill.contains("Stopped seed-svc."),
        "expected the live worker's stopped message, got: {out_kill}"
    );
    assert!(
        kill_reaped,
        "`ft kill` must tear down the live run-worker group (pid {})",
        decoy_a.pid()
    );
    assert!(
        !after_kill.contains("seed-svc"),
        "kill must remove the entry, registry: {after_kill}"
    );

    let dir_b = TempDir::new().unwrap();
    let mut decoy_b = spawn_run_worker_group();
    let port = dead_loopback_port();
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
      "worker_pid": {worker_pid},
      "tunnel_pid": null,
      "created_at": "2026-07-21T00:00:00Z",
      "state_dir": "/tmp/seed-run-state",
      "foreground": false
    }}
  ]
}}"#,
        worker_pid = decoy_b.pid()
    );
    seed_registry(dir_b.path(), &body);

    let (ok_sanitize, out_sanitize) = run_ft(dir_b.path(), &["sanitize"]);
    let sanitize_reaped = wait_for_decoy_exit(&mut decoy_b.child);
    let after_sanitize = fs::read_to_string(registry_path(dir_b.path())).unwrap_or_default();

    assert!(ok_sanitize, "`ft sanitize` failed: {out_sanitize}");
    assert!(
        out_sanitize.contains(&format!("- seed-run (upstream 127.0.0.1:{port} is dead")),
        "expected the zombie bullet naming the dead upstream, got: {out_sanitize}"
    );
    assert!(
        sanitize_reaped,
        "`ft sanitize` must tear down the live run-worker group (pid {})",
        decoy_b.pid()
    );
    assert!(
        !after_sanitize.contains("seed-run"),
        "sanitize must remove the zombie entry, registry: {after_sanitize}"
    );
}
