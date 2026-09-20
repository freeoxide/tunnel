//! Terminal output formatting for `ft` commands.
//!
//! The fixed-format output blocks (start banner, ls table, detail report,
//! doctor/sanitize reports, stop confirmations) live here so command modules
//! stay focused on control flow; inherently sequential printing (prompts,
//! streamed log lines) stays in the commands. Output shapes are fixed by the
//! CLI's public contract.

use crate::cmd::doctor::{Check, CheckStatus};
use crate::model::{Service, ServiceKind};
use chrono::{Datelike, Timelike};
use comfy_table::{Cell, ContentArrangement, Table};

/// Restore the default SIGPIPE disposition so a short-lived printing command
/// piped to a consumer (`ft ls | head`) dies quietly on the broken pipe
/// instead of panicking. NEVER call on a serving path (start/run/hook/drop/
/// proxy, the worker): a SigDfl server dies on the first client disconnect.
pub fn reset_sigpipe() {
    #[cfg(unix)]
    {
        use nix::sys::signal::{SigHandler, Signal, signal};
        // Before any ft task or printing exists; sigaction is process-wide
        // and thread-safe, so tokio's already-running workers are no concern.
        let _ = unsafe { signal(Signal::SIGPIPE, SigHandler::SigDfl) };
    }
}

/// Format a timestamp as `YYYY-MM-DD HH:MM` (no seconds, no timezone suffix).
fn fmt_started(service: &Service) -> String {
    let t = service.created_at;
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}",
        t.year(),
        t.month(),
        t.day(),
        t.hour(),
        t.minute(),
    )
}

/// The public URL, or `(pending)` while the worker has not discovered one.
/// Borrowed: both call sites (println, Cell::new) stringify exactly once.
fn url_or_pending(service: &Service) -> &str {
    service.public_url.as_deref().unwrap_or("(pending)")
}

/// Print the success block emitted by the START command.
///
/// Shape (trailing blank line between the banner and the fields is intentional):
/// ```text
/// Started <name>
///
/// ID:      <id>
/// Local:   <local_url>
/// Public:  <public_url>
/// Logs:    <service_dir>/
/// ```
pub fn print_started(service: &Service) {
    println!("Started {}", service.name);
    println!();
    println!("ID:      {}", service.id);
    println!("Local:   {}", service.local_url);
    println!("Public:  {}", url_or_pending(service));
    // Trailing slash mirrors how shells render directories.
    println!("Logs:    {}/", service.state_dir.display());
}

/// Print the drop bucket's access-token block, ONCE per successful `ft drop`:
/// the token is the write credential, so the operator must leave the start
/// command with it in hand (it also lives in the token file and `ft detail`).
/// The example embeds `example_origin` so it is copy-pasteable.
pub fn print_drop_token(token: &str, example_origin: &str) {
    println!();
    println!("Token:   {token}");
    println!();
    println!("Uploads REQUIRE this token (POST/PUT; GET downloads are public), e.g.:");
    println!(
        "  curl -H \"Authorization: Bearer {token}\" --data-binary @file.txt \
         {example_origin}/file.txt"
    );
    println!("Recover it later with `ft detail <name>`.");
}

/// Print the service list as a table, or `(no services)` when empty.
/// Columns `ID NAME STATUS PORT URL` are a fixed output contract — the kind
/// is visible in `ft detail`'s `Mode:` row, not here.
pub fn print_list(services: &[Service]) {
    if services.is_empty() {
        println!("(no services)");
        return;
    }

    let mut table = Table::new();
    table
        .load_preset(comfy_table::presets::UTF8_FULL)
        .apply_modifier(comfy_table::modifiers::UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec!["ID", "NAME", "STATUS", "PORT", "URL"]);

    // Cell::new stringifies exactly once; owned Strings would allocate twice
    // per cell (ours plus comfy-table's re-stringify).
    for s in services {
        table.add_row(vec![
            Cell::new(s.id),
            Cell::new(s.name.as_str()),
            Cell::new(s.status().as_str()),
            Cell::new(s.port),
            Cell::new(url_or_pending(s)),
        ]);
    }

    println!("{table}");
}

/// A recorded pid rendered for the detail rows, `-` when absent (not yet
/// spawned, or a kind of service that never carries one).
fn pid_or_dash(pid: Option<u32>) -> String {
    pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into())
}

/// The `Directory:` row value: the carried path, or `-` when this kind of
/// service fronts a port and carries no directory.
fn dir_or_dash(service: &Service) -> String {
    service
        .dir
        .as_deref()
        .map_or_else(|| "-".to_string(), |d| d.display().to_string())
}

/// Print a key/value detail block for a single service, including a Logs
/// section listing its log paths.
///
/// The `Mode`/`Directory` rows are kind-aware: Proxy renders `Upstream:`
/// (its `local_url` IS the operator's server), Run/Hook render no directory
/// (a run's `Command PID:` row is its origin fact; a hook's `Requests:` file
/// sits in the Logs section), Drop renders its upload target's `Directory:`
/// plus a `Token:` row read back from the private token file — the token is
/// NOT registry state, so that file is the only way `ft detail` can recover
/// it (`-` when unreadable). Only a Static service renders the static-origin
/// flag rows and a `server.log` (other kinds run no traced static server).
pub fn print_detail(service: &Service) {
    println!("Name:         {}", service.name);
    println!("ID:           {}", service.id);
    println!("Status:       {}", service.status().as_str());
    match service.kind {
        ServiceKind::Proxy => {
            println!("Mode:         {}", service.kind.as_str());
            println!("Upstream:     {}", service.local_url);
        }
        ServiceKind::Run | ServiceKind::Hook => {
            println!("Mode:         {}", service.kind.as_str());
        }
        ServiceKind::Drop => {
            println!("Mode:         {}", service.kind.as_str());
            println!("Directory:    {}", dir_or_dash(service));
        }
        ServiceKind::Static => {
            println!(
                "Mode:         {}",
                if service.foreground {
                    "foreground"
                } else {
                    "background"
                }
            );
            println!("Directory:    {}", dir_or_dash(service));
            // Always rendered on/off so the shape is predictable; the token
            // row only when one is configured (the operator chose it — same
            // recovery convenience as the drop bucket's token row).
            println!(
                "SPA:          {}",
                if service.static_flags.spa {
                    "on"
                } else {
                    "off"
                }
            );
            println!(
                "CORS:         {}",
                if service.static_flags.cors {
                    "on"
                } else {
                    "off"
                }
            );
            if let Some(token) = &service.static_flags.token {
                println!("Token:        {token}");
            }
        }
    }
    println!("Port:         {}", service.port);
    println!("Worker PID:   {}", service.worker_pid);
    println!("Tunnel PID:   {}", pid_or_dash(service.tunnel_pid));
    println!("Command PID:  {}", pid_or_dash(service.command_pid));
    println!("Started:      {}", fmt_started(service));
    println!("Local URL:    {}", service.local_url);
    println!("Public URL:   {}", url_or_pending(service));
    if service.kind == ServiceKind::Drop {
        // The token's durable home is the private token file; detail is where
        // the operator recovers it. A missing/unreadable file renders `-`
        // rather than failing the whole detail.
        let token = crate::server::drop_server::read_token(&service.state_dir)
            .ok()
            .flatten()
            .unwrap_or_else(|| "-".to_string());
        println!("Token:        {token}");
    }
    println!();
    println!("Logs:");
    println!("  {}", service.state_dir.join("worker.log").display());
    if service.kind == ServiceKind::Static {
        // Only a Static worker runs (and traces requests into) a server. A
        // run's command output lands in worker.log instead.
        println!("  {}", service.state_dir.join("server.log").display());
    }
    if service.kind == ServiceKind::Hook {
        // The request record the /__inspect views serve; a logs-section
        // sibling so the operator finds it with the other artifacts.
        println!("  {}", service.state_dir.join("requests.json").display());
    }
    println!("  {}", service.state_dir.join("tunnel.log").display());
}

/// Print the confirmation for an active service that was just stopped.
pub fn print_stopped(name: &str) {
    println!("Stopped {name}.");
}

/// Print the confirmation for removing a service that was already dead.
pub fn print_removed_stale(name: &str) {
    println!("Removed stale service {name}.");
}

/// Print the DOCTOR report: one line per check (`ok`/`warn`/`fail`,
/// width-aligned), an indented `hint:` under any problem carrying one, then a
/// blank line and the `N problem(s), M note(s)` summary (`all checks passed`
/// when both are zero). Rendering only — the decision logic lives in
/// `cmd/doctor.rs`.
///
/// ```text
/// ok    cloudflared: found at /usr/local/bin/cloudflared
/// fail  origin api: proxying 3000 but nothing is listening — the tunnel will 502 every request
///       hint: start the upstream server or stop the service (`ft kill api`)
/// ```
pub fn print_doctor(checks: &[Check]) {
    for check in checks {
        // Width 4 aligns `ok` under `warn`/`fail`.
        println!(
            "{:<4} {}: {}",
            check.status.as_str(),
            check.name,
            check.detail
        );
        if check.status.is_problem()
            && let Some(hint) = &check.hint
        {
            println!("      hint: {hint}");
        }
    }
    let problems = checks.iter().filter(|c| c.status.is_problem()).count();
    let notes = checks
        .iter()
        .filter(|c| c.status == CheckStatus::Note)
        .count();
    println!();
    if problems == 0 && notes == 0 {
        println!("all checks passed");
    } else {
        println!("{problems} problem(s), {notes} note(s)");
    }
}

/// Print the SANITIZE report (rendering only — the decision logic lives in
/// `cmd/sanitize.rs`): `Nothing to clean.` or a `Sanitized N service(s):`
/// bullet list of `(name, reason)`, plus the left-alone note for skipped
/// foreground services (the operator's cue to stop them by hand).
///
/// ```text
/// Sanitized 2 service(s):
///   - proxy-3000 (upstream 127.0.0.1:3000 is dead — tunnel was 502ing every request)
///   - demo (worker no longer running)
/// Left 1 foreground service(s) alone (stop it with Ctrl-C in its terminal):
///   - web
/// ```
pub fn print_sanitized(removed: &[(String, String)], skipped_foreground: &[String]) {
    if removed.is_empty() {
        println!("Nothing to clean.");
    } else {
        println!("Sanitized {} service(s):", removed.len());
        for (name, reason) in removed {
            println!("  - {name} ({reason})");
        }
    }
    if !skipped_foreground.is_empty() {
        println!(
            "Left {} foreground service(s) alone (stop it with Ctrl-C in its terminal):",
            skipped_foreground.len()
        );
        for name in skipped_foreground {
            println!("  - {name}");
        }
    }
}
