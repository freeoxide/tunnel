//! Terminal output for `ft`: fixed-format blocks live here; sequential
//! printing stays in the commands. Shapes are CLI contract.

use crate::cmd::doctor::{Check, CheckStatus};
use crate::model::{Service, ServiceKind};
use chrono::{Datelike, Timelike};
use comfy_table::{Cell, ContentArrangement, Table};

/// Restore default SIGPIPE so a short-lived printing command piped to a
/// consumer (`ft ls | head`) dies quietly instead of panicking. NEVER call
/// on a serving path (start/run/hook/drop/proxy, the worker): a SigDfl
/// server dies on the first client disconnect.
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

/// The START success block (the blank line between banner and fields is fixed).
pub fn print_started(service: &Service) {
    println!("Started {}", service.name);
    println!();
    println!("ID:      {}", service.id);
    println!("Local:   {}", service.local_url);
    println!("Public:  {}", url_or_pending(service));
    // Trailing slash mirrors how shells render directories.
    println!("Logs:    {}/", service.state_dir.display());
}

/// The drop token block, printed ONCE per successful start: the token is the
/// write credential the operator must leave with. Example is copy-pasteable.
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

/// The service table, or `(no services)` when empty. Columns
/// `ID NAME STATUS PORT URL` are fixed — the kind shows in `ft detail`.
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

/// The key/value detail block. The `Mode`/`Directory` rows are kind-aware:
/// Proxy renders `Upstream:`; Drop renders its target plus a `Token:` row
/// read from the private token file (the token is NOT registry state — that
/// file is the only recovery path); only Static renders the origin-flag rows
/// and a `server.log`.
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
            // row only when configured (operator's choice, like drop's).
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
        // The token's durable home is the private file; `-` on a missing or
        // unreadable one rather than failing the whole detail.
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

/// The DOCTOR report: aligned `ok/warn/fail` check lines, indented `hint:`
/// lines, then the problem/note summary. Rendering only.
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

/// The SANITIZE report: `Nothing to clean.` or a bullet list, plus the
/// left-alone foreground note. Rendering only — decisions in `cmd/sanitize.rs`.
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
