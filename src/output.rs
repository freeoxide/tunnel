//! Terminal output formatting for `ft` commands.
//!
//! The fixed-format output blocks (start banner, ls table, detail report,
//! doctor/sanitize reports, stop confirmations) live here so command modules
//! stay focused on control flow; inherently sequential printing — interactive
//! prompts, streamed log lines — stays in the commands themselves. Output
//! shapes are fixed by the CLI's public contract — see the `OUTPUT FORMATS`
//! notes in the module docs of the command layer.

use crate::cmd::doctor::{Check, CheckStatus};
use crate::model::{Service, ServiceKind};
use chrono::{Datelike, Timelike};
use comfy_table::{Cell, ContentArrangement, Table};

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

/// The public URL, or `(pending)` while the worker has not discovered one yet.
///
/// Returns a borrowed slice to avoid cloning the (potentially long) public URL
/// on every call. Both call sites use the borrow for free: `println!` takes it
/// as a format argument, and the `comfy_table` row hands it to `Cell::new`,
/// which stringifies each cell exactly once internally.
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

/// Print the drop bucket's access-token block, printed ONCE by a successful
/// `ft drop` (background and foreground alike): the token is the write
/// credential for the bucket, so the operator must walk away from the start
/// command with it in hand (it also lives in the service's private token file
/// and is shown by `ft detail`). The example embeds `example_origin` so the
/// command line is copy-pasteable.
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
///
/// Columns: `ID NAME STATUS PORT URL`. Status comes from `Service::status`;
/// URL is the public URL or `(pending)`. Proxy services render through the
/// same columns unchanged: their `PORT` is the upstream port they front, and
/// the kind is visible in `ft detail`'s `Mode:` row — adding a kind column
/// here would perturb the static table, which is a fixed output contract.
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

    // Cell::new stringifies each cell exactly once internally; passing owned
    // Strings would allocate twice per cell (our conversion plus comfy-table's
    // re-stringify through its blanket From<T: ToString> for Cell), so hand it
    // borrows and plain integers instead.
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
/// section listing the service's log paths.
///
/// The `Mode`/`Directory` rows are kind-aware: a Static service keeps the
/// historical shape exactly (mode = foreground/background, plus the served
/// `Directory:`) and adds its static-origin flag rows (`SPA:`/`CORS:` always,
/// on/off; `Token:` only when the operator started it with `--token`), a Proxy
/// service renders its kind in the `Mode:` row and
/// replaces `Directory:` with the `Upstream:` it fronts (the proxy's
/// `local_url` IS the operator's server), a Run service renders its kind with
/// no Directory row at all (its origin is the command ft spawned — the
/// `Command PID:` row is the run-specific fact), a Hook service renders
/// its kind with no Directory/Upstream row (its origin is ft's own webhook
/// receiver; the `Requests:` file in the Logs section is where the recorded
/// requests live), and a Drop service renders its kind plus the upload
/// target's `Directory:` row and a `Token:` row — the drop bucket's write
/// credential, read back from the service's private token file (the token is
/// deliberately NOT registry state, so the file read here is the only way
/// `ft detail` can recover it for the operator; `-` when it cannot be read).
/// A proxy, run, hook, or drop service runs no traced static server, so the
/// Logs section lists no `server.log` (a run's command output is teed into
/// `worker.log`; a hook's request record is `requests.json`; a drop's record
/// is the bucket directory itself).
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
            // The static-origin flags as started (`--spa`/`--cors`/`--token`):
            // always rendered on/off so the shape is predictable, with the
            // token row only when one is configured (a `-` placeholder for a
            // value that never existed would just be noise on the historical
            // no-flag shape). The token renders because the operator chose it
            // — same recovery convenience as the drop bucket's token row.
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
        // The upload credential's durable home is the service's private token
        // file; detail is where the operator recovers it (printed once at
        // start, this is the second and last place it appears). A missing or
        // unreadable file renders as `-` rather than failing the whole detail.
        let token = crate::drop_server::read_token(&service.state_dir)
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
        // The hook origin's own request record — the data the /__inspect
        // views serve — is a file sibling of the logs, so it is listed here
        // where the operator already looks for a service's on-disk artifacts.
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

/// Print the DOCTOR report.
///
/// Shape (one line per check, then a blank line and the one-line summary):
/// ```text
/// ok    cloudflared: found at /usr/local/bin/cloudflared
/// fail  origin api: proxying 3000 but nothing is listening — the tunnel will 502 every request
///       hint: start the upstream server or stop the service (`ft kill api`)
///
/// 1 problem(s), 0 note(s)
/// ```
/// The three status words (`ok`, `warn`, `fail`) are left-aligned to the
/// same width; an indented `hint:` line follows any problem that carries a
/// remediation. The summary counts problems (warn + fail) and notes
/// separately, collapsing to `all checks passed` only when there are none
/// of either. Rendering only — doctor's decision logic lives in
/// `cmd/doctor.rs`.
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

/// Print the SANITIZE report.
///
/// Shape (prune-style plain text; `removed` is a list of
/// `(name, reason)` pairs, the reason rendering inside the bullet's
/// parentheses — e.g. `worker no longer running` or `upstream
/// 127.0.0.1:3000 is dead — tunnel was 502ing every request`):
/// ```text
/// Sanitized 2 service(s):
///   - proxy-3000 (upstream 127.0.0.1:3000 is dead — tunnel was 502ing every request)
///   - demo (worker no longer running)
/// Left 1 foreground service(s) alone (stop it with Ctrl-C in its terminal):
///   - web
/// ```
/// `Nothing to clean.` is printed when nothing was removed; the left-alone
/// note still follows when foreground zombies were skipped, since that is
/// the operator's cue to stop them by hand. Rendering only — the decision
/// logic lives in `cmd/sanitize.rs`.
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
