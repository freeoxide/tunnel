//! Terminal output formatting for `ft` commands.
//!
//! All printing lives here so command modules stay focused on control flow.
//! Output shapes are fixed by the CLI's public contract — see the `OUTPUT
//! FORMATS` notes in the module docs of the command layer.

use crate::model::Service;
use chrono::{Datelike, Timelike};
use comfy_table::{ContentArrangement, Table};

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
fn url_or_pending(service: &Service) -> String {
    service
        .public_url
        .clone()
        .unwrap_or_else(|| "(pending)".into())
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

/// Print the service list as a table, or `(no services)` when empty.
///
/// Columns: `ID NAME STATUS PORT URL`. Status comes from `Service::status`;
/// URL is the public URL or `(pending)`.
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

    for s in services {
        table.add_row(vec![
            s.id.to_string(),
            s.name.clone(),
            s.status().as_str().to_string(),
            s.port.to_string(),
            url_or_pending(s),
        ]);
    }

    println!("{table}");
}

/// Print a key/value detail block for a single service, including a Logs
/// section listing the worker, server, and tunnel log paths.
pub fn print_detail(service: &Service) {
    let tunnel_pid = service
        .tunnel_pid
        .map(|p| p.to_string())
        .unwrap_or_else(|| "-".into());

    println!("Name:         {}", service.name);
    println!("ID:           {}", service.id);
    println!("Status:       {}", service.status().as_str());
    println!("Directory:    {}", service.dir.display());
    println!("Port:         {}", service.port);
    println!("Worker PID:   {}", service.worker_pid);
    println!("Tunnel PID:   {}", tunnel_pid);
    println!("Started:      {}", fmt_started(service));
    println!("Local URL:    {}", service.local_url);
    println!("Public URL:   {}", url_or_pending(service));
    println!();
    println!("Logs:");
    println!("  {}", service.state_dir.join("worker.log").display());
    println!("  {}", service.state_dir.join("server.log").display());
    println!("  {}", service.state_dir.join("tunnel.log").display());
}

/// Print the confirmation for an active service that was just stopped.
pub fn print_stopped(name: &str) {
    println!("Stopped {}.", name);
}

/// Print the confirmation for removing a service that was already dead.
pub fn print_removed_stale(name: &str) {
    println!("Removed stale service {}.", name);
}
