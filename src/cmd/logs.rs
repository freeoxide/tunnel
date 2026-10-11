//! The `logs` command: print the tail of a service's log files.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, bail};
use tokio::io::{AsyncReadExt, AsyncSeekExt};

use crate::error::Result;
use crate::model::Registry;
use crate::state::StateDir;

const TAIL_LINES: usize = 40;
const FOLLOW_INTERVAL: Duration = Duration::from_millis(500);
const READ_CAP: u64 = 65_536;

/// Print the last ~40 lines of `tunnel.log` then `worker.log`; with `follow`,
/// keep polling both until Ctrl+C.
pub async fn run(target: String, follow: bool) -> Result<()> {
    let state = StateDir::new()?;
    let registry = Registry::load(&state)?;

    let Some(service) = registry.find(&target) else {
        bail!("no service matches '{target}'");
    };

    let tunnel_log = state.tunnel_log(&service.name);
    let worker_log = state.worker_log(&service.name);

    print_tail(&tunnel_log, "tunnel").await?;
    println!();
    print_tail(&worker_log, "worker").await?;

    if follow {
        follow_logs(&tunnel_log, &worker_log).await?;
    }

    Ok(())
}

async fn print_tail(path: &Path, label: &str) -> Result<()> {
    println!("--- {label} ---");

    let mut file = match tokio::fs::File::open(path).await {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("  (no {label}.log yet)");
            return Ok(());
        }
        Err(e) => bail!("opening log {}: {}", path.display(), e),
    };

    if let Ok(meta) = file.metadata().await
        && meta.len() > READ_CAP
    {
        file.seek(std::io::SeekFrom::Start(meta.len() - READ_CAP))
            .await?;
    }

    let mut buf = Vec::new();
    file.read_to_end(&mut buf)
        .await
        .context("reading log file")?;

    let text = String::from_utf8_lossy(&buf);
    let tail: Vec<&str> = text.lines().rev().take(TAIL_LINES).collect();
    for line in tail.into_iter().rev() {
        println!("{line}");
    }
    Ok(())
}

async fn follow_logs(tunnel_path: &Path, worker_path: &Path) -> Result<()> {
    let mut tunnel = open_at_end(tunnel_path).await?;
    let mut worker = open_at_end(worker_path).await?;
    // Per-file leftover buffers carried across reads so a line or multi-byte
    // UTF-8 code point that straddles a read boundary is never split.
    let mut tunnel_leftover = Vec::new();
    let mut worker_leftover = Vec::new();

    loop {
        tokio::select! {
            biased;
            _ = tokio::signal::ctrl_c() => break,
            _ = tokio::time::sleep(FOLLOW_INTERVAL) => {}
        }

        if let Some(f) = tunnel.as_mut() {
            drain_appended(f, &mut tunnel_leftover).await;
        }
        if let Some(f) = worker.as_mut() {
            drain_appended(f, &mut worker_leftover).await;
        }
    }
    Ok(())
}

async fn open_at_end(path: &Path) -> Result<Option<tokio::fs::File>> {
    let mut file = match tokio::fs::File::open(path).await {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => bail!("opening log {}: {}", path.display(), e),
    };
    file.seek(std::io::SeekFrom::End(0)).await?;
    Ok(Some(file))
}

async fn drain_appended(file: &mut tokio::fs::File, leftover: &mut Vec<u8>) {
    let mut buf = vec![0u8; READ_CAP as usize];
    loop {
        let read_start = leftover.len();
        if read_start >= buf.len() {
            // Pathological: a single line longer than READ_CAP with no
            // newline. Flush it as-is rather than growing unbounded.
            flush_text(leftover);
            leftover.clear();
            continue;
        }
        let n = match file.read(&mut buf[read_start..]).await {
            Ok(0) => return,
            Ok(n) => n,
            Err(_) => return,
        };
        leftover.extend_from_slice(&buf[read_start..read_start + n]);

        if let Some(last_nl) = leftover.iter().rposition(|&b| b == b'\n') {
            let rest = leftover.split_off(last_nl + 1);
            flush_text(leftover);
            *leftover = rest;
        }

        if n < buf.len() - read_start {
            return;
        }
    }
}

fn flush_text(bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    let text = String::from_utf8_lossy(bytes);
    for line in text.lines() {
        println!("{line}");
    }
}
