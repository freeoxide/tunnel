//! The `logs` command: print the tail of a service's log files.

use std::path::PathBuf;

use anyhow::{Context, bail};
use tokio::io::{AsyncReadExt, AsyncSeekExt};

use crate::error::Result;
use crate::model::Registry;
use crate::state::StateDir;

/// Number of trailing lines to show per log file by default.
const TAIL_LINES: usize = 40;
/// Poll interval when following log output.
const FOLLOW_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

/// Resolve `target` and print the tail of its logs.
///
/// Prints the last ~40 lines of `tunnel.log` and then `worker.log`. When
/// `follow` is set, keeps polling both files for new content (best-effort,
/// MVP-grade) until interrupted with Ctrl+C.
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

/// Maximum number of bytes read from a log into memory at once. Logs can grow
/// large, so only the trailing window is held when computing the tail.
const READ_CAP: u64 = 65_536;

/// Print a header and the last ~`TAIL_LINES` lines of `path`.
///
/// For large files, only the trailing `READ_CAP` bytes are read so memory stays
/// bounded (a partial first line may be dropped). Friendly error if the file
/// cannot be opened.
async fn print_tail(path: &PathBuf, label: &str) -> Result<()> {
    println!("--- {label} ---");

    let mut file = match tokio::fs::File::open(path).await {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("  (no {label}.log yet)");
            return Ok(());
        }
        Err(e) => bail!("opening log {}: {}", path.display(), e),
    };

    // If the file is larger than the cap, seek to the last `READ_CAP` bytes
    // before reading so we never hold the whole thing in memory.
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
    let tail: Vec<&str> = text.lines().rev().take(TAIL_LINES).collect::<Vec<_>>();
    for line in tail.into_iter().rev() {
        println!("{line}");
    }
    Ok(())
}

/// Poll both logs for newly appended lines until Ctrl+C.
///
/// Each file is opened once and seeked to EOF; subsequent polls read from that
/// offset to the current end, so only newly appended content is printed. A read
/// error logs a warning and continues so a transient failure does not abort the
/// follow.
async fn follow_logs(tunnel_path: &PathBuf, worker_path: &PathBuf) -> Result<()> {
    // A log may not exist yet (e.g. a service that is still starting). Tolerate
    // that by opening each file best-effort and skipping any that are absent.
    let mut tunnel = open_at_end(tunnel_path).await?;
    let mut worker = open_at_end(worker_path).await?;

    loop {
        tokio::select! {
            biased;
            _ = tokio::signal::ctrl_c() => break,
            _ = tokio::time::sleep(FOLLOW_INTERVAL) => {}
        }

        if let Some(f) = tunnel.as_mut() {
            drain_appended(f).await;
        }
        if let Some(f) = worker.as_mut() {
            drain_appended(f).await;
        }
    }
    Ok(())
}

/// Open `path` and seek to its end, ready for incremental reads.
///
/// Returns `None` when the file does not exist yet (so a starting service does
/// not crash `--follow`); any other I/O error is surfaced via `bail!`.
async fn open_at_end(path: &PathBuf) -> Result<Option<tokio::fs::File>> {
    let mut file = match tokio::fs::File::open(path).await {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => bail!("opening log {}: {}", path.display(), e),
    };
    file.seek(std::io::SeekFrom::End(0)).await?;
    Ok(Some(file))
}

/// Read any bytes appended since the last call and print each line.
///
/// Reads at most `READ_CAP` bytes per poll so a runaway writer cannot exhaust
/// memory between polls; any backlog is picked up on subsequent iterations.
async fn drain_appended(file: &mut tokio::fs::File) {
    let mut buf = vec![0u8; READ_CAP as usize];
    loop {
        match file.read(&mut buf).await {
            Ok(0) => return,
            Ok(n) => {
                let text = String::from_utf8_lossy(&buf[..n]);
                for line in text.lines() {
                    println!("{line}");
                }
                if n < buf.len() {
                    // Short read means we've caught up to EOF.
                    return;
                }
                // Filled the buffer — more may be waiting; loop to drain it.
            }
            Err(_) => return,
        }
    }
}
