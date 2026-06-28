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

/// Print a header and the last ~`TAIL_LINES` lines of `path`.
///
/// Reads the whole file (acceptable for MVP-sized logs) and prints its trailing
/// lines. Friendly error if the file cannot be opened.
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
    let mut tunnel = open_at_end(tunnel_path).await?;
    let mut worker = open_at_end(worker_path).await?;

    loop {
        tokio::select! {
            biased;
            _ = tokio::signal::ctrl_c() => break,
            _ = tokio::time::sleep(FOLLOW_INTERVAL) => {}
        }

        drain_appended(&mut tunnel).await;
        drain_appended(&mut worker).await;
    }
    Ok(())
}

/// Open `path` and seek to its end, ready for incremental reads.
async fn open_at_end(path: &PathBuf) -> Result<tokio::fs::File> {
    let mut file = tokio::fs::File::open(path)
        .await
        .with_context(|| format!("opening log {}", path.display()))?;
    file.seek(std::io::SeekFrom::End(0)).await?;
    Ok(file)
}

/// Read any bytes appended since the last call and print each line.
async fn drain_appended(file: &mut tokio::fs::File) {
    let mut buf = Vec::new();
    if file.read_to_end(&mut buf).await.is_ok() && !buf.is_empty() {
        let text = String::from_utf8_lossy(&buf);
        for line in text.lines() {
            println!("{line}");
        }
    }
}
