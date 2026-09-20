//! The `logs` command: print the tail of a service's log files.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, bail};
use tokio::io::{AsyncReadExt, AsyncSeekExt};

use crate::error::Result;
use crate::model::Registry;
use crate::state::StateDir;

/// Number of trailing lines to show per log file by default.
const TAIL_LINES: usize = 40;
/// Poll interval when following log output.
const FOLLOW_INTERVAL: Duration = Duration::from_millis(500);
/// Maximum number of bytes read from a log into memory at once; only the
/// trailing window is held when computing a tail or draining appends.
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

/// The last ~`TAIL_LINES` lines of `path`; only the trailing `READ_CAP` bytes
/// are read so memory stays bounded. Friendly error if unopenable.
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

    // Seek to the last READ_CAP bytes of a large file so the whole thing is
    // never held in memory.
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

/// Poll both logs for appended lines until Ctrl+C (each opened once, seeked
/// to EOF); a read error silently ends that file's follow only.
async fn follow_logs(tunnel_path: &Path, worker_path: &Path) -> Result<()> {
    // A log may not exist yet (e.g. a service that is still starting): open
    // each best-effort and skip any that are absent.
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

/// Open + seek to end for incremental reads; `None` when the file does not
/// exist yet (a starting service must not crash `--follow`).
async fn open_at_end(path: &Path) -> Result<Option<tokio::fs::File>> {
    let mut file = match tokio::fs::File::open(path).await {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => bail!("opening log {}: {}", path.display(), e),
    };
    file.seek(std::io::SeekFrom::End(0)).await?;
    Ok(Some(file))
}

/// Read bytes appended since the last call, print each line. At most
/// READ_CAP per poll; the `leftover` carry never splits a line or code point.
async fn drain_appended(file: &mut tokio::fs::File, leftover: &mut Vec<u8>) {
    let mut buf = vec![0u8; READ_CAP as usize];
    loop {
        // Read into the back of whatever partial bytes we carried over, then
        // append them in place so the carried prefix stays contiguous.
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

        // Print every whole line; carry whatever follows the last newline.
        // No newline at all: a partial line still being written — keep carrying.
        if let Some(last_nl) = leftover.iter().rposition(|&b| b == b'\n') {
            let rest = leftover.split_off(last_nl + 1);
            flush_text(leftover);
            *leftover = rest;
        }

        if n < buf.len() - read_start {
            // Short read means we've caught up to EOF.
            return;
        }
        // Filled the read window — more may be waiting; loop to drain it.
    }
}

/// Decode + print lines. `bytes` always ends at a `\n` boundary (callers
/// carry partial tails), so lossy decoding cannot split a code point.
fn flush_text(bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    let text = String::from_utf8_lossy(bytes);
    for line in text.lines() {
        println!("{line}");
    }
}
