//! Local port allocation helpers.

use crate::error::Result;
use anyhow::Context;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

/// Bound for the loopback connect probe in [`is_port_free`]. A loopback
/// connect is answered by the local kernel almost instantly (accept-queue
/// answer or RST), so this only bounds pathological stacks; it is not a
/// request timeout — nothing is ever read from the socket.
const PROBE_TIMEOUT: Duration = Duration::from_millis(250);

/// Bind `127.0.0.1:0` so the OS picks a free port, then return it.
///
/// NOTE: there is an inherent TOCTOU race — the port could be taken between
/// this call and the worker binding it for real. This is acceptable for the
/// MVP; the worker's actual bind will fail loudly if it loses the race, which
/// the start path surfaces as a clear error.
pub fn allocate_free_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").context("finding a free port")?;
    let port = listener
        .local_addr()
        .context("reading the allocated local port")?
        .port();
    Ok(port)
}

/// True if a TCP port appears free on localhost right now.
///
/// Strategy: a CONNECT-based probe — try to connect to `127.0.0.1:port` and
/// treat connection-refused as "free" and a successful connect (or any other
/// outcome) as "occupied". Chosen over the former plain-bind probe and over a
/// unix-only `setsockopt(SO_REUSEADDR)` bind probe because:
///
/// - TIME_WAIT: a just-stopped server leaves its port held by TIME_WAIT
///   sockets for up to a minute, and a plain bind WITHOUT `SO_REUSEADDR` is
///   NOT reliably rebindable through that window — it can fail with
///   `EADDRINUSE` while nothing is actually serving the port — so the old
///   bind probe made `ft run` reject a perfectly restartable port. Nothing
///   accepts connections on a TIME_WAIT-only port, so the connect probe
///   correctly reads it free, and a dev server (which virtually always sets
///   `SO_REUSEADDR` itself) can rebind it.
/// - Portability: `SO_REUSEADDR` on Windows is a different, dangerous
///   contract (it permits binding over a LIVE listener — a hijack hazard),
///   so the setsockopt route would need a platform split; a loopback connect
///   behaves identically everywhere.
/// - Trade-off accepted: a socket that is bound but not yet listening also
///   refuses connects and reads as free. Such sockets are transient and rare
///   on a loopback service port, and if the child later loses that bind race,
///   the failure surfaces loudly through its own captured output.
///
/// Port 0 deliberately stays reported free (the kernel treats it as "assign
/// me one" in a bind probe): the detached worker carries the dedicated "port
/// 0 is reserved" bail for that input, and returning false here would swap
/// that clear error for a misleading "port 0 is already in use" pre-flight.
pub fn is_port_free(port: u16) -> bool {
    if port == 0 {
        return true;
    }
    let addr = SocketAddr::new(IpAddr::from(Ipv4Addr::LOCALHOST), port);
    match std::net::TcpStream::connect_timeout(&addr, PROBE_TIMEOUT) {
        // Something accepted: occupied, same verdict as the old bind probe.
        Ok(_) => false,
        // Refused = nothing is listening = free to take (TIME_WAIT included).
        Err(e) => e.kind() == std::io::ErrorKind::ConnectionRefused,
        // Any other error (timeout, unreachable) is treated as occupied:
        // conservatively refusing matches the old probe's failure direction.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocate_returns_ephemeral_port_that_is_free() {
        let p = allocate_free_port().expect("allocate");
        assert!(p > 0, "OS-assigned port must be non-zero");
        assert!(
            is_port_free(p),
            "a freshly allocated port should read as free"
        );
    }

    #[test]
    fn is_port_free_is_false_while_a_port_is_held() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("local_addr").port();
        assert!(
            !is_port_free(port),
            "port should read as in-use while the listener is held"
        );
        drop(listener);
    }

    #[test]
    fn a_port_left_in_time_wait_by_a_just_stopped_server_reads_free() {
        // R3-2 pin, in the exact state the old bind probe misread: a client
        // connects, the SERVER side closes first (active close), then the
        // client closes too — leaving the serving port held by a TIME_WAIT
        // socket instead of a listener (the just-stopped-server shape `ft
        // run` used to refuse spuriously).
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("local_addr").port();
        let client = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
        let accepted = listener.accept().expect("accept").0;
        // Drop order is the point: the server closes actively while the
        // client is still open, then the client's close drives the server
        // endpoint into TIME_WAIT.
        drop(listener);
        drop(accepted);
        drop(client);

        // The contract under fix: nothing ACCEPTS on the port any more, so a
        // restart against it must be allowed. A plain bind is NOT reliably
        // rebindable through a TIME_WAIT window (EADDRINUSE despite no
        // listener) — exactly why the probe is connect-based, where "refused"
        // is the platform-independent truth about "nothing is serving here".
        assert!(is_port_free(port), "a TIME_WAIT-only port must read free");
    }

    #[test]
    fn port_zero_stays_reported_free() {
        // is_port_free(0) was true under the old bind probe (the kernel reads
        // 0 as "assign me one"), and the detached worker carries the dedicated
        // "port 0 is reserved" bail for that input. The connect probe must
        // keep returning true so `--port 0` still reaches that clearer error
        // instead of a misleading "already in use" pre-flight refusal.
        assert!(is_port_free(0), "port 0 must keep reading as free");
    }
}
