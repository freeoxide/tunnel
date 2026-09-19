//! Local port allocation helpers.

use crate::error::Result;
use anyhow::Context;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

/// Bound for the loopback connect probe in [`is_port_free`]: the local
/// kernel answers almost instantly, so this only bounds pathological stacks;
/// nothing is ever read from the socket.
const PROBE_TIMEOUT: Duration = Duration::from_millis(250);

/// Bind `127.0.0.1:0` so the OS picks a free port, then return it. Inherent
/// TOCTOU: the port could be taken before the worker binds it for real — the
/// worker's bind then fails loudly and the start path surfaces it.
pub fn allocate_free_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").context("finding a free port")?;
    let port = listener
        .local_addr()
        .context("reading the allocated local port")?
        .port();
    Ok(port)
}

/// True if a TCP port appears free on localhost right now: connect to
/// `127.0.0.1:port` and treat "refused" as free, anything else (accepted,
/// timeout, unreachable) as occupied.
///
/// Connect-based rather than bind-based on purpose: a just-stopped server's
/// port sits in TIME_WAIT (up to a minute) where a plain bind without
/// `SO_REUSEADDR` fails EADDRINUSE although nothing serves — but nothing
/// ACCEPTS either, so the connect probe reads it free and a dev server
/// (which sets `SO_REUSEADDR` itself) can rebind. `SO_REUSEADDR` was rejected
/// as the probe mechanism because on Windows it permits binding over a LIVE
/// listener (hijack hazard); the connect probe behaves identically everywhere.
/// Accepted trade-off: a bound-but-not-yet-listening socket also refuses and
/// reads free — transient, and the loser of that bind race fails loudly in
/// its own captured output.
///
/// Port 0 stays reported free: the worker carries the dedicated "port 0 is
/// reserved" bail, and a false here would swap it for a misleading
/// "already in use" pre-flight.
pub fn is_port_free(port: u16) -> bool {
    if port == 0 {
        return true;
    }
    let addr = SocketAddr::new(IpAddr::from(Ipv4Addr::LOCALHOST), port);
    match std::net::TcpStream::connect_timeout(&addr, PROBE_TIMEOUT) {
        // Something accepted: occupied.
        Ok(_) => false,
        // Refused = nothing is listening = free to take (TIME_WAIT included).
        Err(e) => e.kind() == std::io::ErrorKind::ConnectionRefused,
        // Any other error (timeout, unreachable) conservatively reads as
        // occupied.
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
        // The just-stopped-server shape: server closes first (active close),
        // then the client closes — leaving the serving port in TIME_WAIT with
        // no listener. Nothing accepts, so a restart must be allowed.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("local_addr").port();
        let client = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
        let accepted = listener.accept().expect("accept").0;
        // Drop order is the point: the server's active close while the client
        // is still open drives the server endpoint into TIME_WAIT.
        drop(listener);
        drop(accepted);
        drop(client);

        assert!(is_port_free(port), "a TIME_WAIT-only port must read free");
    }

    #[test]
    fn port_zero_stays_reported_free() {
        // `--port 0` must reach the worker's dedicated "port 0 is reserved"
        // bail, not a misleading "already in use" pre-flight refusal.
        assert!(is_port_free(0), "port 0 must keep reading as free");
    }
}
