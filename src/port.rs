use crate::error::Result;
use anyhow::Context;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

const PROBE_TIMEOUT: Duration = Duration::from_millis(250);

/// Bind `127.0.0.1:0` for an OS-picked port. Inherent TOCTOU: if it is taken
/// before the real bind, that bind fails loudly and the start surfaces it.
pub fn allocate_free_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").context("finding a free port")?;
    let port = listener
        .local_addr()
        .context("reading the allocated local port")?
        .port();
    Ok(port)
}

/// True if the port appears free on localhost: connect; "refused" = free,
/// anything else = occupied. Connect-based so TIME_WAIT ports read free for a
/// rebinding SO_REUSEADDR server; on Windows that flag binds over LIVE listeners.
pub fn is_port_free(port: u16) -> bool {
    if port == 0 {
        return true;
    }
    let addr = SocketAddr::new(IpAddr::from(Ipv4Addr::LOCALHOST), port);
    match std::net::TcpStream::connect_timeout(&addr, PROBE_TIMEOUT) {
        Ok(_) => false,
        Err(e) => e.kind() == std::io::ErrorKind::ConnectionRefused,
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
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("local_addr").port();
        let client = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
        let accepted = listener.accept().expect("accept").0;
        drop(listener);
        drop(accepted);
        drop(client);

        assert!(is_port_free(port), "a TIME_WAIT-only port must read free");
    }

    #[test]
    fn port_zero_stays_reported_free() {
        // Must reach the worker's dedicated "port 0 is reserved" bail.
        assert!(is_port_free(0), "port 0 must keep reading as free");
    }
}
