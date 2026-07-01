//! Local port allocation helpers.

use crate::error::Result;
use anyhow::Context;

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
pub fn is_port_free(port: u16) -> bool {
    std::net::TcpListener::bind(("127.0.0.1", port)).is_ok()
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
}
