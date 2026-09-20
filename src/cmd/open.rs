//! The `open` command: open a service's public URL in the default browser.

use anyhow::bail;

use crate::cloudflared;
use crate::error::Result;
use crate::model::Registry;
use crate::state::StateDir;

/// Resolve the target, print its URL, then try the default browser — a
/// headless box just gets the URL; bails only on unknown/undiscovered target.
pub async fn run(target: String) -> Result<()> {
    let state = StateDir::new()?;
    let registry = Registry::load(&state)?;

    let Some(service) = registry.find(&target) else {
        bail!("no service matches '{target}'");
    };

    let Some(url) = service.public_url.as_deref() else {
        bail!("service '{}' has no public URL yet", service.name);
    };

    // public_url lives in user-editable registry.json — re-check its shape
    // so a tampered field can't point the browser launcher elsewhere.
    if !cloudflared::is_tunnel_url(url) {
        bail!(
            "service '{}' has a malformed public URL (expected https://*.trycloudflare.com)",
            service.name
        );
    }

    // Printed unconditionally — usable even with no browser.
    println!("{url}");

    match open::that(url) {
        Ok(()) => println!("(opened in your default browser)"),
        Err(_) => println!("(no graphical browser detected — open the URL above manually)"),
    }
    Ok(())
}
