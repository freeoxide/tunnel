//! The `open` command: open a service's public URL in the default browser.

use anyhow::bail;

use crate::error::Result;
use crate::model::Registry;
use crate::state::StateDir;

/// Resolve `target` and open its public URL.
///
/// Always prints the URL first. Then attempts to launch the default browser;
/// on a headless box (VPS, no `DISPLAY`/`WAYLAND_DISPLAY`, or no `xdg-open`)
/// the launch simply fails and we surface the URL for manual use — this never
/// crashes or exits non-zero just because there is no browser.
///
/// Bails only if the target is unknown or its URL has not been discovered yet.
pub async fn run(target: String) -> Result<()> {
    let state = StateDir::new()?;
    let registry = Registry::load(&state)?;

    let Some(service) = registry.find(&target) else {
        bail!("no service matches '{target}'");
    };

    let Some(url) = service.public_url.as_deref() else {
        bail!("service '{}' has no public URL yet", service.name);
    };

    // Print the URL unconditionally so it is available even when no browser
    // can be launched.
    println!("{url}");

    match open::that(url) {
        Ok(()) => println!("(opened in your default browser)"),
        Err(_) => println!("(no graphical browser detected — open the URL above manually)"),
    }
    Ok(())
}
