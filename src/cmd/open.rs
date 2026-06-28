//! The `open` command: open a service's public URL in the default browser.

use anyhow::bail;

use crate::error::Result;
use crate::model::Registry;
use crate::state::StateDir;

/// Resolve `target` and open its public URL.
///
/// Bails if the target is unknown, or if the URL has not been discovered yet
/// (the worker is still starting or failed).
pub async fn run(target: String) -> Result<()> {
    let state = StateDir::new()?;
    let registry = Registry::load(&state)?;

    let Some(service) = registry.find(&target) else {
        bail!("no service matches '{target}'");
    };

    let Some(url) = service.public_url.as_deref() else {
        bail!("service '{}' has no public URL yet", service.name);
    };

    open::that(url)?;
    Ok(())
}
