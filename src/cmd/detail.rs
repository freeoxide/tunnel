//! The `detail` command: show full information about one service.

use anyhow::bail;

use crate::error::Result;
use crate::model::Registry;
use crate::output;
use crate::state::StateDir;

/// Resolve the target (id or name) and print its detail block; bails with a
/// friendly "no service matches" on an unknown target.
pub async fn run(target: String) -> Result<()> {
    let state = StateDir::new()?;
    let registry = Registry::load(&state)?;

    let Some(service) = registry.find(&target) else {
        bail!("no service matches '{target}'");
    };

    output::print_detail(service);
    Ok(())
}
