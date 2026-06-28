//! The `ls` command: list all known services.

use crate::error::Result;
use crate::model::Registry;
use crate::output;
use crate::state::StateDir;

/// Print every service in the registry as a table.
///
/// Status is computed per service (probing the worker pid), and an empty
/// registry prints `(no services)`.
pub async fn run() -> Result<()> {
    let state = StateDir::new()?;
    let registry = Registry::load(&state)?;
    output::print_list(&registry.services);
    Ok(())
}
