//! The `ls` command: list all known services.

use crate::error::Result;
use crate::model::Registry;
use crate::output;
use crate::state::StateDir;

/// Print the registry as a table (empty -> `(no services)`); status is
/// computed per service by probing the worker pid.
pub async fn run() -> Result<()> {
    let state = StateDir::new()?;
    let registry = Registry::load(&state)?;
    output::print_list(&registry.services);
    Ok(())
}
