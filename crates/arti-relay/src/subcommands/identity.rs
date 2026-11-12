//! The `identity` subcommand.

use crate::cli;

/// Run the identity subcommand.
pub(crate) fn run(_args: cli::IdentityArgs, _global_args: cli::GlobalArgs) -> anyhow::Result<()> {
    Ok(())
}
