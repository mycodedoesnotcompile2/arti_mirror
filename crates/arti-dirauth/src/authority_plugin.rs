//! Arti consensus method plugin for C Tor
//!
//! Implements `authority-plugin.md` pursuant to `doc/dev/notes/dirauth-sketch.md`.
//!
//! This is the actual implementation.

use anyhow::Context as _;

use tor_dirauth::consensus;
use tor_error::ErrorReport as _;

mod utils;

/// Options and arguments to plugin invocation
#[derive(Debug, clap::Parser)]
struct CliArgs {
    /// Operation verb and its arguments
    #[command(subcommand)]
    op: CliOperation,
}

/// Operation verb and its arguments
#[derive(Debug, Clone, clap::Subcommand)]
enum CliOperation {
}

/// Top-level error - program exits with this, or `Ok(())`
#[derive(Debug, thiserror::Error)]
enum CliError {
    /// Invalid operation or usage
    #[error("invalid operation or usage")]
    #[allow(dead_code)] // XXXX
    InvalidInputs(#[source] anyhow::Error),

    /// Unsupported consensus method
    #[error("fall back to C Tor")]
    #[allow(dead_code)] // TODO DIRAUTH
    UnsupportedConsensusMethod(#[from] consensus::UnsupportedConsensusMethod),

    /// Operational error
    #[error("failed")]
    #[allow(dead_code)] // XXXX
    OperationalError(#[source] anyhow::Error),
}

/// Actual implementation of the plugin's invocations
///
/// Split off for ease of testing.
#[allow(clippy::needless_pass_by_value)] // XXXX
fn plugin_impl(args: CliArgs) -> Result<(), CliError> {
    match args.op {
    }
}

/// Entrypoint for the Arti-in-C-Tor consensus method plugin
pub fn plugin_main() {
    match (|| {
        let args = <CliArgs as clap::Parser>::try_parse()
            .context("invalid arguments")
            .map_err(CliError::InvalidInputs)?;

        plugin_impl(args)
    })() {
        Ok(()) => {}
        Err(e) => {
            eprintln!("arti-authority-plugin: error: {}", e.report());
            std::process::exit(i32::from(e.exit_status()));
        }
    }
}

impl CliError {
    /// Exit status corresponding to this error, as per `authority-plugin.md`
    ///
    /// Returns `u8` because that's what Unix processes can exit,
    /// `std::process:exit`'s `i32` argument notwithstanding.
    fn exit_status(&self) -> u8 {
        use CliError as E;
        match self {
            E::InvalidInputs { .. } => 8,
            E::UnsupportedConsensusMethod { .. } => 10,
            E::OperationalError { .. } => 32,
        }
    }
}
