//! The `identity` subcommand.

use anyhow::Context;
use serde::Serialize;
use tor_keymgr::KeyMgr;
use tor_relay_crypto::pk::{RelayIdentityKeypair, RelayIdentityRsaKeypair};

use crate::cli;
use crate::keys::{RelayIdentityKeypairSpecifier, RelayIdentityRsaKeypairSpecifier};
use crate::relay::InertTorRelay;

/// The relay identity fingerprints.
#[derive(Serialize)]
struct Fingerprints {
    /// Ed25519 identity, in unpadded base64.
    ed25519: String,
    /// RSA identity, in uppercase hex.
    rsa: String,
}

/// Run the identity subcommand.
pub(crate) fn run(args: cli::IdentityArgs, global_args: cli::GlobalArgs) -> anyhow::Result<()> {
    let config = crate::load_config(&global_args)?;
    let state_path = config.storage.state_dir(&crate::config::base_resolver())?;
    let keymgr = InertTorRelay::create_keymgr(&state_path, config.storage.permissions())
        .context("Failed to create key manager")?;

    print_fingerprints(&keymgr, args.json)
}

/// Print the Ed25519 and RSA identity fingerprints.
#[allow(clippy::print_stdout)]
fn print_fingerprints(keymgr: &KeyMgr, json: bool) -> anyhow::Result<()> {
    let fingerprints = get_fingerprints(keymgr)?;

    if json {
        println!("{}", serde_json::to_string(&fingerprints)?);
        return Ok(());
    }

    match fingerprints {
        Some(fp) => {
            println!("Ed25519: {}", fp.ed25519);
            println!("RSA: {}", fp.rsa);
        }
        None => println!("No identity key found"),
    }

    Ok(())
}

/// Get the identity fingerprints, if the identity keys exist.
fn get_fingerprints(keymgr: &KeyMgr) -> anyhow::Result<Option<Fingerprints>> {
    let ed_kp = keymgr.get::<RelayIdentityKeypair>(&RelayIdentityKeypairSpecifier::new())?;
    let rsa_kp = keymgr.get::<RelayIdentityRsaKeypair>(&RelayIdentityRsaKeypairSpecifier::new())?;

    let (Some(ed_kp), Some(rsa_kp)) = (ed_kp, rsa_kp) else {
        return Ok(None);
    };

    Ok(Some(Fingerprints {
        ed25519: ed_kp.to_ed25519_id().to_string(),
        rsa: rsa_kp
            .to_rsa_identity()
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect(),
    }))
}
