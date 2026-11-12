//! The `identity` subcommand.

use anyhow::Context;
use serde::Serialize;
use tor_keymgr::{KeyMgr, KeystoreSelector};
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
pub(crate) fn run(args: &cli::IdentityArgs, global_args: &cli::GlobalArgs) -> anyhow::Result<()> {
    let config = crate::load_config(global_args)?;
    let state_path = config.storage.state_dir(&crate::config::base_resolver())?;
    let keymgr = InertTorRelay::create_keymgr(&state_path, config.storage.permissions())
        .context("Failed to create key manager")?;

    // Attempt to generate the identity key.
    if args.generate {
        generate_identity(&keymgr, args.overwrite)?;
    }

    print_fingerprints(&keymgr, args.json)
}

/// Generate the Ed25519 and RSA identity keys.
///
/// Existing keys are only replaced if `overwrite` is set.
fn generate_identity(keymgr: &KeyMgr, overwrite: bool) -> anyhow::Result<()> {
    let ed_spec = RelayIdentityKeypairSpecifier::new();
    let rsa_spec = RelayIdentityRsaKeypairSpecifier::new();

    let exists = keymgr.get::<RelayIdentityKeypair>(&ed_spec)?.is_some()
        || keymgr.get::<RelayIdentityRsaKeypair>(&rsa_spec)?.is_some();
    if exists && !overwrite {
        anyhow::bail!("Identity keys already exist. Use --overwrite to replace them");
    }

    let mut rng = tor_llcrypto::rng::CautiousRng;
    let selector = KeystoreSelector::default();
    keymgr
        .generate::<RelayIdentityKeypair>(&ed_spec, selector, &mut rng, overwrite)
        .context("Failed to generate the Ed25519 identity key")?;
    keymgr
        .generate::<RelayIdentityRsaKeypair>(&rsa_spec, selector, &mut rng, overwrite)
        .context("Failed to generate the RSA identity key")?;

    Ok(())
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
