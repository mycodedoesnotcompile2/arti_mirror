use std::process::Output;

use assert_cmd::cargo::cargo_bin_cmd;

use crate::util::create_state_dir_entry;

/// Path to a test specific configuration.
const CFG_PATH: &str = "./tests/testcases/keys/keys.in/keys.toml";

/// Path to a test specific configuration that includes a CTor keystore
const CFG_PATH_WITH_CTOR: &str = "./tests/testcases/keys/conf/keys.toml";

/// A client of an `ArtiNativeKeystore`.
// TODO: Consider using the
// [const_format](https://docs.rs/const_format/latest/const_format/index.html) crate to reduce duplication.
const CLIENT_KEY: &str = "Keystore ID: arti
Role: ks_hsc_desc_enc
Summary: Descriptor decryption key
KeystoreItemType: X25519StaticKeypair
Location: client/mnyizjj7m3hpcr7i5afph3zt7maa65johyu2ruis6z7cmnjmaj3h6tad/ks_hsc_desc_enc.x25519_private
Extra info:
- hs_id: […]tad.onion
";

/// A client of an `ArtiNativeKeystore`, no ID field.
const CLIENT_KEY_NO_ID: &str = "Role: ks_hsc_desc_enc
Summary: Descriptor decryption key
KeystoreItemType: X25519StaticKeypair
Location: client/mnyizjj7m3hpcr7i5afph3zt7maa65johyu2ruis6z7cmnjmaj3h6tad/ks_hsc_desc_enc.x25519_private
Extra info:
- hs_id: […]tad.onion
";

/// A client of an `ArtiNativeKeystore`, compact output.
const CLIENT_KEY_COMPACT: &str = "client/mnyizjj7m3hpcr7i5afph3zt7maa65johyu2ruis6z7cmnjmaj3h6tad/ks_hsc_desc_enc.x25519_private";

/// An unrecognized entry of an `ArtiNativeKeystore`.
const UNRECOGNIZED_ENTRY: &str = "Keystore ID: arti
Location: hss/allium-cepa/unrecognized-entry
Error: Key has invalid path: hss/allium-cepa/unrecognized-entry
";

/// An unrecognized entry of an `ArtiNativeKeystore`, no ID field.
const UNRECOGNIZED_ENTRY_NO_ID: &str = "Location: hss/allium-cepa/unrecognized-entry
Error: Key has invalid path: hss/allium-cepa/unrecognized-entry
";

/// An unrecognized entry of an `ArtiNativeKeystore`, compact output
const UNRECOGNIZED_ENTRY_COMPACT: &str = "hss/allium-cepa/unrecognized-entry";

/// The long term identity of an `ArtiNativeKeystore`.
const ID_KEY: &str = "Keystore ID: arti
Role: ks_hs_id
Summary: Long-term identity keypair
KeystoreItemType: Ed25519ExpandedKeypair
Location: hss/allium-cepa/ks_hs_id.ed25519_expanded_private
Extra info:
- nickname: allium-cepa
";

/// The long term identity of an `ArtiNativeKeystore`, no ID field.
const ID_KEY_NO_ID: &str = "Role: ks_hs_id
Summary: Long-term identity keypair
KeystoreItemType: Ed25519ExpandedKeypair
Location: hss/allium-cepa/ks_hs_id.ed25519_expanded_private
Extra info:
- nickname: allium-cepa
";

/// The long term identity of an `ArtiNativeKeystore`, compact output.
const ID_KEY_COMPACT: &str = "hss/allium-cepa/ks_hs_id.ed25519_expanded_private";

/// An unrecognized path in an `ArtiNativeKeystore`.
const UNRECOGNIZED_PATH: &str = "Keystore ID: *not available*
Location: unrecognized-path-dir/ks_hs_id.ed25519_expanded_private
Error: Unrecognized
";

/// An unrecognized path in an `ArtiNativeKeystore`, no ID field.
const UNRECOGNIZED_PATH_NO_ID: &str =
    "Location: unrecognized-path-dir/ks_hs_id.ed25519_expanded_private
Error: Unrecognized
";

/// An unrecognized path in an `ArtiNativeKeystore`, compact output.
const UNRECOGNIZED_PATH_COMPACT: &str = "unrecognized-path-dir/ks_hs_id.ed25519_expanded_private";

/// The secret key of an `CTorServiceKeystore`.
const CTOR_SECRET: &str = "Keystore ID: ctor
Role: ks_hs_id
Summary: Long-term identity keypair
KeystoreItemType: Ed25519ExpandedKeypair
Location: hs_ed25519_secret_key
";

/// The secret key of an `CTorServiceKeystore`, no ID field.
const CTOR_SECRET_NO_ID: &str = "Role: ks_hs_id
Summary: Long-term identity keypair
KeystoreItemType: Ed25519ExpandedKeypair
Location: hs_ed25519_secret_key
";

/// The secret key of an `CTorServiceKeystore`, compact output.
const CTOR_SECRET_COMPACT: &str = "hs_ed25519_secret_key";

/// The public key of a `CTorServiceKeystore`.
const CTOR_PUBLIC: &str = "Keystore ID: ctor
Role: kp_hs_id
Summary: Public part of the identity key
KeystoreItemType: Ed25519PublicKey
Location: hs_ed25519_public_key
";

/// The public key of a `CTorServiceKeystore`, no ID field.
const CTOR_PUBLIC_NO_ID: &str = "Role: kp_hs_id
Summary: Public part of the identity key
KeystoreItemType: Ed25519PublicKey
Location: hs_ed25519_public_key
";

/// The public key of a `CTorServiceKeystore`, compact output.
const CTOR_PUBLIC_COMPACT: &str = "hs_ed25519_public_key";

/// The hostname file of a `CTorServiceKeystore`.
const CTOR_HOSTNAME: &str = "Keystore ID: ctor
Location: hostname
Error: Key hostname is malformed
";

/// The hostname file of a `CTorServiceKeystore`, no ID field.
const CTOR_HOSTNAME_NO_ID: &str = "Location: hostname
Error: Key hostname is malformed
";

const CTOR_HOSTNAME_COMPACT: &str = "hostname";

/// An unrecognized entry in a `CTorServiceKeystore`.
const CTOR_UNRECOGNIZED_ENTRY: &str = "Keystore ID: ctor
Location: hs_unrecognized_entry
Error: Key hs_unrecognized_entry is malformed
";

/// An unrecognized entry in a `CTorServiceKeystore`, no ID field.
const CTOR_UNRECOGNIZED_ENTRY_NO_ID: &str = "Location: hs_unrecognized_entry
Error: Key hs_unrecognized_entry is malformed
";

/// An unrecognized entry in a `CTorServiceKeystore`, compact output.
const CTOR_UNRECOGNIZED_ENTRY_COMPACT: &str = "hs_unrecognized_entry";

/// The output relative to all the keys present in the test `ArtiNativeKeystore`.
pub(super) const LIST_OUTPUT_ARTI: &[&str] =
    &[CLIENT_KEY, UNRECOGNIZED_ENTRY, ID_KEY, UNRECOGNIZED_PATH];

/// The output relative to all the keys present in the test `ArtiNativeKeystore`, no ID field.
pub(super) const LIST_OUTPUT_ARTI_NO_ID: &[&str] = &[
    CLIENT_KEY_NO_ID,
    UNRECOGNIZED_ENTRY_NO_ID,
    ID_KEY_NO_ID,
    UNRECOGNIZED_PATH_NO_ID,
];

/// The output relative to all the keys present in the test `ArtiNativeKeystore`, compact output.
pub(super) const LIST_OUTPUT_ARTI_COMPACT: &[&str] = &[
    CLIENT_KEY_COMPACT,
    UNRECOGNIZED_ENTRY_COMPACT,
    ID_KEY_COMPACT,
    UNRECOGNIZED_PATH_COMPACT,
];

/// The output relative to all the keys present in the test `CTorServiceKeystore`.
///
// TODO: The hostname file of the ctor keystore is not
// currently handled correctly and is erroneously represented
// as an unrecognized entry. This should be fixed.
pub(super) const LIST_OUTPUT_CTOR: &[&str] = &[
    CTOR_HOSTNAME,
    CTOR_SECRET,
    CTOR_PUBLIC,
    CTOR_UNRECOGNIZED_ENTRY,
];

/// The output relative to all the keys present in the test `CTorServiceKeystore`,
/// no ID field.
///
// TODO: The hostname file of the ctor keystore is not
// currently handled correctly and is erroneously represented
// as an unrecognized entry. This should be fixed.
pub(super) const LIST_OUTPUT_CTOR_NO_ID: &[&str] = &[
    CTOR_HOSTNAME_NO_ID,
    CTOR_SECRET_NO_ID,
    CTOR_PUBLIC_NO_ID,
    CTOR_UNRECOGNIZED_ENTRY_NO_ID,
];

/// The output relative to all the keys present in the test `CTorServiceKeystore`,
/// compact output.
///
// TODO: The hostname file of the ctor keystore is not
// currently handled correctly and is erroneously represented
// as an unrecognized entry. This should be fixed.
pub(super) const LIST_OUTPUT_CTOR_COMPACT: &[&str] = &[
    CTOR_HOSTNAME_COMPACT,
    CTOR_SECRET_COMPACT,
    CTOR_PUBLIC_COMPACT,
    CTOR_UNRECOGNIZED_ENTRY_COMPACT,
];

/// A struct that represents the subcommand `keys list`.
#[derive(Debug, Clone, Default, Eq, PartialEq, derive_builder::Builder)]
pub(super) struct KeysListCmd {
    /// Use [`with_arti`] to include a populated `ArtiNativeKeystore`.
    #[builder(default)]
    with_arti: bool,
    /// Use [`with_ctor`] to include a populated `CTorServiceKeystore`.
    #[builder(default)]
    with_ctor: bool,
    /// Use [`keystore`] to pass a `-k <KEYSTORE_ID>` flag to the command.
    #[builder(default)]
    keystore: Option<String>,
    /// Use [`compact`] to pass the `--compact` flag to the command.
    #[builder(default)]
    compact: bool,
}

impl KeysListCmd {
    /// Execute the command and return its output as an [`Output`].
    pub(super) fn output(&self) -> std::io::Result<Output> {
        let mut cmd = cargo_bin_cmd!("arti");
        if self.with_ctor {
            cmd.args(["-c", CFG_PATH_WITH_CTOR]);
        } else {
            cmd.args(["-c", CFG_PATH]);
        }
        // When [`with_arti`] is set to false, the default configured state directory,
        // which holds an Arti-native keystore with both valid and invalid entries,
        // will be replaced by a new, temporary, empty directory.
        let state_dir;
        if !self.with_arti {
            state_dir = tempfile::TempDir::new().unwrap();
            let state_dir_path = state_dir.path().to_path_buf();
            let state_dir_path = state_dir_path.to_str().unwrap();

            let opt = create_state_dir_entry(state_dir_path);

            cmd.args(["-o", &opt]);
        }

        cmd.args(["keys", "list"]);

        if let Some(keystore_id) = &self.keystore {
            cmd.args(["-k", keystore_id]);
        }

        if self.compact {
            cmd.arg("--compact");
        }

        cmd.output()
    }
}

/// A struct that represents the subcommand `keys list-keystores`.
#[derive(Debug, Clone, Default, Eq, PartialEq, derive_builder::Builder)]
pub(super) struct KeysListKeystoreCmd {
    /// Use [`with_ctor`] to include a `CTorServiceKeystore` in the configuration.
    #[builder(default)]
    with_ctor: bool,
}

impl KeysListKeystoreCmd {
    /// Execute the command and return its output as an [`Output`].
    pub(super) fn output(&self) -> std::io::Result<Output> {
        let mut cmd = cargo_bin_cmd!("arti");
        if self.with_ctor {
            cmd.args(["-c", CFG_PATH_WITH_CTOR]);
        } else {
            cmd.args(["-c", CFG_PATH]);
        }

        cmd.args(["keys", "list-keystores"]);

        cmd.output()
    }
}
