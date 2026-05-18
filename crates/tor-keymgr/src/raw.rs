//! Raw keystore entry identifiers used in plumbing CLI functionalities.

use std::path::PathBuf;

use tor_basic_utils::PathExt;
use tor_key_forge::KeystoreItemType;

use crate::ArtiPath;

/// The raw identifier of a key inside a [`Keystore`](crate::Keystore).
///
/// The exact type of the identifier depends on the backing storage of the keystore
/// (for example, an on-disk keystore will identify its entries by [`Path`](RawEntryId::Path)).
#[cfg_attr(feature = "onion-service-cli-extra", visibility::make(pub))]
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, derive_more::Display)]
pub(crate) enum RawEntryId {
    /// An entry identified by path inside an on-disk keystore.
    // NOTE: this will only be used by on-disk keystores like
    // [`ArtiNativeKeystore`](crate::ArtiNativeKeystore)
    #[display("{}", _0.display_lossy())]
    Path(PathBuf),

    /// An entry of an in-memory ephemeral key storage
    /// [`ArtiEphemeralKeystore`](crate::ArtiEphemeralKeystore)
    #[display("{} {:?}", _0.0, _0.1)]
    Ephemeral((ArtiPath, KeystoreItemType)),
    // TODO: when/if we add support for non on-disk keystores,
    // new variants will be added
}
