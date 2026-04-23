//! Views that restricts the access to only specific keys which are tailored for specific tasks.
//! The domain specific views use the generic view helper which wraps the [`KeyMgr`].

use anyhow::{Context, Result};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, RwLock},
};

use tor_keymgr::{KeyMgr, KeySpecifierPattern};
use tor_relay_crypto::{
    RelaySigningKeyCert,
    pk::{
        RelayIdentityKeypair, RelayIdentityRsaKeypair, RelayLinkSigningKeypair, RelayNtorKeys,
        RelaySigningKeypair,
    },
};

use crate::keys::{
    RelayIdentityKeypairSpecifier, RelayIdentityRsaKeypairSpecifier,
    RelayLinkSigningKeypairSpecifier, RelayLinkSigningKeypairSpecifierPattern,
    RelayNtorKeypairSpecifier, RelayNtorKeypairSpecifierPattern, RelaySigningKeyCertSpecifier,
    RelaySigningKeypairSpecifier, RelaySigningKeypairSpecifierPattern,
    RelaySigningPublicKeySpecifier, Timestamp,
};

/// Local helper enum to identify specific key/cert that expires.
///
/// This is used in the valid_until cache of the [`FullKeyView`] and only exposed to the crypto
/// task which uses it to update the cache.
#[derive(Copy, Clone, PartialEq, Eq, Hash, strum::Display)]
pub(super) enum ExpirableKeyType {
    /// Relay link authentication ed25519 keypair.
    LinkEd,
    /// Relay signing ed25519 keypair.
    RelaysignEd,
    /// Ntor latest (current) keypair.
    NtorLatest,
    /// Ntor previous keypair.
    NtorPrevious,
}

/// Write guard on the [`FullKeyView`] protecting the valid_until cache.
///
/// This is only visible to the crypto task as only that task can change the cache.
pub(super) struct KeyViewWriteGuard<'a> {
    /// Write lock guard on the valid_until cache.
    guard: std::sync::RwLockWriteGuard<'a, HashMap<ExpirableKeyType, Timestamp>>,
    /// The key manager which should only be accessed by holding this guard.
    keymgr: &'a KeyMgr,
}

#[expect(unused)] // TODO(relay): Remove
impl KeyViewWriteGuard<'_> {
    /// Set the valid_until time in the cache for a given key type.
    pub(super) fn set_valid_until(&mut self, ty: ExpirableKeyType, valid_until: Timestamp) {
        self.guard.insert(ty, valid_until);
    }

    /// Reference to the key manager.
    pub(super) fn keymgr(&self) -> &KeyMgr {
        self.keymgr
    }

    /// Rebuild the valid_until cache from the current keystore state.
    ///
    /// Reads all expirable key types from the keystore and replaces the cache. For ntor keys,
    /// entries are sorted descending so the newest is [`NtorLatest`] and the second (if any) is
    /// [`NtorPrevious`].
    ///
    /// Returns the set of key types whose cached `valid_until` changed (added, removed, or
    /// updated).
    pub(super) fn reconcile(&mut self) -> anyhow::Result<HashSet<ExpirableKeyType>> {
        let mut cache = HashMap::new();

        if let Some(entry) = self
            .keymgr
            .list_matching(&RelayLinkSigningKeypairSpecifierPattern::new_any().arti_pattern()?)?
            .first()
        {
            let ts = RelayLinkSigningKeypairSpecifier::try_from(entry.key_path())?.valid_until;
            cache.insert(ExpirableKeyType::LinkEd, ts);
        }

        if let Some(entry) = self
            .keymgr
            .list_matching(&RelaySigningKeypairSpecifierPattern::new_any().arti_pattern()?)?
            .first()
        {
            let ts = RelaySigningKeypairSpecifier::try_from(entry.key_path())?.valid_until;
            cache.insert(ExpirableKeyType::RelaysignEd, ts);
        }

        let mut ntor: Vec<Timestamp> = self
            .keymgr
            .list_matching(&RelayNtorKeypairSpecifierPattern::new_any().arti_pattern()?)?
            .iter()
            .map(|entry| Ok(RelayNtorKeypairSpecifier::try_from(entry.key_path())?.valid_until))
            .collect::<anyhow::Result<_>>()?;
        // Sort in descending order.
        ntor.sort_by(|a, b| b.cmp(a));
        if let Some(&ts) = ntor.first() {
            cache.insert(ExpirableKeyType::NtorLatest, ts);
        }
        if let Some(&ts) = ntor.get(1) {
            cache.insert(ExpirableKeyType::NtorPrevious, ts);
        }

        // Do we have another key after that and if yes, warn that too many exists.
        if ntor.get(2).is_some() {
            tracing::warn!(
                "Found more than 2 NTor keys in the keystore. This is not supposed to happen. Latest two will be used"
            );
        }

        // Who changed here.
        let changed = [
            ExpirableKeyType::LinkEd,
            ExpirableKeyType::RelaysignEd,
            ExpirableKeyType::NtorLatest,
            ExpirableKeyType::NtorPrevious,
        ]
        .into_iter()
        .filter(|ty| self.guard.get(ty) != cache.get(ty))
        .collect();

        *self.guard = cache;
        Ok(changed)
    }
}

/// A full view of all relay keys within the [`KeyMgr`] it holds.
///
/// This keeps the key view that are used accross tasks coherent that is it keeps a cache of
/// valid_until value for expirable keys. Only keys of that valid_until are looked for which makes
/// that each task will always see the same key when doing a lookup.
///
/// That valid_until cache is updated by the crypto task when keys are generated/rotated.
///
/// Domain specific view wrap this view in order to restrict key access.
pub(crate) struct FullKeyView {
    /// The relay key manager.
    keymgr: Arc<KeyMgr>,
    /// The keys' valid_until cache.
    ///
    /// This is used to keep coherence between tasks. All view get to see the same key. This is set
    /// when keys get generated/rotated.
    keys_valid_until: RwLock<HashMap<ExpirableKeyType, Timestamp>>,
}

impl FullKeyView {
    /// Constructor.
    pub(crate) fn new(keymgr: Arc<KeyMgr>) -> Self {
        Self {
            keymgr,
            keys_valid_until: RwLock::new(HashMap::new()),
        }
    }

    /// Return a reference to the [`KeyMgr`]
    // TODO(relay): Remove this as this is only for the code transition of the crypto task rewrite.
    // The keymgr is behind the write lock once all this is done.
    pub(super) fn keymgr(&self) -> &KeyMgr {
        &self.keymgr
    }

    /// Get the valid_until value from the cache for the given key type.
    fn get_valid_until(&self, ty: ExpirableKeyType) -> Result<Option<Timestamp>> {
        let guard = self
            .keys_valid_until
            .read()
            .map_err(|e| anyhow::anyhow!("Poisoned valid_until lock: {e}"))?;
        Ok((*guard).get(&ty).cloned())
    }

    /// Lock the view for write access.
    ///
    /// This is only visible to the crypto task so it can update all valid_until and rotate keys at
    /// once in order to keep the cache coherent with the [`KeyMgr`].
    pub(super) fn lock(&self) -> Result<KeyViewWriteGuard<'_>> {
        let guard = self
            .keys_valid_until
            .write()
            .map_err(|e| anyhow::anyhow!("Poisoned valid_until lock: {e}"))?;
        Ok(KeyViewWriteGuard {
            guard,
            keymgr: &self.keymgr,
        })
    }

    /// Return the relay ed25519 identity keypair (KS_relayid_ed).
    pub(crate) fn ks_relayid_ed(&self) -> Result<RelayIdentityKeypair> {
        self.keymgr
            .get(&RelayIdentityKeypairSpecifier::new())?
            .context("Missing Ed25519 identity")
    }

    /// Return the relay RSA identity keypair (KS_relayid_rsa).
    pub(crate) fn ks_relayid_rsa(&self) -> Result<RelayIdentityRsaKeypair> {
        self.keymgr
            .get(&RelayIdentityRsaKeypairSpecifier::new())?
            .context("Missing RSA identity")
    }

    /// Return the link authentication keypair (KS_link_ed).
    pub(crate) fn ks_link_ed(&self) -> Result<RelayLinkSigningKeypair> {
        let valid_until = self
            .get_valid_until(ExpirableKeyType::LinkEd)?
            .ok_or(anyhow::anyhow!("No link authentication key"))?;
        self.keymgr
            .get(&RelayLinkSigningKeypairSpecifier::new(valid_until))?
            .context("Missing link authentication key")
    }

    /// Return the latest and previous ntor keypairs from the keystore (KS_ntor).
    pub(crate) fn ks_ntor_keys(&self) -> anyhow::Result<RelayNtorKeys> {
        let valid_until = self
            .get_valid_until(ExpirableKeyType::NtorLatest)?
            .ok_or(anyhow::anyhow!("No latest ntor key"))?;
        let latest = self
            .keymgr
            .get(&RelayNtorKeypairSpecifier::new(valid_until))?
            .context("Missing latest ntor key")?;
        let mut keys = RelayNtorKeys::new(latest);

        // Might not have a previous all the time.
        if let Some(valid_until) = self.get_valid_until(ExpirableKeyType::NtorPrevious)? {
            let previous = self
                .keymgr
                .get(&RelayNtorKeypairSpecifier::new(valid_until))?
                .context("Missing previous ntor key")?;
            keys = keys.with_previous(previous);
        }
        Ok(keys)
    }

    /// Return the relay signing key (KS_relaysign_ed).
    pub(crate) fn ks_relaysign_ed(&self) -> Result<RelaySigningKeypair> {
        let valid_until = self
            .get_valid_until(ExpirableKeyType::RelaysignEd)?
            .ok_or(anyhow::anyhow!("No relay signing key"))?;
        self.keymgr
            .get(&RelaySigningKeypairSpecifier::new(valid_until))?
            .context("Missing relay signing key")
    }

    /// Return the relay signing key certificate.
    pub(crate) fn cert_relaysign_ed(&self) -> Result<RelaySigningKeyCert> {
        let valid_until = self
            .get_valid_until(ExpirableKeyType::RelaysignEd)?
            .ok_or(anyhow::anyhow!("No relay signing key"))?;
        let (_key, cert) = self
            .keymgr
            .get_key_and_cert::<RelaySigningKeypair, RelaySigningKeyCert>(
                &RelaySigningKeyCertSpecifier::new(RelaySigningPublicKeySpecifier::new(
                    valid_until,
                )),
                &RelayIdentityKeypairSpecifier::new(),
            )?
            .context("Missing relaysign_ed key and cert")?;
        Ok(cert)
    }
}
