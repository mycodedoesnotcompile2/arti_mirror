//! Define a trait for accessing HsDesc database keys.

use std::sync::Arc;

use crate::repo::{RepoError, enc::DbEncryptionKey, storage::KeyDate};

/// An abstract trait for accessing HsDesc database keys.
///
/// In practice, this wraps an ordinary key manager.
/// We also allow it to be ephemeral, for testing.
pub trait KeyStore {
    /// Return a key corresponding to HsDescs that expire on `date`.
    ///
    /// If no key for that date exists, create one, remember it, and return it.
    fn get_or_create_key(&self, date: KeyDate) -> Result<Arc<DbEncryptionKey>, RepoError>;

    /// Delete all keys that are older than `date`.
    fn delete_keys_older_than(&self, date: KeyDate) -> Result<(), RepoError>;
}

/// Test only: ephemeral KeyStore.
#[cfg(test)]
pub(crate) mod ephemeral {
    use super::*;
    use std::{
        collections::{BTreeMap, btree_map::Entry},
        sync::Mutex,
    };

    /// An ephemeral KeyStore: It holds keys in memory.
    pub(crate) struct EphemeralKeystore {
        map: Mutex<BTreeMap<KeyDate, Arc<DbEncryptionKey>>>,
    }

    impl EphemeralKeystore {
        /// Create a new ephemeral keystore.
        pub(crate) fn new() -> Self {
            Self {
                map: Mutex::new(BTreeMap::new()),
            }
        }
    }

    impl super::KeyStore for EphemeralKeystore {
        fn get_or_create_key(
            &self,
            date: KeyDate,
        ) -> Result<Arc<crate::repo::enc::DbEncryptionKey>, crate::repo::RepoError> {
            match self.map.lock().expect("lock poisoned").entry(date) {
                Entry::Vacant(vac) => {
                    let new_key = Arc::new(DbEncryptionKey::new(date));
                    vac.insert_entry(Arc::clone(&new_key));
                    Ok(new_key)
                }
                Entry::Occupied(occ) => Ok(Arc::clone(occ.get())),
            }
        }

        fn delete_keys_older_than(&self, date: KeyDate) -> Result<(), crate::repo::RepoError> {
            let mut map = self.map.lock().expect("lock poisoned");
            let on_date_or_after = map.split_off(&date);
            *map = on_date_or_after;
            Ok(())
        }
    }
}
