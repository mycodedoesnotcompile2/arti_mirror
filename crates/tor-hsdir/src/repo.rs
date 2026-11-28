//! Repository implementation for hidden service descriptors.

use std::{
    borrow::Cow,
    collections::HashMap,
    sync::{Arc, Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard, TryLockError, Weak},
    time::SystemTime,
};

use tor_error::Bug;
use tor_hscrypto::{RevisionCounter, pk::HsBlindId};
use weak_table::WeakValueHashMap;

use crate::repo::storage::HsDescStorage;

mod enc;
mod keystore;
mod storage;

// TODO: This might want to become private as we integrate with KeyMgr.
pub use enc::DbEncryptionKey;
pub use keystore::KeyStore;
pub use storage::KeyDate;

/// A persistent repository for storing hidden service descriptors on a relay.
///
/// This repository uses an encrypting database to store entries on disk.
//
// NOTE: This type is a wrapper around `HsDescStorage`
// to prevent us from keeping multiple copies of the same HsDesc in RAM
// if we're serving it on a lot of connections at once.
pub struct HsDescRepo {
    /// The inner representation of this repository.
    ///
    /// We take this lock as "read" most of the time.
    /// When it's available for "write",
    /// we opportunistically clean out the "recent" cache as appropriate.
    inner: RwLock<Inner>,
}

/// Inner representation of an [`HsDescRepo`].
///
/// This type is a bit tricky in how it caches entries from the database.
/// (We want to cache entries ourselves,
/// since they need to be decrypted before they can be served,
/// and since we want to de-duplicate the RAM
/// for holding multiple copies of the same descriptor.)
///
/// There are two caches here: `recent` and `serving`.
/// Whenever we read or write hsdesc to the database, we add it to `recent`.
/// We use revision counters to ensure that the most recent version of
/// the hsdesc wins.
///
/// From time to time, we expire entries in `recent`.
/// When we do so, we turn them into weak references and move them to `serving`.
/// That way, we will hold them in RAM (as we must) as long as _somebody_
/// needs them, but we will drop them as soon as nobody wants them any longer.
///
/// ## Guarantees and invariants
///
/// Since we allow multiple `get()`s and `try_insert()`s to run at once, we need
/// to be a bit careful in what we promise.
///
/// Our guarantee is:
/// - once a call to `get()` or `try_insert()` has finished, _subsequent_ `get()`s
///   for the same [`HsBlindId`]
///   will receive a HsDesc with a revision counter _at least as high_ as the
///   one that was returned or added.
///
/// - We don't have two copies of the same hsdesc in RAM at once.
///
/// ## Concurrency
///
/// There are separate locks for `storage` and `cache`.  These locks do not nest!
/// No thread should ever hold both at once.
///
/// There is an overarching RwLock that protects this entire structure.
/// We use that lock to ensure that no other operation can run
/// -- even touching the database --
/// while we are transferring entries from `recent` to `serving`.
/// (Since transferring entries to "serving"
/// can potentially remove them from the cache entirely,
/// we need to make sure that these transfers do not interleave with
/// simultaneous "get" and "try_inserts", which could then get confused.)
///
/// TODO: Explain this better!
struct Inner {
    /// Our underlying persistent storage.
    ///
    /// (This could _logically_ be a RwLock, but sqlite::Connection isn't Sync,
    /// and so we can't actually allow multiple concurrent readers on it.
    /// If we find that we are hitting contention,
    /// we could use a connection pool, or we could
    /// migrate from sqlite to fjall or something else
    /// that supports optimistic concurrency.)
    storage: Mutex<HsDescStorage>,

    /// A cache of decrypted [`HsDesc`] values that we have recently accessed
    /// from the database.
    ///
    /// "None" here represents a negative entry: we looked something up in the database,
    /// and found nothing.
    recent: Mutex<HashMap<HsBlindId, Option<Arc<HsDesc>>>>,

    /// A cache of not-so-recent decrypted [`HsDesc`] values that we are currently serving.
    ///
    /// Using a WeakValueHashMap means that once nobody is serving the HsDesc,
    /// its entry will be lazily freed from this map.
    ///
    /// If an entry for the same Id is present here and in `recent`,
    /// the one in `recent` is correct.
    serving: WeakValueHashMap<HsBlindId, Weak<HsDesc>>,
}

/// An (unparsed) HsDesc entry returned from an [`HsDescRepo`].
//
// TODO: Participate in memory quota system?
#[derive(Clone, Debug)]
pub struct HsDesc {
    /// The revision counter for this entry.
    revision_counter: RevisionCounter,

    /// The time at which this entry expires.
    expiration: SystemTime,

    /// The contents of this entry.
    body: Box<str>,
}

impl AsRef<str> for HsDesc {
    fn as_ref(&self) -> &str {
        self.body.as_ref()
    }
}

/// Metadata used when inserting an HsDesc entry into an [`HsDescRepo`].
///
/// This information should be derived from parsing the outer layer of the HsDesc.
#[derive(Clone, Debug)]
#[allow(clippy::exhaustive_structs)]
pub struct HsDescMeta {
    /// Blinded HsId key: used by clients when requesting the descriptor.
    pub blind_id: HsBlindId,

    /// The revision counter for this descriptor.
    pub revision_counter: RevisionCounter,

    /// The time at which this descriptor should expire.
    pub expiration: SystemTime,
}

/// A possible outcome from inserting a reasonable-looking hidden service descriptor.
#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum InsertStatus {
    /// There was no other descriptor with the same HsBlindId,
    /// or this descriptor had a higher revision counter:
    /// It has been inserted.
    Inserted,

    /// There was an existing descriptor with the same HsBlindId
    /// and a greater or equal revision counter:
    /// the descriptor was not inserted.
    Superseded,
}

impl HsDescRepo {
    /// Construct a new [`HsDescRepo`] from a database connection,
    /// to access HsDescs starting `now`,
    /// storing any database keys in `keystore`.
    //
    // TODO: This is a dubious API and we should create a public wrapper for it that behaves more
    // sensibly.
    #[allow(unused)]
    pub(crate) fn from_connection<KS: KeyStore>(
        conn: rusqlite::Connection,
        now: SystemTime,
        keystore: &KS,
    ) -> Result<Self, RepoError> {
        let serving = WeakValueHashMap::new();
        let storage = Mutex::new(HsDescStorage::from_connection(conn, now, keystore)?);
        let recent = Mutex::new(HashMap::new());
        Ok(Self {
            inner: RwLock::new(Inner {
                serving,
                storage,
                recent,
            }),
        })
    }

    /// Return a read-guard over `inner`, opportunistically removing entries from the
    /// "recent" cache.
    fn get_inner(inner: &RwLock<Inner>) -> RwLockReadGuard<Inner> {
        /// Number of entries to retain in `recent`.
        //
        // TODO: We should make this higher, and probably make it configurable.
        // Right now it is at zero in order to ensure the greatest amount of racing in our test code.
        const RETAIN_IN_RECENT: usize = 0;

        match inner.try_write() {
            Err(TryLockError::Poisoned(e)) => panic!("Poisoned lock! {e}"),
            Err(TryLockError::WouldBlock) => {
                // Somebody else has the write lock we just get a read lock instead.
                inner.read().expect("poisoned lock")
            }
            Ok(mut inner_w) => {
                // We got the write lock! Let's be quick with it.
                //
                // (If we decide that trying for the write lock at all is too slow,
                // we could use an atomic counter for the number of members in recent,
                // but let's not do that unless it's actually needed.)

                // We use a destructuring pattern-match here so we can use "recent" and "serving" at the same time.
                let Inner {
                    ref mut serving,
                    ref recent,
                    ..
                } = *inner_w;

                let mut recent = recent.lock().expect("Poisoned lock");
                if recent.len() > RETAIN_IN_RECENT * 2 {
                    let n_to_remove = recent.len() - RETAIN_IN_RECENT;
                    // (We use extract_if here to remove entries more or less arbitrarily.  In the
                    // future we might use a smarter removal algorithm, but this is probably fine.)
                    for (k, v) in recent.extract_if(|_, _| true).take(n_to_remove) {
                        match v {
                            Some(v) => serving.insert(k, v),
                            None => serving.remove(&k),
                        };
                    }
                }
                drop(recent); // must do this explicitly or else we still hold this lock when we try to downgrade.
                RwLockWriteGuard::downgrade(inner_w)
            }
        }
    }

    /// Return the [`HsDesc`] entry for `blind_id`, if there is one.
    ///
    /// If there is no entry, or the entry is expired at `now`, return None.
    ///
    /// If `now` is None, don't check expiry.
    pub fn get(
        &self,
        blind_id: &HsBlindId,
        now: Option<SystemTime>,
    ) -> Result<Option<Arc<HsDesc>>, RepoError> {
        use std::collections::hash_map::Entry;

        let inner = Self::get_inner(&self.inner);

        // Part one: see if we have an existing entry in the cache.
        {
            let mut recent_cache = inner.recent.lock().expect("Poisoned lock");
            let recent_entry = recent_cache.entry(*blind_id);
            let (cached, was_recent) = if let Entry::Occupied(occupied) = &recent_entry {
                // Check recent first...
                match occupied.get() {
                    None => return Ok(None), // Cached negative entry: nothing to do but return it.
                    Some(hsdesc) => (Some(Arc::clone(hsdesc)), true),
                }
            } else {
                // ... and _then_ check serving.
                (inner.serving.get(blind_id), false)
            };

            if let Some(cached) = cached {
                if let Some(now) = now
                    && cached.expiration < now
                {
                    // In this case should we add a negative entry to the recent_cache?
                    return Ok(None);
                }

                if !was_recent {
                    // We've been asked for this item, so now it counts as recent.
                    recent_entry.insert_entry(Some(Arc::clone(&cached)));
                }

                return Ok(Some(cached));
            }
        }

        // Part two: See if there is an entry in storage.
        //
        // (We get the storage lock here, and we don't touch the cache!)
        let answer = {
            let storage = inner.storage.lock().expect("Poisoned lock");
            storage.get(blind_id, now)?.map(Arc::new)
        };

        // Part three: add to "recent".
        {
            match inner.recent.lock().expect("Poisoned lock").entry(*blind_id) {
                Entry::Occupied(mut occupied) => match (&answer, occupied.get()) {
                    (Some(from_db), Some(in_cache)) => {
                        if in_cache.revision_counter > from_db.revision_counter {
                            return Ok(Some(Arc::clone(in_cache)));
                        } else {
                            occupied.insert(answer.clone());
                        }
                    }
                    (Some(_from_db), None) => {
                        occupied.insert(answer.clone());
                    }
                    (None, Some(in_cache)) => {
                        return Ok(Some(Arc::clone(in_cache)));
                    }
                    (None, None) => {}
                },
                Entry::Vacant(vacant) => {
                    vacant.insert(answer.clone());
                }
            }
        }

        Ok(answer)
    }

    /// Try to insert a `body` into storage for the descriptor described in `meta`.
    ///
    /// Return an `InsertStatus` describing the results of this insertion.
    ///
    /// Note that if this method returns Superseded, then the superseding hsdesc
    /// _might not yet be visible in the cache_ after this method returns.
    /// That's okay.
    pub fn try_insert(&self, meta: &HsDescMeta, body: &str) -> Result<InsertStatus, RepoError> {
        use InsertStatus::*;
        let inner = Self::get_inner(&self.inner);

        // Step one: Check if there is an entry in the cache with a better revision counter.
        // If so, stop early.
        //
        // (We get the cache lock here, and we don't touch the storage!)
        {
            if let Some(serving) = inner.serving.get(&meta.blind_id)
                && serving.revision_counter >= meta.revision_counter
            {
                return Ok(Superseded);
            }

            if let Some(Some(recent)) = inner
                .recent
                .lock()
                .expect("Poisoned lock")
                .get(&meta.blind_id)
                && recent.revision_counter >= meta.revision_counter
            {
                return Ok(Superseded);
            }
        };

        // Step two: see if we can insert this into the storage.
        //
        // While this is happening, the cache still holds the previous value (if any) for
        // this descriptor's HsBlindId, but that's okay.
        //
        // (We get the storage lock here, and we don't touch the cache!)
        {
            let mut storage = inner.storage.lock().expect("Poisoned lock");

            if storage.try_insert(meta, body)? == Superseded {
                // The database didn't want it; there is a more recent one.
                //
                // (TODO: It may be appropriate to update 'recent' here.)
                return Ok(Superseded);
            };
        }

        // Step three: Add the entry to "recent" the cache, if appropriate.
        //
        // (We get the cache lock here, and we don't touch the storage!)
        {
            // Since a race is possible, we need to compare revision counters
            // to see if a more recent entry has been added to the cache.
            use std::collections::hash_map::Entry;

            let mut cache = inner.recent.lock().expect("Lock poisoned");
            match cache.entry(meta.blind_id) {
                Entry::Occupied(mut occupied) => {
                    let other = occupied.get();
                    if let Some(other) = other
                        && other.revision_counter > meta.revision_counter
                    {
                        // Another thread has added a better entry for this HsBlindId,
                        // and persisted it to disk!
                        // (They must have done so after we released the storage lock but before
                        // we got the cache lock.)
                        Ok(InsertStatus::Superseded)
                    } else {
                        // The entry we inserted was better than the one in the cache;
                        // drop that entry from the cache.
                        occupied.insert(Some(Arc::new(HsDesc {
                            revision_counter: meta.revision_counter,
                            expiration: meta.expiration,
                            body: body.into(),
                        })));
                        Ok(InsertStatus::Inserted)
                    }
                }
                Entry::Vacant(vacant) => {
                    vacant.insert(Some(Arc::new(HsDesc {
                        revision_counter: meta.revision_counter,
                        expiration: meta.expiration,
                        body: body.into(),
                    })));
                    Ok(InsertStatus::Inserted)
                }
            }
        }
    }

    // TODO: Expire old entries in the database.
}

/// An error from an [`HsDescRepo`].
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RepoError {
    /// The database reported an error.
    #[error("A database error occurred")]
    Sqlite(Arc<rusqlite::Error>),

    /// We found an existing database that didn't declare its schema in a way we recognized.
    #[error("Existing database with unrecognized format")]
    UnrecognizedSchema,

    /// We found something in the database that we couldn't decode or understand.
    #[error("Invalid data in database: {0}")]
    InvalidData(Cow<'static, str>),

    /// We were unable to decrypt an entry.
    ///
    /// (This is usually a bug.)
    #[error("Unable to decrypt database entry")]
    Decrypt(#[from] enc::DecryptError),

    /// We were unable to encrypt an entry to store it.
    ///
    /// (This is always a bug.)
    #[error("Unable to encrypt database entry")]
    Encrypt(#[source] Bug),

    /// We tried to insert a descriptor whose
    #[error("Expiration time out of bounds for inserted data")]
    UntimelyInsert,

    /// We found invalid UTF-8 after decrypting a database entry.
    #[error("Invalid UTF-8 in database")]
    InvalidUtf8Data(#[from] std::string::FromUtf8Error),

    /// We tried to instantiate a database key for some date
    /// after the latest date supported by the [`time`] crate.
    //
    // As of this writing, `time` allows up to 9999-12-31,
    // so if you run into this, either `time` has been revised,
    // your clock is set wrong, or you are running `arti`
    // far in the distant future.
    #[error("Tried to compute a date beyond time::Date::MAX")]
    EndOfTime,
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    #![allow(clippy::string_slice)] // See arti#2571
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use std::{collections::VecDeque, time::Duration};

    use rand::RngExt;
    use tor_basic_utils::RngExt as _;

    use super::*;

    struct Concurrent {
        id: HsBlindId,
        persist: Mutex<VecDeque<Arc<HsDesc>>>,
        repo: HsDescRepo,
    }

    impl Concurrent {
        fn lets_race(&self, n: usize, now: SystemTime) -> Result<(), RepoError> {
            let mut last_revctr_seen = 1000;
            let mut rng = rand::rng();
            for _ in 0..n {
                let revctr_to_add = last_revctr_seen + 1;
                let exp_seconds = rng.gen_range_checked(3600..12 * 3600).unwrap();
                let meta = HsDescMeta {
                    blind_id: self.id,
                    revision_counter: RevisionCounter::from(revctr_to_add),
                    expiration: now + Duration::new(exp_seconds, 0),
                };

                let outcome = self.repo.try_insert(
                    &meta,
                    &format!("This is the entry with revctr {:?}", meta.revision_counter),
                )?;

                let got = self.repo.get(&self.id, None)?.unwrap();
                if outcome == InsertStatus::Inserted {
                    assert!(*got.revision_counter >= revctr_to_add);
                }
                assert!(*got.revision_counter >= last_revctr_seen);
                assert_eq!(
                    got.as_ref().as_ref(),
                    &format!("This is the entry with revctr {:?}", got.revision_counter)
                );
                last_revctr_seen = *got.revision_counter;

                {
                    let mut p = self.persist.lock().unwrap();
                    p.push_back(got);
                    while p.len() > 64 {
                        p.pop_front();
                    }
                }
            }
            Ok(())
        }
    }

    #[test]
    fn test_racing() {
        let mut rng = rand::rng();
        // Chosen so that times will be split across two days.
        let now = time::macros::utc_datetime!(2026-11-16 22:00).into();
        let keystore = keystore::ephemeral::EphemeralKeystore::new();

        let concurrent = Concurrent {
            persist: Default::default(),
            id: HsBlindId::from(rng.random::<[u8; 32]>()),
            repo: HsDescRepo::from_connection(
                rusqlite::Connection::open_in_memory().unwrap(),
                now,
                &keystore,
            )
            .unwrap(),
        };

        std::thread::scope(|s| {
            let handles: Vec<_> = (0..16)
                .map(|_| s.spawn(|| concurrent.lets_race(200, now)))
                .collect();

            for h in handles {
                let _: () = h.join().unwrap().unwrap();
            }
        });
    }
}
