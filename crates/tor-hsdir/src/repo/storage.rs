//! Encrypted storage for HsDescs, backed by a sqlite database.
//!
//! # Design
//!
//! In arti, hsdir entries are persistent and saved on disk.
//! This allows us to avoid some kinds of DoS attack
//! (where RAM gets filled up with hsdescs), and to provide more availability across restarts.
//!
//! Doing this securely will cost some complexity, however.
//! We want to avoid[^best-effort] hsdescs persisting in plaintext on disk.
//! To solve this, we encrypt hsdescs in storage.
//! We change the encryption key for each day,
//! so that any residual storage in the database is unrecoverable.
//!
//! (In addition to encrypting the hsdescs,
//! we also encrypt their [`RevisionCounter`]s,
//! since the revision counters could in theory leak which descriptors were which.
//! This is probably overkill!)
//!
//! Furthermore, we use a keyed hash to derive
//! the database index for each HsDesc from its [`HsBlindId`].
//! This also helps conceal which HsDescs we have.
//! These keys are also rotated daily.
//!
//! ## Keys and dates
//!
//! HsDesc expiration times work a bit oddly:
//! They are given in a number of minutes (30..720) _after_ the descriptor is uploaded.
//! Therefore, the latest time that any hsdesc can expire is "tomorrow at noon UTC".
//! Because of this, we keep two keys around at any given time:
//! one for hsdescs that expire today, and one for hsdescs that expire tomorrow.
//!
//! [^best-effort]: This is a best-effort goal only.
//!   Reading v3 hsdescs doesn't actually gain the attacker very much
//!   unless they happen to know the real [`HsId`] keys for the onion service;
//!   and if they knew those, they could just fetch the hsdescs in realtime.
//!
//! [`HsId`]: tor_hscrypto::pk::HsId
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use base64ct::Encoding;
use rusqlite::{OptionalExtension as _, params};
use saturating_time::SaturatingTime;
use subtle::ConstantTimeEq;
use time::UtcDateTime;
use tor_hscrypto::{RevisionCounter, pk::HsBlindId};
use tor_llcrypto::util::ct::ct_lookup_idx;
use zeroize::Zeroizing;

use crate::repo::{
    HsDesc, HsDescMeta, InsertStatus, RepoError,
    enc::{self, DbEncryptionKey},
    keystore::KeyStore,
};

/// Underlying encrypted storage for HsDescs
pub(crate) struct HsDescStorage {
    /// A connection to a sqlite database holding HsDescs.
    conn: rusqlite::Connection,

    /// A pair of encryption keys: the first is for HsDescs that expire "today",
    /// and the second is for HsDescs that expire "tomorrow".
    ///
    /// (The longest possible HsDesc expiration interval is 720 minutes from "now",
    /// so we don't need to store anything that will expire after "tomorrow".)
    keys: [Arc<enc::DbEncryptionKey>; 2],
}

/// An identifier for a HsDesc identity in the database.
///
/// This is formed by hashing a secret key together with a [`HsBlindId`],
/// so that once the key is deleted,
/// we can't tell which entries corresponded to which HsDescs.
#[derive(Clone)]
pub(crate) struct DbId(pub(crate) Zeroizing<[u8; 32]>);

impl subtle::ConstantTimeEq for DbId {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&*other.0)
    }
}

impl DbId {
    /// Return a unique base64-encoding for this [`DbId`].
    fn to_b64(&self) -> String {
        base64ct::Base64Unpadded::encode_string(self.0.as_ref())
    }
}

/// A hsdesc expiration date for which a single database encryption key is valid.
#[derive(Clone, Debug, Copy)]
#[cfg_attr(test, derive(PartialEq, Eq, PartialOrd, Ord))] // testing only because not CT.
pub struct KeyDate(pub(crate) time::Date);

impl KeyDate {
    /// Create a new [`KeyDate`] containing a given [`SystemTime`]
    fn new_containing(when: SystemTime) -> KeyDate {
        Self(UtcDateTime::from(when).date())
    }

    /// Return the next [`KeyDate`] after this one.
    ///
    /// Returns None if this is the latest representable date.
    fn next(&self) -> Option<KeyDate> {
        Some(Self(self.0.next_day()?))
    }

    /// Return the earliest representable time (midnight) on this date.
    fn start_of_day(&self) -> SystemTime {
        UtcDateTime::new(self.0, time::Time::MIDNIGHT).into()
    }

    /// Return the latest representable time (one second before midnight) on this date.
    fn end_of_day(&self) -> SystemTime {
        UtcDateTime::new(self.0, time::Time::MAX).into()
    }
}

impl subtle::ConstantTimeEq for KeyDate {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        // NOTE: converting "to_ordinal_date" here isn't actually needed:
        // Internally, [`time::Date`] stores its values as a u32,
        // so the built-in comparison would already probably be constant time.
        // But we don't want to depend on their implementation,
        // since they might change it in the future.
        let (year1, day1) = self.0.to_ordinal_date();
        let (year2, day2) = other.0.to_ordinal_date();
        year1.ct_eq(&year2) & day1.ct_eq(&day2)
    }
}

/// Helper: Given an expiration date and a slice of keys,
/// return the _index_ of the key corresponding to that date.
///
/// Returns None if no key in `keys` has the right expiration date.
///
/// Runs in constant time[^1], which is probably not necessary.
///
/// NOTE: This function returns an index instead of a key because:
///  - There are borrowing issues that we want to avoid.
///  - We sometimes want to use this to index arrays other than `keys`.
///
/// [^1]: subject to provisos on [`ct_lookup_idx`]
fn key_idx_for_expiration(keys: &[Arc<DbEncryptionKey>], day: KeyDate) -> Option<usize> {
    ct_lookup_idx(keys, |key| key.date().ct_eq(&day))
}

impl HsDescStorage {
    /// Initialize a new [`HsDescStorage`] from a database connection, and a keystore.
    pub(crate) fn from_connection<KS: KeyStore>(
        conn: rusqlite::Connection,
        now: SystemTime,
        keystore: &KS,
    ) -> Result<Self, RepoError> {
        // sqlite (as of Jun 2024) does not enforce foreign keys automatically unless you set this
        // pragma on the connection.
        // We don't have any foreign keys in this schema right now, but "belt and suspenders".
        conn.pragma_update(None, "foreign_keys", "ON")?;

        let today = KeyDate::new_containing(now);
        let tomorrow = today.next().ok_or(RepoError::EndOfTime)?;
        let mut db: HsDescStorage = Self {
            conn,
            keys: [
                keystore.get_or_create_key(today)?,
                keystore.get_or_create_key(tomorrow)?,
            ],
        };
        db.initialize()?;
        db.remove_expired(now)?;
        keystore.delete_keys_older_than(today)?;
        Ok(db)
    }

    /// Return the next time at which we should rotate our keys.
    pub(crate) fn rotation_time(&self) -> SystemTime {
        self.keys[1].date().start_of_day()
    }

    /// If `now` is late enough, update our keys based on `now`, creating them if necessary.
    pub(crate) fn rotate_keys_if_needed<KS: KeyStore>(
        &mut self,
        now: SystemTime,
        keystore: &KS,
    ) -> Result<bool, RepoError> {
        let today = KeyDate::new_containing(now);
        if today.ct_eq(&self.keys[0].date()).into() {
            return Ok(false);
        }
        let tomorrow = today.next().ok_or(RepoError::EndOfTime)?;

        // Rather than conditionally move keys[1] into keys[0],
        // we rely on the keystore to give us today's key again.
        self.keys = [
            keystore.get_or_create_key(today)?,
            keystore.get_or_create_key(tomorrow)?,
        ];
        keystore.delete_keys_older_than(today)?;

        Ok(true)
    }

    /// Helper: create the sqlite database schema if it is not already there.
    fn initialize(&mut self) -> Result<(), RepoError> {
        let tx = self.conn.transaction()?;

        // If we have any tables, then the database already exists.
        let db_n_tables: u32 = tx.query_row(
            "SELECT COUNT(name) FROM sqlite_master
             WHERE type='table'
             AND name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )?;
        let db_exists = db_n_tables > 0;

        if db_exists {
            // If the database exists, check the schema; it had better be "1" for now.
            //
            // (This can also fail if this is the wrong kind of database, but that's _probably_ okay?)
            let schema_version: u32 = tx.query_row(CHECK_SCHEMA, [], |row| row.get(0))?;
            if schema_version != 1 {
                return Err(RepoError::UnrecognizedSchema);
            }
        } else {
            // No database; time to install it.
            tx.execute_batch(INSTALL_SCHEMA)?;
        }
        tx.commit()?;

        Ok(())
    }

    /// Given an HsBlindId,
    /// return the two encrypted positions at which we might find it,
    /// depending on when it expires.
    fn derive_db_ids(&self, blind_id: &HsBlindId) -> [DbId; 2] {
        [
            self.keys[0].derive_index(blind_id),
            self.keys[1].derive_index(blind_id),
        ]
    }

    /// Remove every entry that has expired before `now`.
    pub(crate) fn remove_expired(&mut self, now: SystemTime) -> Result<(), RepoError> {
        let now = UtcDateTime::from(now);
        self.conn.execute(EXPIRE_ENTRIES, params![now])?;
        Ok(())
    }

    /// If there is an entry for `blind_id`, and it has not expired by `now`, return it.
    ///
    /// If `now` is None, then ignore the expiration time.
    pub(crate) fn get(
        &self,
        blind_id: &HsBlindId,
        now: Option<SystemTime>,
    ) -> Result<Option<HsDesc>, RepoError> {
        let db_ids = self.derive_db_ids(blind_id);

        // We have to search for the entry at two points, since it might expire today _or_ tomorrow.
        // But it will only be present at one point, so `query_row` is okay.
        let r: Option<(UtcDateTime, Box<[u8]>)> = self
            .conn
            .query_row(
                FIND_ENTRY,
                params![db_ids[0].to_b64(), db_ids[1].to_b64()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;

        let Some((expiration, ciphertext)) = r else {
            // No entry at all.
            return Ok(None);
        };

        if let Some(now) = now {
            if now > expiration {
                // This entry has expired.
                return Ok(None);
            }
        }

        // Determine which key to use to decrypt the entry, based on its expiration date.
        let Some(use_key_idx) = key_idx_for_expiration(&self.keys, KeyDate(expiration.date()))
        else {
            return Ok(None);
        };

        let use_key = &self.keys[use_key_idx];
        let db_id = &db_ids[use_key_idx];

        let (revision_counter, body) = decode_entry(&use_key.decrypt_entry(db_id, &ciphertext)?)?;

        Ok(Some(HsDesc {
            revision_counter,
            expiration: expiration.into(),
            body,
        }))
    }

    /// If appropriate, try to insert the text at `text` for the HsDesc described by `meta`.
    ///
    /// Returns `Ok(`[`InsertStatus::Inserted`]`)` if the entry was successfully added,
    /// and `Ok(`[`InsertStatus::Superseded`]`)` if there was already an entry
    /// for the same [`HsBlindId`] whose revision counter was equal or greater.
    pub(crate) fn try_insert(
        &mut self,
        meta: &HsDescMeta,
        text: &str,
    ) -> Result<InsertStatus, RepoError> {
        let expires = round_expiration(meta.expiration);

        let Some(use_key_idx) = key_idx_for_expiration(&self.keys, KeyDate(expires.date())) else {
            // We have no key for this expiration date, so it is either "before today" or "after
            // tomorrow". Either way,
            return Err(RepoError::UntimelyInsert);
        };
        let db_ids = self.derive_db_ids(&meta.blind_id);
        let db_ids_b64 = [db_ids[0].to_b64(), db_ids[1].to_b64()];

        let tx = self.conn.transaction()?;

        // We have to see if the entry is present at either possible DbId;
        // and if it is, we need to check its revision counter.
        let r: Option<(UtcDateTime, Box<[u8]>)> = tx
            .query_row(FIND_ENTRY, params![&db_ids_b64[0], &db_ids_b64[1]], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .optional()?;

        if let Some((old_expiration, encrypted)) = r {
            if let Some(old_key_idx) =
                key_idx_for_expiration(&self.keys, KeyDate(old_expiration.date()))
            {
                let (prev_revctr, _) = decode_entry(
                    &self.keys[old_key_idx].decrypt_entry(&db_ids[old_key_idx], &encrypted)?,
                )?;
                if prev_revctr >= meta.revision_counter {
                    // The old value had a revision counter as new or newer; discard this one.
                    return Ok(InsertStatus::Superseded);
                }

                // We need to delete the old value if its DbId is not the same as this.
                if use_key_idx != old_key_idx {
                    tx.execute(DELETE_BY_DB_ID, params![&db_ids_b64[old_key_idx]])?;
                }
            } else {
                // This should be unreachable: There was a value at one of the DbIds we had,
                // but its expiration date was not the right date for either!
                // This means database corruption or 256-bit collision.
                // Either way, we can just let this entry get removed by expiration.
            }
        }

        // Encrypt the new entry and write it into the DB.
        let encrypted = self.keys[use_key_idx]
            .encrypt_entry(
                &db_ids[use_key_idx],
                &encode_entry(meta.revision_counter, text),
            )
            .map_err(RepoError::Encrypt)?;

        tx.execute(
            INSERT_ENTRY,
            params![db_ids_b64[use_key_idx], expires, &encrypted[..],],
        )?;

        tx.commit()?;

        Ok(InsertStatus::Inserted)
    }
}

impl From<rusqlite::Error> for RepoError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(Arc::new(value))
    }
}

/// Round `t` forward to a reasonably course amount,
/// to avoid leaking the upload times of individual descriptors.
///
/// (Note: this would round times near the end of "tomorrow" to the day after.
/// But since the maximum expiration interval in an hsdesc is 720 minutes,
/// no hsdesc will actually expire in the final minutes of "tomorrow".)
#[allow(unstable_name_collisions)] // For saturating_duration_since
fn round_expiration(t: SystemTime) -> UtcDateTime {
    /// To what granularity will we run the time, in seconds?
    const SECONDS_GRANULARITY: u64 = 60 * 10;

    let sec_since_epoch: u64 = t
        .saturating_duration_since(SystemTime::UNIX_EPOCH)
        .as_secs();
    let dur_expiration = sec_since_epoch
        .checked_next_multiple_of(SECONDS_GRANULARITY)
        .map(|s| Duration::new(s, 0))
        .unwrap_or(Duration::MAX);
    let expiration = SystemTime::UNIX_EPOCH.saturating_add(dur_expiration);
    UtcDateTime::from(expiration).truncate_to_minute()
}

/// Return a byte encoding of a revision counter and hsdesc body, ready to encrypt.
//
// TODO: do we want to pad these to the next 512 bytes or something to avoid leaking their length
// when we store them? Or is that overkill?
fn encode_entry(revision_counter: RevisionCounter, body: &str) -> Box<[u8]> {
    let length_out = 8 + body.len();
    let mut out = Vec::with_capacity(length_out);
    out.extend_from_slice(&u64::from(revision_counter).to_be_bytes());
    out.extend_from_slice(body.as_bytes());

    debug_assert_eq!(out.len(), length_out);
    out.into_boxed_slice()
}

/// Given a value returned by `encode_entry`, transform it bask in to a revision counter and hsdesc body.
///
/// Return an error if the input is too short, or if its utf-8 is invalid.
fn decode_entry(encoded: &[u8]) -> Result<(RevisionCounter, Box<str>), RepoError> {
    let (rc, body) = encoded
        .split_at_checked(8)
        .ok_or_else(|| RepoError::InvalidData("plaintext data too short".into()))?;
    let rc = RevisionCounter::from(u64::from_be_bytes(rc.try_into().expect("8 != 8!?")));

    let body = String::from_utf8(body.into())?.into();

    Ok((rc, body))
}

/// SQL command: find the declared version of the database schema.
const CHECK_SCHEMA: &str = "
    SELECT schema_version FROM HsDescSchema;
";

/// SQL commands: Create the tables and indices for the database schema.
const INSTALL_SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS HsDescSchema (
        -- A single number indicating our version.
        schema_version INTEGER
    );

    INSERT INTO HsDescSchema (schema_version) VALUES ( 1 );

    CREATE TABLE IF NOT EXISTS HsDescriptors (
        -- A DbId, encoded in unpadded base64
        id TEXT NOT NULL PRIMARY KEY,

        -- The time when this entry expires, rounded.
        expires DATE NOT NULL,

        -- An encrypted blob containing the revision counter and hsdesc text,
        -- as returned by `encrypt_entry(encode_entry(..))`.
        encrypted BLOB NOT NULL
    );

    -- This index helps expire entries.  We probably don't need it, but it won't hurt.
    CREATE INDEX IF NOT EXISTS HsDescriptorsByExpiration ON HsDescriptors(expires);
";

/// SQL command: Remove every entry that has expired before a given time.
const EXPIRE_ENTRIES: &str = "
    DELETE FROM HsDescriptors WHERE expires < ?;
";

/// SQL command: return the entry with one of two base64-encoded [`DbId`]s.
///
/// (We always look at two positions because, when we look for an entry,
/// we don't know whether it will expire today or tomorrow,
/// and so we don't know which [`DbId`] it has.)
///
/// ## On 'limit 1'
///
/// We will never find both DbIds for a given [`HsBlindId`] unless:
///
/// - There has been a 256-bit collision
///   where two two [`HsBlindId`]s received the same [`DbId`].
/// - OR, we have failed to delete the entry with a lower revision counter
///   when we insert the new one.
///
/// In both cases, it's reasonable to return an entry arbitrarily.
const FIND_ENTRY: &str = "
    SELECT expires, encrypted FROM HsDescriptors WHERE id = ? OR id = ?
    LIMIT 1;
";

/// SQL command: remove the entry with a given base64-encoded [`DbId`].
const DELETE_BY_DB_ID: &str = "
    DELETE FROM HsDescriptors WHERE id = ?;
";

/// SQL command: insert an entry into the database.
const INSERT_ENTRY: &str = "
    INSERT OR REPLACE INTO HsDescriptors(id, expires, encrypted)
    VALUES ( ?, ?, ? );
";

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

    use crate::repo::keystore::ephemeral::EphemeralKeystore;

    use super::*;
    use rand::RngExt as _;
    use std::{assert_matches, collections::HashSet};
    use time::macros::{date, utc_datetime};

    #[test]
    fn keydate_basics() {
        let now = utc_datetime!(2008-08-02 17:00:25);
        let d = KeyDate::new_containing(now.into());
        assert_eq!(d.0, date!(2008 - 08 - 02));
        let d2 = d.next().unwrap();
        assert_eq!(d2.0, date!(2008 - 08 - 03));

        assert_eq!(
            d2.start_of_day(),
            SystemTime::from(utc_datetime!(2008-08-03 00:00:00))
        );
        assert_eq!(
            d2.end_of_day(),
            SystemTime::from(utc_datetime!(2008-08-03 23:59:59.999_999_999))
        );
    }

    #[test]
    fn test_simple() {
        let now = utc_datetime!(2008-08-02 17:00:25);
        let ks = EphemeralKeystore::new();
        let mut store = HsDescStorage::from_connection(
            rusqlite::Connection::open_in_memory().unwrap(),
            now.into(),
            &ks,
        )
        .unwrap();

        let k = HsBlindId::from([12; 32]);
        let rc = RevisionCounter::from(99);
        let r = store
            .try_insert(
                &HsDescMeta {
                    blind_id: k,
                    revision_counter: rc,
                    expiration: utc_datetime!(2008-08-02 19:00).into(),
                },
                "Hello world!",
            )
            .unwrap();
        assert_eq!(r, InsertStatus::Inserted);

        let d = store.get(&k, None).unwrap();
        let d = d.unwrap();
        assert_eq!(d.body.as_ref(), "Hello world!");
        assert_eq!(d.revision_counter, RevisionCounter::from(99));
        assert_eq!(
            d.expiration,
            round_expiration(utc_datetime!(2008-08-02 19:00).into())
        );
        // check: Same day, but expired.
        let d = store
            .get(&k, Some(utc_datetime!(2008-08-02 20:00).into()))
            .unwrap();
        assert!(d.is_none());
    }

    #[test]
    fn test_reload() {
        let now = utc_datetime!(2008-08-02 17:00:25);
        let mut rng = rand::rng();
        let ks = EphemeralKeystore::new();

        let tmpdir = tempfile::TempDir::new().unwrap();
        let dbpath = tmpdir.as_ref().join("db.sqlite");
        let mut store = HsDescStorage::from_connection(
            rusqlite::Connection::open(&dbpath).unwrap(),
            now.into(),
            &ks,
        )
        .unwrap();

        // Note: Here, and in other tests, (and in the tor hs design itself!)
        // we assume that HsBlindId will never accidentally collide.
        // Since they are 256 bits[^1] long, that's a safe assumption.
        //
        // [^1]: minus a couple for ed25519 silliness
        let ids: HashSet<_> = (0..100)
            .map(|_| HsBlindId::from(rng.random::<[u8; 32]>()))
            .collect();
        let rc = RevisionCounter::from(99);
        for id in &ids {
            let r = store
                .try_insert(
                    &HsDescMeta {
                        blind_id: *id,
                        revision_counter: rc,
                        expiration: utc_datetime!(2008-08-02 19:00).into(),
                    },
                    &format!("Hello world {:?}!", id.as_ref()),
                )
                .unwrap();
            assert_eq!(r, InsertStatus::Inserted);
        }
        drop(store);

        // Now create a new store and make sure that it works.
        let store = HsDescStorage::from_connection(
            rusqlite::Connection::open(&dbpath).unwrap(),
            now.into(),
            &ks,
        )
        .unwrap();
        for id in &ids {
            let d = store.get(id, None).unwrap();
            let d = d.unwrap();
            assert_eq!(d.body.as_ref(), format!("Hello world {:?}!", id.as_ref()));
        }
        for _ in 0..10 {
            let other_id = HsBlindId::from(rng.random::<[u8; 32]>());
            let d = store.get(&other_id, None).unwrap();
            assert!(d.is_none());
        }
    }

    #[test]
    fn test_overwrite() {
        let now = utc_datetime!(2008-08-02 17:00:25);
        let ks = EphemeralKeystore::new();
        const COUNT: &str = "SELECT COUNT(*) FROM HsDescriptors;";

        let mut store = HsDescStorage::from_connection(
            rusqlite::Connection::open_in_memory().unwrap(),
            now.into(),
            &ks,
        )
        .unwrap();

        let blind_id = HsBlindId::from([41; 32]);

        for d in [
            utc_datetime!(2008-08-01 20:00:00),
            utc_datetime!(2008-08-10 12:34),
        ] {
            let r = store.try_insert(
                &HsDescMeta {
                    blind_id,
                    revision_counter: 100.into(),
                    expiration: d.into(),
                },
                "not timely",
            );
            assert_matches!(r, Err(RepoError::UntimelyInsert));
        }

        let r = store
            .try_insert(
                &HsDescMeta {
                    blind_id,
                    revision_counter: 1000.into(),
                    expiration: utc_datetime!(2008-08-02 20:00:00).into(),
                },
                "First text",
            )
            .unwrap();
        assert_eq!(r, InsertStatus::Inserted);

        let r = store
            .try_insert(
                &HsDescMeta {
                    blind_id,
                    revision_counter: 999.into(), // lower number,
                    expiration: utc_datetime!(2008-08-02 20:00:01).into(),
                },
                "revision counter is lower; this will get ignored.",
            )
            .unwrap();
        assert_eq!(r, InsertStatus::Superseded);

        let r = store
            .try_insert(
                &HsDescMeta {
                    blind_id,
                    revision_counter: 1000.into(), // same number,
                    expiration: utc_datetime!(2008-08-02 20:00:01).into(),
                },
                "revision counter is the same; this will get ignored.",
            )
            .unwrap();
        assert_eq!(r, InsertStatus::Superseded);

        // Successful update; same day.
        let r = store
            .try_insert(
                &HsDescMeta {
                    blind_id,
                    revision_counter: 1002.into(),
                    // it doesn't matter if expiration is lower,
                    // so long as the revision counter increases.
                    expiration: utc_datetime!(2008-08-02 15:00:00).into(),
                },
                "Updated; same day",
            )
            .unwrap();
        assert_eq!(r, InsertStatus::Inserted);
        let t = store.get(&blind_id, None).unwrap().unwrap();
        assert_eq!(t.body.as_ref(), "Updated; same day");

        // Successful update; next day.
        let r = store
            .try_insert(
                &HsDescMeta {
                    blind_id,
                    revision_counter: 10_000.into(),
                    expiration: utc_datetime!(2008-08-03 10:00:00).into(),
                },
                "Updated; next day",
            )
            .unwrap();
        assert_eq!(r, InsertStatus::Inserted);
        let t = store.get(&blind_id, None).unwrap().unwrap();
        assert_eq!(t.body.as_ref(), "Updated; next day");
        let count: u32 = store.conn.query_one(COUNT, [], |row| row.get(0)).unwrap();
        assert_eq!(count, 1);

        // Successful update; back to the first day!
        let r = store
            .try_insert(
                &HsDescMeta {
                    blind_id,
                    revision_counter: 1_000_000.into(),
                    expiration: utc_datetime!(2008-08-02 01:00:00).into(),
                },
                "Updated; back to first day",
            )
            .unwrap();
        assert_eq!(r, InsertStatus::Inserted);
        let t = store.get(&blind_id, None).unwrap().unwrap();
        assert_eq!(t.body.as_ref(), "Updated; back to first day");
        let count: u32 = store.conn.query_one(COUNT, [], |row| row.get(0)).unwrap();
        assert_eq!(count, 1);
    }
}
