//! Functionality for encrypting HsDescs and [`HsBlindId`]s at rest.

use crate::repo::storage::{DbId, KeyDate};

use aes_gcm::{AeadInOut as _, Aes128Gcm, KeyInit as _, aes::cipher::InOutBuf};
use rand::{Rng as _, RngExt as _};
use tiny_keccak::{Hasher, TupleHash};
use tor_error::{Bug, internal, into_internal};
use tor_hscrypto::pk::HsBlindId;
use zeroize::Zeroizing;

/// Key for encrypting and decrypting entries in our persistent HsDesc storage.
#[derive(Clone)]
pub struct DbEncryptionKey {
    /// A GCM key used to encrypt and authenticate entries.
    gcm: Aes128Gcm,

    /// A hash key used to derive [`DbId`] values from [`HsBlindId`]s.
    hash_key: Zeroizing<[u8; 32]>,

    /// An expiration date for which this key is used.
    for_day: KeyDate,
}

/// The length of AES-GCM nonce that we use.
///
/// This is the default for the aes_gcm crate,
/// and allows us to encrypt values up to 4 GiB
/// while avoiding nonce collision up to ~280 trillion HsDescs.
const NONCE_LEN: usize = 12;

/// The length of an AES-GCM tag.
const TAG_LEN: usize = 16;

impl DbEncryptionKey {
    /// Create a new random key for use on `for_day`.
    pub(crate) fn new(for_day: KeyDate) -> Self {
        let mut rng = rand::rng();
        let hash_key: Zeroizing<_> = Zeroizing::new(rng.random());
        let mut aes_key = Zeroizing::new(aes_gcm::Key::<Aes128Gcm>::default());
        rng.fill_bytes(&mut aes_key);

        Self {
            gcm: Aes128Gcm::new(&aes_key),
            hash_key,
            for_day,
        }
    }

    /// Return the date on which this key is to be used.
    pub(crate) fn date(&self) -> KeyDate {
        self.for_day
    }

    /// Return the database index at which `blinded_pk` should be stored,
    /// if its HsDesc expires on this key's date.
    pub(crate) fn derive_index(&self, blinded_pk: &HsBlindId) -> DbId {
        let mut idx = DbId(Default::default());

        const CUSTOM: &[u8] = b"arti hsdir index v0";
        let mut h = TupleHash::v128(CUSTOM);
        h.update(&*self.hash_key);
        h.update(blinded_pk.as_ref());
        h.finalize(&mut *idx.0);
        idx
    }

    /// Encrypt the given plaintext, while authenticating the value of `idx`.
    ///
    /// Returns a newly allocated output containing the nonce, the authentication tag, and the data.
    pub(crate) fn encrypt_entry(&self, idx: &DbId, plaintext: &[u8]) -> Result<Box<[u8]>, Bug> {
        let rlen = NONCE_LEN + TAG_LEN + plaintext.len(); /*nonce, tag, text */
        let mut output = vec![0; rlen];

        self.encrypt_entry_into(idx, plaintext, &mut output)?;

        Ok(output.into_boxed_slice())
    }

    /// Helper for `encrypt_entry`: Reads data from `plaintext` and writes into `output`,
    /// which must be the correct length.
    fn encrypt_entry_into(
        &self,
        idx: &DbId,
        plaintext: &[u8],
        output: &mut [u8],
    ) -> Result<(), Bug> {
        let (nonce_out, rest) = output
            .split_at_mut_checked(NONCE_LEN)
            .ok_or_else(|| internal!("Too short!"))?;
        let (tag_out, body_out) = rest
            .split_at_mut_checked(TAG_LEN)
            .ok_or_else(|| internal!("Too short!"))?;

        rand::rng().fill_bytes(nonce_out);

        let nonce = nonce_out[..]
            .try_into()
            .map_err(into_internal!("Wrong nonce length"))?;

        let tag = self
            .gcm
            .encrypt_inout_detached(
                nonce,
                idx.0.as_ref(),
                InOutBuf::new(plaintext, body_out).map_err(into_internal!("Length mismatch"))?,
            )
            .map_err(into_internal!("GCM encryption failed"))?;

        tag_out.copy_from_slice(&tag[..]);

        Ok(())
    }

    /// Decrypt a `ciphertext` returned by [`encrypt_entry`](Self::encrypt_entry).
    ///
    /// If it is well formed, correctly authenticated, and the `idx` field is correct, return
    /// the plaintext.
    pub(crate) fn decrypt_entry(
        &self,
        idx: &DbId,
        ciphertext: &[u8],
    ) -> Result<Box<[u8]>, DecryptError> {
        let (nonce, rest) = ciphertext
            .split_at_checked(NONCE_LEN)
            .ok_or(DecryptError::TooShort)?;
        let (tag, body) = rest
            .split_at_checked(TAG_LEN)
            .ok_or(DecryptError::TooShort)?;

        let mut output = vec![0; body.len()];

        let nonce = nonce
            .try_into()
            .map_err(into_internal!("Wrong nonce length"))?;
        let tag = tag.try_into().map_err(into_internal!("Wrong tag length"))?;

        let () = self.gcm.decrypt_inout_detached(
            nonce,
            idx.0.as_ref(),
            InOutBuf::new(body, &mut output[..]).map_err(into_internal!(
                "Somehow rust aliasing rules are not in effect"
            ))?,
            tag,
        )?;

        Ok(output.into_boxed_slice())
    }
}

/// An error from decrypting a database entry
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DecryptError {
    /// The AES-GCM decryption failed: the tag must have been wrong.
    #[error("Decryption failed")]
    Gcm(#[from] aes_gcm::Error),

    /// There wasn't enough data to hold tag, nonce, and plaintext.
    #[error("Decrypted data was too short.")]
    TooShort,

    /// An internal programming error.
    #[error("Internal error")]
    Internal(#[from] Bug),
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

    use super::*;

    use subtle::ConstantTimeEq as _;
    use time::macros::date;

    #[test]
    fn keygen_sanity() {
        let mut rng = rand::rng();
        let d1 = KeyDate(date!(2008 - 08 - 02));
        let k1 = DbEncryptionKey::new(d1);
        let k2 = DbEncryptionKey::new(d1);
        let b = HsBlindId::from(rng.random::<[u8; 32]>());
        assert_ne!(k1.hash_key, k2.hash_key);
        assert_eq!(
            k1.derive_index(&b).ct_ne(&k2.derive_index(&b)).unwrap_u8(),
            1
        );
        let dbid = k1.derive_index(&b);
        let text = b"Hello world";
        assert_ne!(
            k1.encrypt_entry(&dbid, text).unwrap(),
            k2.encrypt_entry(&dbid, text).unwrap()
        );
    }

    #[test]
    fn round_trip() {
        let mut rng = rand::rng();
        let d1 = KeyDate(date!(2008 - 08 - 02));
        let k1 = DbEncryptionKey::new(d1);
        let b = HsBlindId::from(rng.random::<[u8; 32]>());

        let plaintext: [u8; 917] = rng.random();
        let dbid = k1.derive_index(&b);
        let ciphertext = k1.encrypt_entry(&dbid, &plaintext).unwrap();
        assert!(ciphertext.len() > plaintext.len());
        let pt2 = k1.decrypt_entry(&dbid, &ciphertext).unwrap();
        assert_eq!(&*pt2, &plaintext);

        // Now make sure that a different dbid fails.
        let b2 = HsBlindId::from(rng.random::<[u8; 32]>());
        let dbid2 = k1.derive_index(&b2);
        assert!(matches!(
            k1.decrypt_entry(&dbid2, &ciphertext),
            Err(DecryptError::Gcm(_)),
        ));
    }
}
