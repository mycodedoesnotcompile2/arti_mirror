//! Implements the relay 'family' type.
//!
//! Families are opt-in lists of relays with the same operators,
//! used to avoid building insecure circuits.

use crate::types::misc::LongIdent;
use crate::{NetdocErrorKind, NormalItemArgument, Pos};
use base64ct::Encoding;
use derive_deftly::Deftly;
use tor_llcrypto::pk::ed25519::{ED25519_ID_LEN, Ed25519Identity};

/// A ZST indicating that we have parsed a legacy relay family.
///
/// Tor relays once used lists of Relay IDs to
/// declare that they belong to the same family, to
/// indicate that they are controlled by the same party or parties,
/// and as such should not be used in the same circuit. Two relays
/// belong to the same family if and only if each one lists the other
/// as belonging to its family.
///
/// Now, HappyFamilyIds are used for this purpose.
/// This type remains to indicate that a family list has been parsed.
/// The actual members of the list are not retained, however, since they
/// are no longer used for anything.
///
/// NOTE: when parsing, this type always discards incorrectly-formatted
/// entries, including entries that are only nicknames.
//
// TODO: This type probably belongs in a different crate.
//
// TODO (cve, Diziet): Overhaul or remove LegacyFamily, HappyFamilyId, HappyFamilyIds:
//   - Possibly, these don't all warrant newtype wrappers
//   - Where they do warrant newtype wrappers the API should be appropriate for that
// See <https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/4117#note_3428678>
#[derive(Clone, Debug, Default, Hash, Eq, PartialEq, Ord, PartialOrd, Deftly)]
#[derive_deftly(ItemValueEncodable, ItemValueParseable)]
#[non_exhaustive]
pub struct LegacyFamily;

impl LegacyFamily {
    /// Return a new empty LegacyFamily.
    pub fn new() -> Self {
        LegacyFamily::default()
    }
}

impl std::str::FromStr for LegacyFamily {
    type Err = crate::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let v: Result<Vec<LongIdent>, _> = s
            .split(crate::parse::tokenize::is_sp)
            .map(|e| e.parse::<LongIdent>())
            .filter(Result::is_ok)
            .collect();
        let _ignore = v?;
        Ok(LegacyFamily)
    }
}

/// An identifier representing a relay family.
///
/// In the ["happy families"](https://spec.torproject.org/proposals/321) scheme,
/// microdescriptors will no longer have to contain a list of relay members,
/// but will instead contain these identifiers.
///
/// If two relays have a `HappyFamilyId` in common, they belong to the same family.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum HappyFamilyId {
    /// An identifier derived from an Ed25519 relay family key. (`KP_familyid_ed`)
    Ed25519(Ed25519Identity),
    /// An unrecognized string.
    Unrecognized(String),
}

/// Prefix for a HappyFamilyId derived from an ed25519 `KP_familyid_ed`.
const ED25519_ID_PREFIX: &str = "ed25519:";

impl std::str::FromStr for HappyFamilyId {
    type Err = crate::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let mut buf = [0_u8; ED25519_ID_LEN];
        if let Some(s) = s.strip_prefix(ED25519_ID_PREFIX) {
            if let Ok(decoded) = base64ct::Base64Unpadded::decode(s, &mut buf) {
                if let Some(ed_id) = Ed25519Identity::from_bytes(decoded) {
                    return Ok(HappyFamilyId::Ed25519(ed_id));
                }
            }
            return Err(NetdocErrorKind::BadArgument
                .with_msg("Invalid ed25519 family ID")
                .at_pos(Pos::at(s)));
        }
        Ok(HappyFamilyId::Unrecognized(s.to_string()))
    }
}

impl std::fmt::Display for HappyFamilyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HappyFamilyId::Ed25519(id) => write!(f, "{}{}", ED25519_ID_PREFIX, id),
            HappyFamilyId::Unrecognized(s) => write!(f, "{}", s),
        }
    }
}

impl PartialOrd for HappyFamilyId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(Ord::cmp(self, other))
    }
}
impl Ord for HappyFamilyId {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // We sort HappyFamilyId values by string representation.
        // This is not super-efficient, but we don't need to do it very often.
        Ord::cmp(&self.to_string(), &other.to_string())
    }
}

impl From<Ed25519Identity> for HappyFamilyId {
    fn from(value: Ed25519Identity) -> Self {
        Self::Ed25519(value)
    }
}

impl NormalItemArgument for HappyFamilyId {}

/// A list of multiple [`HappyFamilyId`] entries as found in microdescs.
///
/// Using the [`FromIterator`] implementation for [`HappyFamilyId`] leads the
/// result to get deduplicated and sorted automatically using
/// [`HappyFamilyIds::dedup()`] and [`HappyFamilyIds::sort()`], as those calls
/// are effectively required for a useful use of this type.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deftly, derive_more::AsRef)]
#[derive_deftly(ItemValueEncodable, ItemValueParseable)]
pub struct HappyFamilyIds(
    // TODO DIRMIRROR: Replace with BTreeSet at one point.
    // TODO could/should this be a type alias instead?
    Vec<HappyFamilyId>,
);

impl HappyFamilyIds {
    /// Return a new empty [`HappyFamilyIds`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Push `family_id` onto this instance.
    pub fn push(&mut self, family_id: HappyFamilyId) {
        self.0.push(family_id);
    }

    /// Sort entries ascending by their [`HappyFamilyId`].
    pub fn sort(&mut self) {
        self.0.sort();
    }

    /// Deduplicates entries.
    pub fn dedup(&mut self) {
        self.0.dedup();
    }
}

impl FromIterator<HappyFamilyId> for HappyFamilyIds {
    fn from_iter<T: IntoIterator<Item = HappyFamilyId>>(iter: T) -> Self {
        let mut res = Self(iter.into_iter().collect());
        // TODO: We should really reconsider this because it does not achieve
        // the same as subsequent calls to push.  As outlined above, we probably
        // want to switch to a BTreeSet in the long run anyways.
        res.sort();
        res.dedup();
        res
    }
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
    use std::str::FromStr;

    use super::*;
    use crate::Result;
    #[test]
    fn family() -> Result<()> {
        let _f = "nickname1 nickname2 $ffffffffffffffffffffffffffffffffffffffff=foo eeeeeeeeeeeeeeeeeeeEEEeeeeeeeeeeeeeeeeee ddddddddddddddddddddddddddddddddd  $cccccccccccccccccccccccccccccccccccccccc~blarg ".parse::<LegacyFamily>()?;
        Ok(())
    }
    #[test]
    fn family_ids() {
        let ed_str_rep = "ed25519:7sToQRuge1bU2hS0CG0ViMndc4m82JhO4B4kdrQey80";
        let ed_id = HappyFamilyId::from_str(ed_str_rep).unwrap();
        assert!(matches!(ed_id, HappyFamilyId::Ed25519(_)));
        assert_eq!(ed_id.to_string().as_str(), ed_str_rep);

        let other_str_rep = "hello-world";
        let other_id = HappyFamilyId::from_str(other_str_rep).unwrap();
        assert!(matches!(other_id, HappyFamilyId::Unrecognized(_)));
        assert_eq!(other_id.to_string().as_str(), other_str_rep);

        assert_eq!(ed_id, ed_id);
        assert_ne!(ed_id, other_id);
    }

    #[test]
    fn parse2() {
        #[derive(Debug, PartialEq, Eq, derive_deftly::Deftly)]
        #[derive_deftly(NetdocParseable)]
        struct Wrapper {
            family: LegacyFamily,
        }

        const LINE: &str = "family $0000000000000000000000000000000000000000 $FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
        let parsed =
            crate::parse2::parse_netdoc::<Wrapper>(&crate::parse2::ParseInput::new(LINE, ""))
                .unwrap();
        assert_eq!(
            parsed,
            Wrapper {
                family: LegacyFamily
            }
        );
    }
}
