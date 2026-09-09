//! Code for working with bridge descriptors.
//!
//! Here we need to keep track of which bridge descriptors we need, and inform
//! the directory manager of them.

use std::collections::HashMap;
use std::sync::Arc;

use crate::{
    bridge::BridgeConfig,
    sample::{Candidate, CandidateStatus, Universe, WeightThreshold},
};
use dyn_clone::DynClone;
use futures::stream::BoxStream;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use strum::{EnumCount, EnumIter};
use tor_error::{HasKind, HasRetryTime};
use tor_linkspec::{ChanTarget, HasChanMethod, HasRelayIds, OwnedChanTarget};
use tor_llcrypto::pk::{ed25519::Ed25519Identity, rsa::RsaIdentity};
use tor_netdir::RelayWeight;
use tor_netdoc::doc::routerdesc::RouterDesc;
use web_time_compat::{SystemTime, SystemTimeExt};

use super::BridgeRelay;

/// A router descriptor that can be used to build circuits through a bridge.
///
/// These descriptors are fetched from the bridges themselves, and used in
/// conjunction with configured bridge information and pluggable transports to
/// contact bridges and build circuits through them.
#[derive(Clone, Debug)]
pub struct BridgeDesc {
    /// The inner descriptor.
    ///
    /// NOTE: This is wrapped in an `Arc<>` because we expect to pass BridgeDesc
    /// around a bit and clone it frequently.  If that doesn't actually happen,
    /// we can remove the Arc here.
    desc: Arc<RouterDesc>,

    /// The RsaIdentity of the [`RouterDesc`] found in [`BridgeDesc::desc`].
    // It is unfortunate that we have to store this in an extra field, but the
    // alternatives are not satisfying either:
    // * Include the [`RsaIdentity`] inside [`RouterDesc`] so we can return
    //   a reference to it.
    //     * This is not nice because it would involve `netdoc(skip)`.
    // * Change [`tor_linkspec`] to use the values directly rather than
    //   returning references to it.
    //     * This is the more clean solution, especially because both types
    //       implement [`Copy`] anyways.
    //     * However, [`tor_linkspec`] and its traits and types are deeply
    //       integrated into the codebase and changing them would mean lots of
    //       fixes everywhere.
    rsa_identity: RsaIdentity,
}

impl AsRef<RouterDesc> for BridgeDesc {
    fn as_ref(&self) -> &RouterDesc {
        self.desc.as_ref()
    }
}

impl BridgeDesc {
    /// Construct a new BridgeDesc from `desc`.
    ///
    /// The provided `desc` must be a descriptor retrieved from the bridge
    /// itself.
    pub fn new(desc: Arc<RouterDesc>) -> Self {
        let rsa_identity = desc.rsa_identity();
        Self { desc, rsa_identity }
    }
}

impl tor_linkspec::HasRelayIdsLegacy for BridgeDesc {
    fn ed_identity(&self) -> &Ed25519Identity {
        self.desc.ed_identity()
    }

    fn rsa_identity(&self) -> &RsaIdentity {
        &self.rsa_identity
    }
}

/// Trait for an object that knows how to fetch bridge descriptors as needed.
///
/// A "bridge descriptor" (represented by [`BridgeDesc`]) is a self-signed
/// representation of a bridge's keys, capabilities, and other information. We
/// can connect to a bridge without a descriptor, but we need to have one before
/// we can build a multi-hop circuit through a bridge.
///
/// In arti, the implementor of this trait is `BridgeDescMgr`.  We define this
/// trait here so that we can avoid a circularity in our crate dependencies.
/// (Since `BridgeDescMgr` uses circuits, it needs `CircMgr`, which needs
/// `GuardMgr`, which in turn needs `BridgeDescMgr` again. We break this
/// circularity by having `GuardMgr` use `BridgeDescMgr` only through this
/// trait's API.)
pub trait BridgeDescProvider: DynClone + Send + Sync {
    /// Return the current set of bridge descriptors.
    fn bridges(&self) -> Arc<BridgeDescList>;

    /// Return a stream that gets a notification when the set of bridge
    /// descriptors has changed.
    fn events(&self) -> BoxStream<'static, BridgeDescEvent>;

    /// Change the set of bridges that we want to download descriptors for.
    ///
    /// Bridges outside of this set will not have their descriptors updated,
    /// and will not be revealed in the BridgeDescList.
    fn set_bridges(&self, bridges: &[BridgeConfig]);
}

dyn_clone::clone_trait_object!(BridgeDescProvider);

/// An event describing a change in a `BridgeDescList`.
///
/// Currently changes are always reported as `BridgeDescEvent::SomethingChanged`.
///
/// In the future, as an optimization, more fine-grained information may be provided.
/// Unrecognized variants should be handled the same way as `SomethingChanged`.
/// (So right now, it is not necessary to match on the variant at all.)
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, EnumIter, EnumCount, IntoPrimitive, TryFromPrimitive,
)]
#[non_exhaustive]
#[repr(u16)]
pub enum BridgeDescEvent {
    /// Some change occurred to the set of descriptors
    ///
    /// The return value from [`bridges()`](BridgeDescProvider::bridges)
    /// may have changed.
    ///
    /// The nature of the change is not specified; it might affect multiple descriptors,
    /// and include multiple different kinds of change.
    ///
    /// This event may also be generated spuriously, if nothing has changed,
    /// but this will usually be avoided for performance reasons.
    SomethingChanged,
}

/// An error caused while fetching bridge descriptors
///
/// Note that when this appears in `BridgeDescList`, as returned by `BridgeDescMgr`,
/// the fact that this is `HasRetryTime` does *not* mean the caller should retry.
/// Retries will be handled by the `BridgeDescMgr`.
/// The `HasRetryTime` impl can be used as a guide to
/// whether the situation is likely to improve soon.
///
/// Does *not* include the information about which bridge we were trying to
/// get a descriptor for.
pub trait BridgeDescError:
    std::error::Error + DynClone + HasKind + HasRetryTime + Send + Sync + 'static
{
}

dyn_clone::clone_trait_object!(BridgeDescError);

/// A set of bridge descriptors, managed and modified by a BridgeDescProvider.
pub type BridgeDescList = HashMap<BridgeConfig, Result<BridgeDesc, Box<dyn BridgeDescError>>>;

/// A collection of bridges, possibly with their descriptors.
#[derive(Debug, Clone)]
pub(crate) struct BridgeSet {
    /// The configured bridges.
    config: Arc<[BridgeConfig]>,
    /// A map from those bridges to their descriptors.  It may contain elements
    /// that are not in `config`.
    descs: Option<Arc<BridgeDescList>>,
}

impl BridgeSet {
    /// Create a new `BridgeSet` from its configuration.
    pub(crate) fn new(config: Arc<[BridgeConfig]>, descs: Option<Arc<BridgeDescList>>) -> Self {
        Self { config, descs }
    }

    /// Returns the bridge that best matches a given guard.
    ///
    /// Note that since the guard may have more identities than the bridge the
    /// match may not be perfect: the caller needs to check for a closer match
    /// if they want to be certain.
    ///
    /// We check for a match by identity _and_ channel method, since channel
    /// method is part of what makes two bridge lines different.
    pub(crate) fn bridge_by_guard<T>(&self, guard: &T) -> Option<&BridgeConfig>
    where
        T: ChanTarget,
    {
        self.config.iter().find(|bridge| {
            guard.has_all_relay_ids_from(*bridge)
                // The Guard could have more addresses than the BridgeConfig if
                // we happen to know its descriptor, it is using a direct
                // connection, and it has listed more addresses there.
                && bridge.chan_method().contained_by(&guard.chan_method())
        })
    }

    /// Return a BridgeRelay wrapping the provided configuration, plus any known
    /// descriptor for that configuration.
    fn relay_by_bridge<'a>(&'a self, bridge: &'a BridgeConfig) -> BridgeRelay<'a> {
        let desc = match self.descs.as_ref().and_then(|d| d.get(bridge)) {
            Some(Ok(b)) => Some(b.clone()),
            _ => None,
        };
        BridgeRelay::new(bridge, desc)
    }

    /// Look up a BridgeRelay corresponding to a given guard.
    pub(crate) fn bridge_relay_by_guard<T: tor_linkspec::ChanTarget>(
        &self,
        guard: &T,
    ) -> CandidateStatus<BridgeRelay> {
        match self.bridge_by_guard(guard) {
            Some(bridge) => {
                let bridge_relay = self.relay_by_bridge(bridge);
                if bridge_relay.has_all_relay_ids_from(guard) {
                    // We have all the IDs from the guard, either in the bridge
                    // line or in the descriptor, so the match is exact.
                    CandidateStatus::Present(bridge_relay)
                } else if bridge_relay.has_descriptor() {
                    // We don't have an exact match and we have have a
                    // descriptor, so we know that this is _not_ a real match.
                    CandidateStatus::Absent
                } else {
                    // We don't have a descriptor; finding it might make our
                    // match precise.
                    CandidateStatus::Uncertain
                }
            }
            // We found no bridge that matches this guard's identities, so we
            // can declare it absent.
            None => CandidateStatus::Absent,
        }
    }
}

impl Universe for BridgeSet {
    fn contains<T: tor_linkspec::ChanTarget>(&self, guard: &T) -> Option<bool> {
        match self.bridge_relay_by_guard(guard) {
            CandidateStatus::Present(_) => Some(true),
            CandidateStatus::Absent => Some(false),
            CandidateStatus::Uncertain => None,
        }
    }

    fn status<T: tor_linkspec::ChanTarget>(&self, guard: &T) -> CandidateStatus<Candidate> {
        match self.bridge_relay_by_guard(guard) {
            CandidateStatus::Present(bridge_relay) => CandidateStatus::Present(Candidate {
                listed_as_guard: true,
                is_dir_cache: true, // all bridges are directory caches.
                full_dir_info: bridge_relay.has_descriptor(),
                owned_target: OwnedChanTarget::from_chan_target(&bridge_relay),
                sensitivity: crate::guard::DisplayRule::Redacted,
            }),
            CandidateStatus::Absent => CandidateStatus::Absent,
            CandidateStatus::Uncertain => CandidateStatus::Uncertain,
        }
    }

    fn timestamp(&self) -> SystemTime {
        // We just use the current time as the timestamp of this BridgeSet.
        // This makes the guard code treat a BridgeSet as _continuously updated_:
        // anything listed in the guard set is treated as listed right up to this
        // moment, and anything unlisted is treated as unlisted right up to this
        // moment.
        SystemTime::get()
    }

    /// Note that for a BridgeSet, we always treat the current weight as 0 and
    /// the maximum weight as "unlimited".  That's because we don't have
    /// bandwidth measurements for bridges, and so `max_sample_bw_fraction`
    /// doesn't apply to them.
    fn weight_threshold<T>(
        &self,
        _sample: &tor_linkspec::ByRelayIds<T>,
        _params: &crate::GuardParams,
    ) -> WeightThreshold
    where
        T: HasRelayIds,
    {
        WeightThreshold {
            current_weight: RelayWeight::from(0),
            maximum_weight: RelayWeight::from(u64::MAX),
        }
    }

    fn sample<T>(
        &self,
        pre_existing: &tor_linkspec::ByRelayIds<T>,
        filter: &crate::GuardFilter,
        n: usize,
    ) -> Vec<(Candidate, tor_netdir::RelayWeight)>
    where
        T: HasRelayIds,
    {
        use rand::seq::IteratorRandom;
        self.config
            .iter()
            .filter(|bridge_conf| {
                filter.permits(*bridge_conf)
                    && pre_existing.all_overlapping(*bridge_conf).is_empty()
            })
            .sample(&mut rand::rng(), n)
            .into_iter()
            .map(|bridge_config| {
                let relay = self.relay_by_bridge(bridge_config);
                (
                    Candidate {
                        listed_as_guard: true,
                        is_dir_cache: true,
                        full_dir_info: relay.has_descriptor(),
                        owned_target: OwnedChanTarget::from_chan_target(&relay),
                        sensitivity: crate::guard::DisplayRule::Redacted,
                    },
                    RelayWeight::from(0),
                )
            })
            .collect()
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
    use super::*;
    use crate::GuardFilter;
    use crate::bridge::test_util::*;
    use crate::guard::DisplayRule;
    use tor_linkspec::{ByRelayIds, OwnedChanTargetBuilder};

    /// [`BRIDGE_3`], with an ed25519 identity in the bridge line too.
    const BRIDGE_3_WITH_ED: &str = "192.0.2.3:9001 3333333333333333333333333333333333333333 ed25519:MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM";

    /// An error that a `BridgeDescProvider` might report for a bridge.
    #[derive(Clone, Debug, thiserror::Error)]
    #[error("could not fetch descriptor")]
    struct FetchFailed;
    impl HasKind for FetchFailed {
        fn kind(&self) -> tor_error::ErrorKind {
            tor_error::ErrorKind::TorAccessFailed
        }
    }
    impl HasRetryTime for FetchFailed {
        fn retry_time(&self) -> tor_error::RetryTime {
            tor_error::RetryTime::AfterWaiting
        }
    }
    impl BridgeDescError for FetchFailed {}

    /// One entry in a [`BridgeDescList`].
    type DescEntry = (BridgeConfig, Result<BridgeDesc, Box<dyn BridgeDescError>>);

    /// Build a `BridgeSet` from bridge lines and a list of descriptor results.
    fn bridge_set(lines: &[&str], descs: Option<Vec<DescEntry>>) -> BridgeSet {
        let config: Arc<[BridgeConfig]> = lines.iter().map(|l| bridge(l)).collect();
        let descs = descs.map(|d| Arc::new(d.into_iter().collect::<BridgeDescList>()));
        BridgeSet::new(config, descs)
    }

    /// A guard with the identities and channel method of `cfg`, optionally
    /// with an extra ed25519 identity.
    fn guard(cfg: &BridgeConfig, ed_id: Option<&str>) -> OwnedChanTarget {
        let mut b = OwnedChanTargetBuilder::default();
        b.ids().rsa_identity(*cfg.rsa_identity().unwrap());
        if let Some(ed) = cfg.ed_identity() {
            b.ids().ed_identity(*ed);
        }
        if let Some(ed) = ed_id {
            let ed = match ed.parse().unwrap() {
                tor_linkspec::RelayId::Ed25519(ed) => ed,
                _ => panic!("not an ed25519 id: {ed}"),
            };
            b.ids().ed_identity(ed);
        }
        b.method(cfg.chan_method());
        b.build().unwrap()
    }

    /// The wrong ed25519 identity for our descriptor.
    const WRONG_ED_ID: &str = "ed25519:d3JvbmcgZWQyNTUxOSBpZGVudGl0eSEhISEhISEhISE";

    #[test]
    fn bridge_by_guard() {
        let set = bridge_set(&[BRIDGE_LINE, BRIDGE_2, BRIDGE_3_WITH_ED], None);
        let (b1, b2, b3) = (
            bridge(BRIDGE_LINE),
            bridge(BRIDGE_2),
            bridge(BRIDGE_3_WITH_ED),
        );

        // Exact matches.
        assert_eq!(set.bridge_by_guard(&guard(&b1, None)), Some(&b1));
        assert_eq!(set.bridge_by_guard(&guard(&b2, None)), Some(&b2));
        assert_eq!(set.bridge_by_guard(&guard(&b3, None)), Some(&b3));

        // A guard may know more identities than the bridge line does.
        assert_eq!(set.bridge_by_guard(&guard(&b1, Some(ED_ID))), Some(&b1));

        // But it must know every identity from the line.
        assert_eq!(set.bridge_by_guard(&guard(&bridge(BRIDGE_3), None)), None);

        // Same identities, different way of reaching the bridge: no match.
        let b1_other_port = bridge("51.68.172.83:443 EB6EFB27F29AC9511A4246D7ABE1AFABFB416FF1");
        assert_eq!(set.bridge_by_guard(&guard(&b1_other_port, None)), None);

        // Unknown bridge.
        let unknown = bridge("192.0.2.9:9001 9999999999999999999999999999999999999999");
        assert_eq!(set.bridge_by_guard(&guard(&unknown, None)), None);
    }

    #[test]
    fn bridge_relay_by_guard_without_descriptors() {
        let set = bridge_set(&[BRIDGE_LINE, BRIDGE_2], None);
        let b1 = bridge(BRIDGE_LINE);

        // The guard knows exactly what the bridge line knows: present.
        match set.bridge_relay_by_guard(&guard(&b1, None)) {
            CandidateStatus::Present(relay) => {
                assert!(!relay.has_descriptor());
                assert!(relay.same_relay_ids(&b1));
            }
            other => panic!("expected Present, got {other:?}"),
        }
        assert_eq!(set.contains(&guard(&b1, None)), Some(true));

        // The guard knows an ed25519 identity that the bridge line does not.
        // Without a descriptor we can't tell whether it is the same bridge.
        assert!(matches!(
            set.bridge_relay_by_guard(&guard(&b1, Some(ED_ID))),
            CandidateStatus::Uncertain
        ));
        assert_eq!(set.contains(&guard(&b1, Some(ED_ID))), None);

        // Nothing in the set has these identities.
        let unknown = bridge("192.0.2.9:9001 9999999999999999999999999999999999999999");
        assert!(matches!(
            set.bridge_relay_by_guard(&guard(&unknown, None)),
            CandidateStatus::Absent
        ));
        assert_eq!(set.contains(&guard(&unknown, None)), Some(false));
    }

    #[test]
    fn bridge_relay_by_guard_with_descriptors() {
        let b1 = bridge(BRIDGE_LINE);
        let b2 = bridge(BRIDGE_2);
        let set = bridge_set(
            &[BRIDGE_LINE, BRIDGE_2],
            Some(vec![
                (b1.clone(), Ok(bridge_desc())),
                (b2.clone(), Err(Box::new(FetchFailed))),
            ]),
        );

        // With the descriptor, the relay has the ed25519 identity too.
        match set.bridge_relay_by_guard(&guard(&b1, Some(ED_ID))) {
            CandidateStatus::Present(relay) => {
                assert!(relay.has_descriptor());
                assert!(relay.same_relay_ids(&bridge_desc()));
            }
            other => panic!("expected Present, got {other:?}"),
        }
        // A guard that only knows the RSA identity still matches.
        assert_eq!(set.contains(&guard(&b1, None)), Some(true));

        // The descriptor tells us this guard's ed25519 identity is wrong, so
        // it is definitely not this bridge.
        assert!(matches!(
            set.bridge_relay_by_guard(&guard(&b1, Some(WRONG_ED_ID))),
            CandidateStatus::Absent
        ));
        assert_eq!(set.contains(&guard(&b1, Some(WRONG_ED_ID))), Some(false));

        // A failed descriptor fetch is the same as having no descriptor.
        match set.bridge_relay_by_guard(&guard(&b2, None)) {
            CandidateStatus::Present(relay) => assert!(!relay.has_descriptor()),
            other => panic!("expected Present, got {other:?}"),
        }
        assert_eq!(set.contains(&guard(&b2, Some(WRONG_ED_ID))), None);
    }

    #[test]
    fn status() {
        let b1 = bridge(BRIDGE_LINE);
        let b2 = bridge(BRIDGE_2);
        let set = bridge_set(
            &[BRIDGE_LINE, BRIDGE_2],
            Some(vec![(b1.clone(), Ok(bridge_desc()))]),
        );

        // A bridge with a descriptor: full information.
        match set.status(&guard(&b1, None)) {
            CandidateStatus::Present(c) => {
                assert!(c.listed_as_guard);
                assert!(c.is_dir_cache);
                assert!(c.full_dir_info);
                assert!(matches!(c.sensitivity, DisplayRule::Redacted));
                // The candidate carries the identity we learned from the descriptor.
                assert!(c.owned_target.same_relay_ids(&bridge_desc()));
                assert_eq!(c.owned_target.chan_method(), b1.chan_method());
            }
            other => panic!("expected Present, got {other:?}"),
        }

        // A bridge without a descriptor: still a candidate, but we know less.
        match set.status(&guard(&b2, None)) {
            CandidateStatus::Present(c) => {
                assert!(c.listed_as_guard);
                assert!(c.is_dir_cache);
                assert!(!c.full_dir_info);
                assert!(c.owned_target.same_relay_ids(&b2));
            }
            other => panic!("expected Present, got {other:?}"),
        }

        assert!(matches!(
            set.status(&guard(&b2, Some(WRONG_ED_ID))),
            CandidateStatus::Uncertain
        ));
        assert!(matches!(
            set.status(&guard(&b1, Some(WRONG_ED_ID))),
            CandidateStatus::Absent
        ));
    }

    #[test]
    fn timestamp_is_now() {
        let set = bridge_set(&[BRIDGE_LINE], None);
        let before = SystemTime::get();
        let ts = set.timestamp();
        let after = SystemTime::get();
        assert!(before <= ts && ts <= after);
    }

    #[test]
    fn weight_threshold_is_unlimited() {
        // We have no bandwidth information about bridges, so the answer does
        // not depend on the sample or the parameters.
        let set = bridge_set(&[BRIDGE_LINE, BRIDGE_2], None);
        let sample: ByRelayIds<BridgeConfig> = ByRelayIds::new();
        let params = crate::GuardParams::default();

        let threshold = set.weight_threshold(&sample, &params);
        assert_eq!(threshold.current_weight, RelayWeight::from(0));
        assert_eq!(threshold.maximum_weight, RelayWeight::from(u64::MAX));
    }

    #[test]
    fn sample() {
        let b1 = bridge(BRIDGE_LINE);
        let set = bridge_set(
            &[BRIDGE_LINE, BRIDGE_2, BRIDGE_3],
            Some(vec![(b1.clone(), Ok(bridge_desc()))]),
        );
        let no_filter = GuardFilter::unfiltered();
        let nothing: ByRelayIds<BridgeConfig> = ByRelayIds::new();

        // Asking for more than we have gives us everything, each with zero
        // weight (we have no bandwidth information about bridges).
        let all = set.sample(&nothing, &no_filter, 10);
        assert_eq!(all.len(), 3);
        for (candidate, weight) in &all {
            assert_eq!(*weight, RelayWeight::from(0));
            assert!(candidate.listed_as_guard);
            assert!(candidate.is_dir_cache);
            // Only the first bridge has a descriptor.
            let is_b1 = candidate.owned_target.has_all_relay_ids_from(&b1);
            assert_eq!(candidate.full_dir_info, is_b1);
        }

        // Asking for fewer gives us that many.
        assert_eq!(set.sample(&nothing, &no_filter, 2).len(), 2);
        assert_eq!(set.sample(&nothing, &no_filter, 0).len(), 0);

        // Bridges we already have are not offered again.
        let mut have_b1 = ByRelayIds::new();
        have_b1.insert(b1.clone());
        let rest = set.sample(&have_b1, &no_filter, 10);
        assert_eq!(rest.len(), 2);
        assert!(
            rest.iter()
                .all(|(c, _)| !c.owned_target.has_any_relay_id_from(&b1))
        );

        // The filter applies.
        let mut filter = GuardFilter::unfiltered();
        filter.push_reachable_addresses(vec!["192.0.2.3/32:*".parse().unwrap()]);
        let filtered = set.sample(&nothing, &filter, 10);
        assert_eq!(filtered.len(), 1);
        assert!(filtered[0].0.owned_target.same_relay_ids(&bridge(BRIDGE_3)));
    }
}
