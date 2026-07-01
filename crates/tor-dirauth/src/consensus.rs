//! Consensus methods

use crate::internal_prelude::*;

mod method;

pub use method::*;

/// Supported consensus methods
///
/// Not guaranteed to be minimal, but guaranteed to be well-formed,
/// sorted and non-overlapping.
pub const SUPPORTED_METHODS: &[RangeInclusive<ConsensusMethod>] = method::map_ranges!([
    // This list is where the set of supported methods is defined.
    // Only values listed here can be made into a `SupportedConsensusMethod`.
    //
    100..=100,
]);
