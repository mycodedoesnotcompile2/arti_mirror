//! Consensus methods

use crate::internal_prelude::*;

mod method;

pub use method::*;

/// Supported consensus methods
///
/// Not guaranteed to be minimal, but guaranteed to be well-formed,
/// sorted and non-overlapping.
///
/// See <https://spec.torproject.org/dir-spec/computing-consensus.html#consensus-method-list>
/// for where these values come from.
///
/// In tor-dirauth, we use literal numeric constants for consensus method values,
/// rather than trying to give each consensus method a named `const`.
pub const SUPPORTED_METHODS: &[RangeInclusive<ConsensusMethod>] = {
    use ConsensusMethod as M;
    &[
        // This list is where the set of supported methods is defined.
        // Only values listed here can be made into a `SupportedConsensusMethod`.
        //
        M(100)..=M(100),
    ]
};
