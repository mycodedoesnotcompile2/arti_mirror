//! General functions for use in consensus calculations
//!
//! Eg with signatures like [`Aggregate::aggregate`]

use super::*;

/// Return the low median of the inputs
pub(super) fn low_median<'i, T: Ord + Clone + 'i>(
    context: &ConsensusContext,
    inputs: impl ComponentInVotes<&'i T>,
) -> Result<T, ConsensusError> {
    low_median_raw(inputs.map(|(_vnum, v)| v.clone())).ok_or(ConsensusError::NoVotes)
}

/// Return the low median of the inputs, without cloning, and without context
pub(super) fn low_median_raw<'i, T: Ord + 'i>(inputs: impl Iterator<Item = T>) -> Option<T> {
    let mut all = inputs.collect_vec();
    all.sort();
    let i = all.len() / 2; // rounds down
    all.into_iter().nth(i)
}
