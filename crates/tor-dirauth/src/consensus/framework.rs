//! Traits and common types for for calculating consensuses from votes

use super::*;

/// Voter number
///
/// Valid only within a particular consensus calculation round.
/// Corresponds to the index in `ConsensusesContext.votes`.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)] //
#[derive(derive_more::From, derive_more::Into)]
pub(super) struct VoterNum(pub usize);

/// Components within a vote (trait alias)
///
/// Input to [`ConsensusesFromVotes::consensuses`] and [`Aggregate::aggregate`].
pub(super) trait ComponentInVotes<T>: Iterator<Item = (VoterNum, T)> + Clone {}
impl<I, T> ComponentInVotes<T> for I where I: Iterator<Item = (VoterNum, T)> + Clone {}

/// Component of a vote, from which a corresponding consensus component can be calculated
///
/// Implemented on the *input*, ie the vote or part of a vote.
///
/// Implement this trait directly when the different flavours need different outputs.
///
/// Implement [`Aggregate`] instead, if the flavour doesn't matter.
/// There is a blanket implementation of `ConsensusesFromVotes` for any [`Aggregate`].
pub(super) trait ConsensusesFromVotes {
    /// The plain-flavourconsensus component
    type PlainOutput: Sized;
    /// The microdescriptor consensus component
    type MdOutput: Sized;

    /// Calculate the consensus components corresponding to the `Self` in the votes
    ///
    /// Takes as input the vote components (one per vote), and
    /// returns the consensus components, as a pair, one for each flavour.
    ///
    /// `inputs` is an iterator of references to the relevant parts of each vote.
    fn consensuses<'i>(
        context: &ConsensusContext,
        inputs: impl ComponentInVotes<&'i Self>,
    ) -> Result<(Self::PlainOutput, Self::MdOutput), ConsensusError>
    where
        Self: 'i;
}

/// Component of a vote from which a flavour-independent consensus component can be calculated
///
/// Implemented on the *input*, ie the vote or part of a vote.
///
/// Use `[ConsensusesFromVotes`] when flavour is relevant.
pub(super) trait Aggregate: Sized {
    /// The output (consensus) component type.  Often `Self`.
    type Output: Sized;

    /// Calculate the consensus component corresponding to the `Self` in the votes
    ///
    /// Takes as input the vote components (one per vote), and
    /// returns the corresponding consensus components.
    ///
    /// `inputs` is an iterator of references to the relevant parts of each vote.
    fn aggregate<'i>(
        context: &ConsensusContext,
        inputs: impl ComponentInVotes<&'i Self>,
    ) -> Result<Self::Output, ConsensusError>
    where
        Self: 'i;
}

impl<V: Aggregate> ConsensusesFromVotes for V {
    type PlainOutput = V::Output;
    type MdOutput = V::Output;

    fn consensuses<'i>(
        context: &ConsensusContext,
        inputs: impl ComponentInVotes<&'i Self>,
    ) -> Result<(Self::PlainOutput, Self::MdOutput), ConsensusError>
    where
        Self: 'i,
    {
        Ok((
            V::aggregate(context, inputs.clone())?,
            V::aggregate(context, inputs)?,
        ))
    }
}

/// Error during calculation of a consensus
///
/// Normally errors at this stage should be avoided, because that would prevent
/// us from participating in the consensus.
#[derive(thiserror::Error, Clone, Debug)]
#[non_exhaustive]
pub enum ConsensusError {
    /// Tried to calculate a consensus from no votes!
    #[error("tried to calculate a consensus from no votes!")]
    NoVotes,
}

/// "Global" inputs for calculating consensus from votes
pub(super) struct ConsensusContext {
    /// The consensus method for which to generate a consensus
    pub(super) method: SupportedConsensusMethod,

    /// The input votes (in their entirity)
    pub(super) votes: TiVec<VoterNum, tor_netdoc::doc::netstatus::vote::NetworkStatus>,
}
