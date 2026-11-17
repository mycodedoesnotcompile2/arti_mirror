//! Implementation of `compute-consensus` method

use super::*;

/// One authority, that we trust
///
/// Arguments to an `auth`
///
/// As per in `--ids` in `authority-plugin.md`
#[derive(Clone, Debug, PartialEq, Eq, Deftly)]
#[derive_deftly(ItemValueParseable)]
struct TrustedAuthority {
    /// nickname, for error reporting only
    nickname: Nickname,

    /// `SHA1(DER(KP_auth_id_rsa))`
    kp_auth_id_rsa: Fingerprint,
}

/// The trusted authorities input file (`--ids`)
///
/// As per in `--ids` in `authority-plugin.md`
#[derive(Clone, Debug, PartialEq, Eq, Deftly)]
#[derive_deftly(NetdocParseable)]
struct TrustedAuthorityLine {
    /// The `auth` item, which is the only item in this "document"
    auth: TrustedAuthority,
}

/// Vote, checked for validity
///
/// Very similar to [`tor_dirauth::consensus::VoteInput`], but contains owned values.
#[derive(Deftly)]
#[derive_deftly(CheckedVote)]
struct CheckedVote {
    /// Actual vote body
    vote: netstatus::vote::NetworkStatus,

    /// Auth nickname (from `TrustedAuthority`)
    nickname: Nickname,

    /// Signature hashes
    sig_hashes: netstatus::DirectorySignaturesHashesAccu,
}

define_derive_deftly! {
    /// Derives applied only to [`CheckedVote`]
    ///
    /// Expands to `as_consensus_input`
    CheckedVote beta_deftly:

    $impl {
        /// Yields a [`tor_dirauth::consensus::VoteInput`] referencing this `CheckedVote`
        fn as_consensus_input(&self) -> consensus::VoteInput<'_> {
            consensus::VoteInput { $(
                $fname: &self.$fname,
            ) }
        }
    }
}
#[allow(clippy::single_component_path_imports)] // false positive, see rust-clippy#13419
use derive_deftly_template_CheckedVote;

/// Error checking a vote: might be merely logged, ignoring the vote; or might be fatal
#[derive(Debug, thiserror::Error)]
enum VoteError {
    /// verify failed
    #[error("failed to verify vote allegedly from {alleged_nickname}")]
    VerifyFailed {
        /// The error
        #[source]
        error: netstatus::VoteVerifyFailed,
        /// Which alleged voter?
        alleged_nickname: Nickname,
    },

    /// time validity error
    #[error("vote not valid now")]
    OutsideValidityPeriod(#[from] tor_checkable::TimeValidityError),

    /// varying lifetimes
    #[error("not all input votes had the same lifetime: {_0:?} != {_1:?}")]
    VaryingLifetimes(netstatus::Lifetime, netstatus::Lifetime),

    /// bug
    #[error("internal error while checking vote")]
    Bug(#[from] Bug),
}

impl VoteError {
    /// Should we throw `CliError` and exit?
    ///
    /// `Err` means to exit immediately; `Ok` means to just log and skip this vote.
    fn crash(self) -> Result<Self, anyhow::Error> {
        use VoteError as VE;
        match self {
            VE::VerifyFailed {
                error: err @ netstatus::VoteVerifyFailed::DuplicateAuthority(_),
                ..
            } => Err(err.into()),

            VE::VerifyFailed { .. } | //_
            VE::OutsideValidityPeriod { .. } => Ok(self),

            VE::VaryingLifetimes { .. } | //_
            VE::Bug { .. } => Err(self.into()),
        }
    }
}

/// Check that a vote is good
fn check_vote(
    now: SystemTime,
    authorities: &[TrustedAuthority],
    verifier: &mut netstatus::VoteVerifier,
    identical_lifetimes: &mut Option<netstatus::Lifetime>,
    uv: netstatus::vote::NetworkStatusUnverified,
) -> Result<CheckedVote, VoteError> {
    let alleged_signer = uv
        .inspect_unverified()
        .0
        .authority
        .authority
        .dir_source
        .identity;
    let alleged_auth = authorities
        .iter()
        .find(|a| a.kp_auth_id_rsa == alleged_signer)
        .ok_or_else(|| internal!("signing auithority not found but sig verified?!"))?;
    let alleged_nickname = alleged_auth.nickname.clone();

    let sig_hashes = uv.sigs.hashes;
    let vote = uv
        .verify(verifier)
        .map_err(|error| VoteError::VerifyFailed {
            error,
            alleged_nickname: alleged_nickname.clone(),
        })?
        .if_valid_at(&now)?;

    // We have verified the signature based on `TrustedAuthority`, so we know
    // that this *is* the authority that we know as `nickname`.
    // We ignore the nickname within the vote, in favour of the one in our configuration.
    let nickname = alleged_nickname;

    {
        let this = &vote.preamble.lifetime;
        let prev = identical_lifetimes.get_or_insert_with(|| this.clone());
        if this != prev {
            return Err(VoteError::VaryingLifetimes(prev.clone(), this.clone()));
        }
    }

    Ok(CheckedVote {
        vote,
        nickname,
        sig_hashes,
    })
}

/// Computes a consensus from the input votes
///
/// Checks the votes, determines the right consensus method, and returns the consensuses.
fn compute(
    now: SystemTime,
    authorities: &[TrustedAuthority],
    votes: impl Iterator<Item = netstatus::vote::NetworkStatusUnverified>,
) -> Result<consensus::Consensuses, CliError> {
    let mut identical_lifetimes = None;
    let mut verifier = netstatus::VoteVerifier::new(authorities.iter().map(|a| *a.kp_auth_id_rsa));

    let votes: Vec<_> = votes
        .filter_map(|uv| {
            let alleged = uv
                .inspect_unverified()
                .0
                .authority
                .authority
                .dir_source
                .identity;
            match check_vote(
                now,
                authorities,
                &mut verifier,
                &mut identical_lifetimes,
                uv,
            ) {
                Err(e) => match e.crash() {
                    Err(crash) => Some(Err(CliError::OperationalError(
                        crash.context(format!("vote allegedly from {alleged}")),
                    ))),
                    Ok(ignore) => {
                        eprintln!(
                            "ignoring vote allegedly from {alleged}: {}",
                            ignore.report(),
                        );
                        None
                    }
                },
                Ok(y) => Some(Ok(y)),
            }
        })
        .try_collect()?;

    if votes.is_empty() {
        return Err(CliError::OperationalError(anyhow!(
            "all votes rejected, cannot calculate consensus"
        )));
    }

    let consensuses = match consensus::compute_consensus_from_votes(
        authorities.len(),
        votes.iter().map(|cv| cv.as_consensus_input()),
    ) {
        Err(consensus::ConsensusError::UnsupportedMethodChosen(method)) => Err(method)?,
        other => other.map_err(|e| {
            CliError::OperationalError(
                anyhow::Error::from(e).context("failed to calculate consensus"),
            )
        })?,
    };

    Ok(consensuses)
}

/// Computes a consensus from the input votes
///
/// Checks the votes, determines the right consensus method, and returns the consensuses.
pub(crate) fn read_compute(
    now: SystemTime,
    trusted: &parse2::ParseInput,
    votes: &[parse2::ParseInput],
) -> Result<consensus::Consensuses, CliError> {
    let trusted: Vec<TrustedAuthorityLine> = parse2::parse_netdoc_multiple(trusted)
        .context("parse ids list")
        .map_err(CliError::OperationalError)?;
    let trusted = trusted.into_iter().map(|t| t.auth).collect_vec();

    let votes: Vec<_> = votes
        .iter()
        .map(|input| {
            parse2::parse_netdoc_multiple_sophisticated::<netstatus::vote::NetworkStatusUnverified>(
                input,
            )
            .map(|parsed| {
                parsed.into_iter().filter_map(|(r, start, end)| match r {
                    Ok(y) => Some(y),
                    Err(e) => {
                        eprintln!("bad vote at {start}..{end}: {}", e.report());
                        None
                    }
                })
            })
        })
        .flatten_ok()
        .try_collect()?;

    compute(now, &trusted, votes.into_iter())
}
