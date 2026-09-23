//! Calculate the body of a routerstatus we have decided to include

use super::*;
use rs_common::*;

impl<'i> ResolvedRouterStatusInputs<'i> {
    /// Calculate the plain and md routerstatuses
    ///
    /// Similar to `ConsensusesFromVotes::consensuses`,
    /// but takes one `ResolvedRouterStatusInputs`, which includes not only
    /// the routerstatuses from each vote, but also the id-tuple and status-tuple
    /// from the resolution part of the algorithm.
    ///
    /// Can return `None` to mean that this router should not be listed after all
    /// (eg, because its listing would lack the Running flag).
    #[allow(clippy::unnecessary_wraps)] // for consistency; also, might change
    pub(super) fn consensuses(
        &self,
        context: &ConsensusContext,
    ) -> Result<
        Option<(
            //
            netstatus::plain::RouterStatus,
            netstatus::md::RouterStatus,
        )>,
        ConsensusError,
    > {
        let inputs = self
            .per_voter
            .iter_enumerated()
            .filter_map(|(vnum, rs_v)| Some((vnum, rs_v.as_ref()?)));

        /// Copy a field from `self.status_tuple` to the output.
        ///
        /// `from_status_tuple! { OUT . FIELD; SUFFIX }` is equivalent to
        /// `calc! { OUT.FIELD = self.status_tuple.FIELD SUFFIX }``
        ///
        /// The `; SUFFIX` may be omitted.
        macro_rules! from_status_tuple {
            { $out:ident . $field:ident $(; $($suffix:tt)* )? } => {
                calc! { $out.$field = self.status_tuple.$field $( $($suffix)+ )? }
            };
        }

        let (plain_r, md_r) = {
            calc! { both.identity    = self.id.rsa }
            calc! { both.publication = netstatus::IgnoredPublicationTimeSp }
            from_status_tuple! { both.ip }
            from_status_tuple! { both.nickname; .clone() }
            from_status_tuple! { plain.doc_digest; .into() }
            from_status_tuple! { both.or_port }
            from_status_tuple! { both.dir_port }

            // TODO DIRAUTH replace dummy value; actually calculate which md digest to include
            calc! { md.doc_digest = Default::default() }

            construct_both! {
                netstatus::plain::RouterStatusIntroItem, netstatus::md::RouterStatusIntroItem {
                    both. nickname, identity, doc_digest, publication, ip;
                } {
                    both. or_port, dir_port;
                }
            }
        };

        calc! { both.ed25519_id = NotPresent }
        calc! { plain.m = NotPresent }

        // TODO DIRAUTH replace routerstatus dummy values
        calc! { both.flags = DocRelayFlags::new_empty_unknown_discarded() }
        calc! { both.protos = Default::default() }
        calc! { both.weight = Default::default() }
        calc! { md.m = [0; 32].into() }

        Ok(Some(construct_both! {
            netstatus::plain::RouterStatus, netstatus::md::RouterStatus {
                both. r, m, flags, protos, weight, ed25519_id;
            } {
                // TODO DIRAUTH routerstatus fields missing
            }
        }))
    }
}
