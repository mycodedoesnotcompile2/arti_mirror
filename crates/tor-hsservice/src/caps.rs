//! Helpers for capability declaration and negotiation.

use cfg_if::cfg_if;
use tor_cell::relaycell::hs::intro_payload::IntroduceHandshakePayload;
use tor_protover::Protocols;

use crate::IntroRequestError;

cfg_if! {
    if #[cfg(feature = "negotiate-extensions")] {
        use std::sync::LazyLock;
        use tor_protover::{NamedSubver, named::*};

        /// An array of protocols that can be requested via a subprotocol
        /// request extension.
        ///
        /// Note that we don't necessarily support all of these ourselves!
        static REQUESTABLE_LIST: &[NamedSubver] = &[
             RELAY_NEGOTIATE_SUBPROTO,
             RELAY_CRYPT_CGO
        ];

        /// A set of protocols that can be requested via a subprotocol request extension.
        static REQUESTABLE: LazyLock<Protocols> = LazyLock::new(
            || REQUESTABLE_LIST.iter().copied().collect()
        );

        /// A set of protocols that we should advertise, if supported,
        /// in our `flow-control` line.
        static ADVERTISE_FLOWCTRL: LazyLock<Protocols> = LazyLock::new(
            || [FLOWCTRL_AUTH_SENDME, FLOWCTRL_CC].into_iter().collect()
        );
    }
}

/// Return the list of protocols that we should advertise in our hsdesc.
pub(crate) fn declared_protocols() -> Protocols {
    cfg_if! {
        if #[cfg(feature = "negotiate-extensions")] {
            tor_proto::supported_client_protocols().intersection(&REQUESTABLE)
        } else {
            Protocols::new()
        }
    }
}

/// Return the flow control information that we should include in our hsdesc.
pub(crate) fn declared_flowctrl(
    params: &tor_netdir::params::NetParameters,
) -> Option<(Protocols, u8)> {
    cfg_if! {
        if #[cfg(feature = "negotiate-extensions")] {
            let supported = tor_proto::supported_client_protocols();
            supported.supports_named_subver(FLOWCTRL_CC).then(|| {
                (
                    supported.intersection(&ADVERTISE_FLOWCTRL),
                    params.cc_sendme_inc.into()
                )
            })
        } else {
            None
        }
    }
}
