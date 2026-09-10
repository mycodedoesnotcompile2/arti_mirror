//! Code to configure and manage a set of bridge relays.
//!
//! A bridge relay, or "bridge" is a tor relay not listed as part of Tor
//! directory, in order to prevent censors from blocking it.  Instead, clients
//! learn about bridges out-of-band, and contact them either directly or via a
//! pluggable transport.
//!
//! When a client is configured to use bridges, it uses them in place of its
//! regular set of guards in building the first hop of its circuits.
mod config;
mod descs;
mod relay;

pub use config::{BridgeConfig, BridgeConfigBuilder, BridgeParseError};
pub use descs::{BridgeDesc, BridgeDescError, BridgeDescEvent, BridgeDescList, BridgeDescProvider};
pub use relay::BridgeRelay;

pub(crate) use descs::BridgeSet;

/// Fixtures shared by the bridge tests in this crate.
#[cfg(test)]
pub(crate) mod test_util {
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
    use std::sync::Arc;
    use tor_checkable::{SelfSigned, Timebound};
    use tor_netdoc::doc::routerdesc::RouterDesc;

    /// A real router descriptor, as a bridge would serve it.
    ///
    /// Its identities and address match [`BRIDGE_LINE`].
    pub(crate) const DESCRIPTOR: &str = include_str!("../testdata/routerdesc1.txt");

    /// A bridge line for the bridge described by [`DESCRIPTOR`].
    ///
    /// It lists only the RSA identity; the ed25519 identity is only
    /// discoverable from the descriptor.
    pub(crate) const BRIDGE_LINE: &str =
        "51.68.172.83:9001 EB6EFB27F29AC9511A4246D7ABE1AFABFB416FF1";

    /// The ed25519 identity from [`DESCRIPTOR`], as it would appear in a bridge line.
    pub(crate) const ED_ID: &str = "ed25519:z3PGka1FKJSLKyhTCsu0lQsSr6Rq3HRQJ4vgWodVmR4";

    /// Two more bridges, for which we have no descriptor.
    pub(crate) const BRIDGE_2: &str = "192.0.2.2:9001 2222222222222222222222222222222222222222";
    pub(crate) const BRIDGE_3: &str = "192.0.2.3:9001 3333333333333333333333333333333333333333";

    /// Parse `line` as a [`BridgeConfig`].
    pub(crate) fn bridge(line: &str) -> BridgeConfig {
        line.parse()
            .unwrap_or_else(|e| panic!("bad bridge line {line:?}: {e}"))
    }

    /// The [`BridgeDesc`] for [`DESCRIPTOR`].
    ///
    /// The descriptor was published in 2020, so we skip the timeliness check
    /// (and the signature check, which is tor-netdoc's job).
    pub(crate) fn bridge_desc() -> BridgeDesc {
        let desc = RouterDesc::parse(DESCRIPTOR)
            .unwrap()
            .dangerously_assume_wellsigned()
            .dangerously_assume_timely();
        BridgeDesc::new(Arc::new(desc))
    }
}
