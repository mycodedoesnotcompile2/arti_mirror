//! Code for parsing the relay specific config options.

use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};

use derive_deftly::Deftly;
use derive_more::Constructor;
use serde::{Deserialize, Serialize};
use tor_config::ConfigBuildError;
use tor_config::derive::prelude::*;
use tor_netdoc::types::{ContactInfo, Nickname};

use super::{
    BandwidthConfig, BandwidthConfigBuilder, DnsConfig, DnsConfigBuilder, Listen, TestingConfig,
    TestingConfigBuilder,
};
use crate::util::NonEmptyList;

/// Configuration for the "relay" part of the relay.
///
/// TODO: I'm not really sure what to call this yet. I'm expecting that we'll rename and reorganize
/// things as we add more options. But we should come back to this and update the name and/or doc
/// comment.
///
/// TODO: There's a high-level issue for discussing these options:
/// <https://gitlab.torproject.org/tpo/core/arti/-/issues/2252>
#[derive(Debug, Clone, Deftly, Eq, PartialEq)]
#[derive_deftly(TorConfig)]
#[deftly(tor_config(no_default_trait))]
pub(crate) struct RelayConfig {
    /// The nickname of this relay.
    ///
    /// Nicknames are a legacy (and fun!) mechanism that is occasionally useful for
    /// debugging. They should never be used to uniquely identify a relay. Nothing
    /// prevents two relays from having the same nickname.
    ///
    /// It must be between 1 and 19 ASCII alphanumeric characters inclusive.
    #[deftly(tor_config(default = "default_nickname()"))]
    pub(crate) nickname: Nickname,

    /// Contact information for the operator(s) of this relay.
    ///
    /// This is published in the descriptor so that the network health team can reach you
    /// if there is a problem with the relay. It is free-form text but it must be a
    /// single line and must not start with whitespace.
    ///
    /// If unset, the descriptor is published without a contact information.
    //
    // TODO(relay): Before stable, we need to settle with Network Health team on the
    // format of that contact info. It will still be a free-form string in the descriptor
    // but we'll likely enforce a format at the config level.
    #[deftly(tor_config(default))]
    pub(crate) contact: Option<ContactInfo>,

    /// Addresses to listen on for incoming OR connections.
    #[deftly(tor_config(no_default))]
    pub(crate) listen: Listen,

    /// The DNS configuration.
    #[deftly(tor_config(sub_builder))]
    pub(crate) dns: DnsConfig,

    /// The bandwidth rate limiting configuration.
    #[deftly(tor_config(sub_builder))]
    pub(crate) bandwidth: BandwidthConfig,

    /// Options that are only meant for test networks.
    #[deftly(tor_config(sub_builder))]
    pub(crate) testing: TestingConfig,

    /// Addresses to advertise on the network for receiving OR connections.
    ///
    /// All values must be unicast addresses with non-zero ports and no IPv6 zones. Private and
    /// other internal IP addresses such as 127.0.0.1 or 10.0.0.0/8 may only be used when using
    /// custom directory authorities (for test networks).
    // For now, we've decided that we don't want to include any IP address auto-detection in
    // arti-relay, so we require users to provide the addresses to advertise. (So no `Option` and
    // `builder(default)` here).
    #[deftly(tor_config(no_default))]
    pub(crate) advertise: Advertise,
}

/// The address(es) to advertise on the network.
///
/// These are validated in [`validate_advertised`] after the full configuration is constructed,
/// because it depends on the directory authorities whether internal addresses are permitted.
//
// TODO(relay): As of now there is no config reload, but if those parameters ever become changeable
// at runtime, we should do the same thing that C-tor's `ip_address_changed()` does: reset our
// reachability status, restart the bandwidth self-test (if we have been running for more than 6
// hours), and publish a new descriptor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Constructor)]
pub(crate) struct Advertise {
    /// All relays must advertise an IPv4 address.
    ///
    /// The first IPv4 address is considered the relay's primary address.
    ipv4: NonEmptyList<SocketAddrV4>,
    /// Relays may optionally advertise an IPv6 address.
    ipv6: Vec<SocketAddrV6>,
}

impl Advertise {
    /// Return all addresses (both IPv4 and IPv6) as in IP + Port ([`SocketAddr`]).
    pub(crate) fn all_addr(&self) -> Vec<SocketAddr> {
        self.ipv4
            .iter()
            .map(|s| (*s).into())
            .chain(self.ipv6.iter().map(|s| (*s).into()))
            .collect()
    }

    /// Return the primary IPv4 address.
    ///
    /// This is used to get the `router` line of our server descriptor.
    pub(crate) fn primary_ipv4(&self) -> &SocketAddrV4 {
        self.ipv4.iter().next().expect("No primary IPv4")
    }
}

/// Ensure the advertised addresses are publishable in a descriptor.
///
/// Ports of zero, unspecified addresses, multicast addresses, broadcast addresses, and IPv6
/// addresses containing zones and/or flow labels are always rejected. If `allow_internal` is false,
/// then we refuse any "internal" address ([`is_internal`]). C-tor uses this logic within its
/// `address_can_be_used()` function, too. That way, private testing networks can use addresses like
/// 127.0.0.1 for their ORs without breaking things, but real authorities will reject descriptors
/// containing internal addresses (via `dirserv_router_has_valid_address()`).
pub(super) fn validate_advertised(
    advertise: &Advertise,
    allow_internal: bool,
) -> Result<(), ConfigBuildError> {
    let invalid = |problem: String| ConfigBuildError::Invalid {
        field: "relay.advertise".to_owned(),
        problem,
    };

    for addr in advertise.all_addr() {
        let ip = addr.ip().to_canonical();
        if addr.port() == 0 {
            return Err(invalid(format!("{addr} has port 0")));
        }
        let is_broadcast = matches!(ip, IpAddr::V4(v4) if v4.is_broadcast());
        if ip.is_unspecified() || ip.is_multicast() || is_broadcast {
            return Err(invalid(format!(
                "{addr} is an unspecified, multicast or broadcast address"
            )));
        }
        // The descriptor would include the zone (as "%3") that C-tor cannot parse, and any
        // unparseable `or-address` is discarded (`find_single_ipv6_orport()`).
        if matches!(addr, SocketAddr::V6(v6) if v6.scope_id() != 0 || v6.flowinfo() != 0) {
            return Err(invalid(format!("{addr} has an IPv6 zone or flow label")));
        }
        if !allow_internal && is_internal(ip) {
            return Err(ConfigBuildError::Inconsistent {
                fields: vec![
                    "relay.advertise".to_owned(),
                    "tor_network.authorities".to_owned(),
                ],
                problem: format!(
                    "{addr} is a private address, which needs custom directory authorities"
                ),
            });
        }
    }
    Ok(())
}

/// Return true if `ip` is an internal address not reachable from the internet.
///
/// This is precisely the set of addresses that C-tor's `tor_addr_is_internal()` treats as internal
/// (when not listening), which are the ones rejected by the DAs. As with C-tor, we interpret
/// IPv4-mapped IPv6 addresses as IPv4 for this check.
//
// Two other Arti checks use different sets. `ChanTarget::all_addrs_allowed_for_outgoing_channels`
// (tor-linkspec) also forbids IPv4 documentation and all multicasts, but allows 100.64.0.0/10,
// fec0::/10, and all of 0.0.0.0/8 except for 0.0.0.0. The `is_globally_reachable_unicast` check
// (arti-client) also rejects broadcasts and multicasts, but allows fec0::/10 and all of 0.0.0.0/8
// except for 0.0.0.0.
fn is_internal(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            let [a, b, _, _] = v4.octets();
            a == 0 // 0.0.0.0/8
                || v4.is_private() // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                || v4.is_loopback() // 127.0.0.0/8
                || (a == 100 && (b & 0xc0) == 64) // 100.64.0.0/10
                || v4.is_link_local() // 169.254.0.0/16
        }
        IpAddr::V6(v6) => {
            v6.is_unspecified() // ::
                || v6.is_loopback() // ::1
                || v6.is_unique_local() // fc00::/7
                || v6.is_unicast_link_local() // fe80::/10
                || (v6.segments()[0] & 0xffc0) == 0xfec0 // fec0::/10
        }
    }
}

/// Return the default relay nickname. Again, taken from C-tor.
pub(crate) fn default_nickname() -> Nickname {
    "Unnamed".parse().expect("Default nickname is invalid")
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

    #[test]
    fn contact_valid() {
        for info in [
            "Arti relay team",
            "8096R/13371337 Rosa Park<rosa.park@awesome.com>",
            "trailing whitespace is fine  ",
            "Du français avec accent ééé, on aime!",
        ] {
            let contact: ContactInfo = info.parse().unwrap();
            assert_eq!(contact.to_string(), info);
        }
    }

    #[test]
    fn contact_invalid() {
        for info in [
            " leading whitespace", // Leading whitespace
            "\tleading tab",       // Same but with a tab
            "two\nlines",          // New line
            "trailing newline\n",  // Trailing new line
        ] {
            assert!(info.parse::<ContactInfo>().is_err());
        }
    }

    #[test]
    fn nickname_valid() {
        // Some basic names that are all valid.
        for name in ["Unnamed", "a", "42", "Op3nB0rd3rs", "A".repeat(19).as_str()] {
            let nickname: Nickname = name.parse().unwrap();
            assert_eq!(nickname.to_string(), name);
        }
    }

    #[test]
    fn nickname_invalid() {
        for name in [
            "",                      // Too short
            "A".repeat(20).as_str(), // Too long
            "with space",            // Windows spaces...
            "under_score",           // Non alphanumeric
            "dash-ing",              // Non alphanumeric
            "unicödé",               // The French... :P
        ] {
            assert!(name.parse::<Nickname>().is_err());
        }
    }
}
