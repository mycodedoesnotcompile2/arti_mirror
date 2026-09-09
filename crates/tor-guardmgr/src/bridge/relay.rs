//! Implementation code to make a bridge something that we can connect to and use to relay traffic.

use itertools::Itertools as _;
use tor_linkspec::{
    ChanTarget, CircTarget, HasAddrs, HasChanMethod, HasRelayIds, RelayIdRef, RelayIdType,
};

use super::{BridgeConfig, BridgeDesc};

/// The information about a Bridge that is necessary to connect to it and send
/// it traffic.
#[derive(Clone, Debug)]
pub struct BridgeRelay<'a> {
    /// The local configurations for the bridge.
    ///
    /// This is _always_ necessary, since it without it we can't know whether
    /// any pluggable transports are needed.
    bridge_line: &'a BridgeConfig,

    /// A descriptor for the bridge.
    ///
    /// If present, it MUST have every RelayId that the `bridge_line` does.
    ///
    /// `BridgeDesc` is an `Arc<>` internally, so we aren't so worried about
    /// having this be owned.
    desc: Option<BridgeDesc>,

    /// All the known addresses for the bridge.
    ///
    /// This includes the contact addresses in `bridge_line`, plus any addresses
    /// listed in `desc`.
    ///
    /// TODO(nickm): I wish we didn't have to reallocate a for this, but the API
    /// requires that we can return a reference to a slice of this.
    ///
    /// TODO(nickm): perhaps, construct this lazily?
    addrs: Vec<std::net::SocketAddr>,
}

/// A BridgeRelay that is known to have its full information available, and
/// which is therefore usable for multi-hop circuits.
///
/// (All bridges can be used for single-hop circuits, but we need to know the
/// bridge's descriptor in order to construct proper multi-hop circuits
/// with forward secrecy through it.)
#[derive(Clone, Debug)]
pub struct BridgeRelayWithDesc<'a>(
    /// This will _always_ be a bridge relay with a non-None desc.
    &'a BridgeRelay<'a>,
);

impl<'a> BridgeRelay<'a> {
    /// Construct a new BridgeRelay from its parts.
    pub(crate) fn new(bridge_line: &'a BridgeConfig, desc: Option<BridgeDesc>) -> Self {
        let addrs = bridge_line
            .addrs()
            .chain(desc.iter().flat_map(|d| d.as_ref().or_ports()))
            .unique()
            .collect();

        Self {
            bridge_line,
            desc,
            addrs,
        }
    }

    /// Return true if this BridgeRelay has a known descriptor and can be used for relays.
    pub fn has_descriptor(&self) -> bool {
        self.desc.is_some()
    }

    /// If we have enough information about this relay to build a circuit through it,
    /// return a BridgeRelayWithDesc for it.
    pub fn as_relay_with_desc(&self) -> Option<BridgeRelayWithDesc<'_>> {
        self.desc.is_some().then_some(BridgeRelayWithDesc(self))
    }
}

impl<'a> HasRelayIds for BridgeRelay<'a> {
    fn identity(&self, key_type: RelayIdType) -> Option<RelayIdRef<'_>> {
        self.bridge_line
            .identity(key_type)
            .or_else(|| self.desc.as_ref().and_then(|d| d.identity(key_type)))
    }
}

impl<'a> HasAddrs for BridgeRelay<'a> {
    /// Note: Remember (from the documentation at [`HasAddrs`]) that these are
    /// not necessarily addresses _at which the Bridge can be reached_. For
    /// those, use `chan_method`.  These addresses are used for establishing
    /// GeoIp and family info.
    fn addrs(&self) -> impl Iterator<Item = std::net::SocketAddr> {
        self.addrs.iter().copied()
    }
}

impl<'a> HasChanMethod for BridgeRelay<'a> {
    fn chan_method(&self) -> tor_linkspec::ChannelMethod {
        self.bridge_line.chan_method()
    }
}

impl<'a> ChanTarget for BridgeRelay<'a> {}

impl<'a> HasRelayIds for BridgeRelayWithDesc<'a> {
    fn identity(&self, key_type: RelayIdType) -> Option<RelayIdRef<'_>> {
        self.0.identity(key_type)
    }
}
impl<'a> HasAddrs for BridgeRelayWithDesc<'a> {
    /// Note: Remember (from the documentation at [`HasAddrs`]) that these are
    /// not necessarily addresses _at which the Bridge can be reached_. For
    /// those, use `chan_method`.  These addresses are used for establishing
    /// GeoIp and family info.
    fn addrs(&self) -> impl Iterator<Item = std::net::SocketAddr> {
        self.0.addrs()
    }
}
impl<'a> HasChanMethod for BridgeRelayWithDesc<'a> {
    fn chan_method(&self) -> tor_linkspec::ChannelMethod {
        self.0.chan_method()
    }
}

impl<'a> ChanTarget for BridgeRelayWithDesc<'a> {}

impl<'a> BridgeRelayWithDesc<'a> {
    /// Return a reference to the BridgeDesc in this reference.
    fn desc(&self) -> &BridgeDesc {
        self.0
            .desc
            .as_ref()
            .expect("There was supposed to be a descriptor here")
    }
}

impl<'a> CircTarget for BridgeRelayWithDesc<'a> {
    fn ntor_onion_key(&self) -> &tor_llcrypto::pk::curve25519::PublicKey {
        self.desc().as_ref().ntor_onion_key()
    }

    fn protovers(&self) -> &tor_protover::Protocols {
        self.desc().as_ref().protocols()
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
    use crate::bridge::test_util::*;
    use std::net::SocketAddr;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn without_descriptor() {
        let cfg = bridge(BRIDGE_LINE);
        let relay = BridgeRelay::new(&cfg, None);

        assert!(!relay.has_descriptor());
        assert!(relay.as_relay_with_desc().is_none());

        // Everything we know comes from the bridge line.
        assert!(relay.same_relay_ids(&cfg));
        assert!(relay.identity(RelayIdType::Ed25519).is_none());
        assert_eq!(relay.addrs().collect_vec(), cfg.addrs().collect_vec());
        assert_eq!(relay.chan_method(), cfg.chan_method());
    }

    #[test]
    fn with_descriptor() {
        let cfg = bridge(BRIDGE_LINE);
        let desc = bridge_desc();
        let relay = BridgeRelay::new(&cfg, Some(desc.clone()));

        assert!(relay.has_descriptor());

        // The RSA identity comes from the bridge line; the ed25519 identity is
        // learned from the descriptor.
        assert!(relay.has_all_relay_ids_from(&cfg));
        assert!(relay.same_relay_ids(&desc));
        assert_eq!(
            relay.identity(RelayIdType::Ed25519),
            desc.identity(RelayIdType::Ed25519)
        );

        // The bridge line and the descriptor list the same address, so we
        // should see it exactly once.
        assert_eq!(relay.addrs().collect_vec(), vec![addr("51.68.172.83:9001")]);

        // With a descriptor we can act as a CircTarget.
        let with_desc = relay.as_relay_with_desc().unwrap();
        assert_eq!(with_desc.chan_method(), cfg.chan_method());
        assert_eq!(with_desc.ntor_onion_key(), desc.as_ref().ntor_onion_key());
        assert_eq!(with_desc.protovers(), desc.as_ref().protocols());
    }

    #[test]
    fn descriptor_addresses_are_merged() {
        // The bridge line says to contact the bridge at an address other than
        // the one in its descriptor (say, it is behind a NAT).
        let cfg = bridge("192.0.2.1:443 EB6EFB27F29AC9511A4246D7ABE1AFABFB416FF1");
        let relay = BridgeRelay::new(&cfg, Some(bridge_desc()));

        // `addrs()` is for things like GeoIP and family lookup, so it should
        // include both.  (This is the current rule; #956 asks whether it is the
        // right one.  If that changes, this test should change with it.)
        assert_eq!(
            relay.addrs().collect_vec(),
            vec![addr("192.0.2.1:443"), addr("51.68.172.83:9001")]
        );
        // But we only ever contact the bridge the way the bridge line says.
        assert_eq!(relay.chan_method(), cfg.chan_method());
        assert_eq!(
            relay.chan_method().addrs().collect_vec(),
            vec![addr("192.0.2.1:443")]
        );
    }

    #[cfg(feature = "pt-client")]
    #[test]
    fn pluggable_transport() {
        // A bridge behind a pluggable transport, addressed by hostname: the
        // bridge line contributes no socket address at all.
        let cfg = bridge(
            "obfs4 bridge.example.com:443 EB6EFB27F29AC9511A4246D7ABE1AFABFB416FF1 iat-mode=0",
        );
        assert_eq!(cfg.addrs().count(), 0);

        let relay = BridgeRelay::new(&cfg, None);
        assert_eq!(relay.addrs().count(), 0);
        assert_eq!(relay.chan_method(), cfg.chan_method());
        assert!(matches!(
            relay.chan_method(),
            tor_linkspec::ChannelMethod::Pluggable(_)
        ));

        // The descriptor's OR port becomes known as an address, but we still
        // reach the bridge through the transport.
        let relay = BridgeRelay::new(&cfg, Some(bridge_desc()));
        assert_eq!(relay.addrs().collect_vec(), vec![addr("51.68.172.83:9001")]);
        assert_eq!(relay.chan_method(), cfg.chan_method());
    }
}
