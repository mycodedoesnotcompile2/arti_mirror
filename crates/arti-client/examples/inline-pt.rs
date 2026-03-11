// @@ begin example lint list maintained by maint/add_warning @@
#![allow(unknown_lints)] // @@REMOVE_WHEN(ci_arti_nightly)
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
//! <!-- @@ end example lint list maintained by maint/add_warning @@ -->

//! This example shows how to register a programmatic pluggable transport
//! manager with `arti-client`.
//!
//! The connector below is intentionally simple: it treats the PT target like a
//! direct TCP endpoint and does not implement any real obfuscation layer. That
//! makes it useful for understanding the API shape without depending on an
//! actual transport implementation.

#[cfg(feature = "pt-client")]
use {
    anyhow::Result,
    arti_client::TorClient,
    arti_client::config::pt::{InlinePtConnector, InlinePtMgr},
    arti_client::config::{BoolOrAuto, BridgeConfigBuilder, TorClientConfigBuilder},
    async_trait::async_trait,
    safelog::MaybeSensitive,
    std::sync::Arc,
    tokio_crate as tokio,
    tor_linkspec::PtTarget,
    tor_proto::peer::PeerAddr,
    tor_rtcompat::{NetStreamProvider, PreferredRuntime},
};

#[cfg(feature = "pt-client")]
type Runtime = PreferredRuntime;

#[cfg(feature = "pt-client")]
type Stream = <Runtime as NetStreamProvider>::Stream;

#[cfg(feature = "pt-client")]
#[derive(Clone)]
struct PassthroughConnector {
    runtime: Runtime,
}

#[cfg(feature = "pt-client")]
#[async_trait]
impl InlinePtConnector<Stream> for PassthroughConnector {
    async fn connect(&self, target: &PtTarget) -> tor_chanmgr::Result<(PeerAddr, Stream)> {
        let addr = target
            .socket_addrs()
            .and_then(|addrs| addrs.first())
            .copied()
            .ok_or_else(|| {
                tor_chanmgr::Error::UnusableTarget(tor_error::bad_api_usage!(
                    "this example connector expects a bridge line with an IP:port"
                ))
            })?;

        let stream =
            self.runtime
                .connect(&addr)
                .await
                .map_err(|source| tor_chanmgr::Error::Io {
                    peer: MaybeSensitive::not_sensitive(PeerAddr::from(target.clone())),
                    action: "connecting to inline PT target",
                    source: Arc::new(source),
                })?;

        Ok((PeerAddr::from(target.clone()), stream))
    }
}

#[cfg(feature = "pt-client")]
#[tokio::main]
async fn main() -> Result<()> {
    let runtime = PreferredRuntime::current()?;

    let inline_pt = InlinePtMgr::new(runtime.clone());
    inline_pt.register_transport(
        "passthrough".parse()?,
        Arc::new(PassthroughConnector {
            runtime: runtime.clone(),
        }),
    );

    let state_dir = tempfile::tempdir()?;
    let cache_dir = tempfile::tempdir()?;
    let mut config = TorClientConfigBuilder::from_directories(state_dir.path(), cache_dir.path());

    config.bridges().enabled(BoolOrAuto::Explicit(true));

    let mut bridge = BridgeConfigBuilder::default();
    bridge.transport("passthrough");
    bridge.set_addrs(vec!["198.51.100.7:443".parse()?]);
    bridge.set_ids(vec!["0123456789ABCDEF0123456789ABCDEF01234567".parse()?]);
    config.bridges().bridges().push(bridge);

    let config = config.build()?;

    // No `[bridges.transports]` entry is needed here: the programmatic PT
    // manager handles the transport directly.
    let _client = TorClient::with_runtime(runtime)
        .config(config)
        .pluggable_transport_manager(Arc::new(inline_pt))
        .create_unbootstrapped()?;

    eprintln!("constructed a client with an inline pluggable transport manager");
    Ok(())
}

#[cfg(not(feature = "pt-client"))]
pub fn main() {
    panic!("this example can only run with feature `pt-client` enabled");
}
