//! Exit streams

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Context as _;
use futures::io::BufReader;
use tor_cell::relaycell::msg::{BeginAddr, BeginFlags, Connected, End, EndReason};
use tor_error::warn_report;
use tor_proto::stream::{IncomingStream, IncomingStreamRequest};
use tor_rtcompat::Runtime;
use tor_rtcompat::SleepProviderExt as _;
use tracing::{debug, info, trace};

/// Handle an incoming exit stream.
///
/// This is expected to be called from a task dedicated to this stream,
/// so it may async-block (for example to establish the exit connection and proxy traffic).
/// It should not be used with a timeout.
pub(super) async fn handle_begin<R: Runtime>(
    runtime: R,
    incoming: IncomingStream,
) -> anyhow::Result<()> {
    let connect_options = Default::default();

    // It would be nice to have a better API on `IncomingStream`
    // so that we don't need this extra match.
    let msg = match incoming.request() {
        IncomingStreamRequest::Begin(msg) => msg,
        s => {
            return Err(anyhow::anyhow!(
                "unexpected stream request type {s:?}; should be unreachable"
            ));
        }
    };

    // TODO: This is temporary. Remove this once we have exit policy support.
    // This is to help prevent us from accidentally running a public exit while we're testing.
    match std::env::var("ARTI_EXIT") {
        Ok(val) if val.trim() == "1" => {}
        _ => {
            info!("Rejecting incoming stream since `ARTI_EXIT` env variable is not set to '1'");
            return Ok(());
        }
    }

    // Assign these to local variables to ensure we use all of them.
    #[deny(unused)]
    let (addr, port, flags) = (msg.addr(), msg.port(), msg.flags());

    let addr = addr
        .decode()
        .context("failed to decode address from BEGIN message")?;

    let exit_stream_fut = match addr {
        BeginAddr::Ip(addr) => {
            if addr.is_ipv4() && flags.contains(BeginFlags::IPV4_NOT_OKAY) {
                // TODO: Should we use `NOROUTE` here?
                incoming.reject(End::new_misc()).await?;
                debug!(
                    "Rejecting incoming stream to IPv4 address since flags contains IPV4_NOT_OKAY",
                );
                return Ok(());
            }

            if addr.is_ipv6() && !flags.contains(BeginFlags::IPV6_OKAY) {
                // TODO: Should we use `NOROUTE` here?
                incoming.reject(End::new_misc()).await?;
                debug!(
                    "Rejecting incoming stream to IPv6 address since flags did not contain IPV6_OKAY",
                );
                return Ok(());
            }

            // TODO: Need to support an exit policy. Currently we allow exits to anywhere (except
            // basic loopback checks) for testing purposes.
            if addr.to_canonical().is_loopback() || addr.to_canonical().is_unspecified() {
                incoming
                    .reject(End::new_with_reason(EndReason::EXITPOLICY))
                    .await?;
                debug!("Rejecting incoming stream to loopback address");
                return Ok(());
            }

            let addr = SocketAddr::new(addr, port.get());

            let runtime = &runtime;
            async move { runtime.connect(&addr, &connect_options).await }
        }
        BeginAddr::Hostname(_addr) => {
            // TODO: Once we can look up hostnames,
            // we'll probably (maybe?) want to be able to do happy eyeballs with both addresses.
            // We should find a way to resuse our existing happy eyeballs code.
            // https://gitlab.torproject.org/tpo/core/arti/-/work_items/2510
            // TODO: Need to take `BeginFlags::IPV6_PREFERRED` (and other flags) into account here.
            // https://spec.torproject.org/tor-spec/opening-streams.html
            todo!()
        }
    };

    // TODO(tuning): timeout chosen arbitrarily
    let timeout = Duration::from_secs(30);
    let exit_stream = runtime.timeout(timeout, exit_stream_fut).await??;

    let tor_stream = incoming.accept_data(Connected::new_empty()).await?;

    // TODO(tuning): copied from arti
    const STREAM_BUF_LEN: usize = 4096;
    let exit_stream = BufReader::with_capacity(STREAM_BUF_LEN, exit_stream);
    let tor_stream = BufReader::with_capacity(STREAM_BUF_LEN, tor_stream);

    let res = futures_copy::copy_buf_bidirectional(
        tor_stream,
        exit_stream,
        futures_copy::eof::Close,
        futures_copy::eof::Close,
    )
    .await;

    match res {
        Ok((tor_to_exit, exit_to_tor)) => {
            trace!(
                count_fwd = tor_to_exit,
                count_bwd = exit_to_tor,
                "Stream bidirectional copy finished",
            );
        }
        // TODO: arti does something complicated here; see `report_proxy_error()`
        Err(e) => {
            warn_report!(e, "Error while proxying data on exit stream");
        }
    }

    Ok(())
}
