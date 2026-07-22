//! DNS streams

use tor_proto::stream::IncomingStream;

/// Handle an incoming DNS stream
#[expect(clippy::unused_async)] // TODO(relay)
pub(crate) async fn handle_resolve(_incoming: IncomingStream) -> anyhow::Result<()> {
    todo!()
}
