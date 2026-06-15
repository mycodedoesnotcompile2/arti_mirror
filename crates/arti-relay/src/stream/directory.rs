//! Directory streams

use futures::channel::mpsc;
use tor_proto::stream::IncomingStream;

// TODO(#2570): once we dust settles on the implementation,
// we need to factor this out of the client module.
use tor_proto::client::stream::DataStream;

/// Handle an incoming directory stream
pub(super) async fn handle_begin_dir(
    incoming: IncomingStream,
    mut begin_dir_tx: mpsc::Sender<tor_proto::Result<DataStream>>,
) -> anyhow::Result<()> {
    todo!()
}
