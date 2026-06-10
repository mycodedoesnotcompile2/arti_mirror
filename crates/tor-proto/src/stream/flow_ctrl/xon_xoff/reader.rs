//! A wrapper for an [`AsyncRead`] to support XON/XOFF flow control.
//!
//! This allows any `AsyncRead` that implements [`BufferIsEmpty`] to be used with XON/XOFF flow
//! control.

use std::io::Error;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::{AsyncRead, Stream};
use pin_project::pin_project;
use tor_basic_utils::assert_val_impl_trait;
use tor_cell::relaycell::flow_ctrl::XonKbpsEwma;

use crate::stream::StreamTarget;
use crate::util::notify::NotifyReceiver;

/// A wrapper for an [`AsyncRead`] to support XON/XOFF flow control.
///
/// This reader will take care of communicating with the circuit reactor to handle XON/XOFF-related
/// events.
#[derive(Debug)]
#[pin_project]
pub(crate) struct XonXoffReader<R, T: DrainRateNotifier = StreamTarget> {
    /// How we communicate with the circuit reactor.
    #[pin]
    ctrl: XonXoffReaderCtrl<T>,
    /// The inner reader.
    #[pin]
    reader: R,
    /// Have we received a drain rate request notification from the reactor,
    /// but haven't yet sent a drain rate update back to the reactor?
    pending_drain_rate_update: bool,
}

impl<R, T: DrainRateNotifier> XonXoffReader<R, T> {
    /// Create a new [`XonXoffReader`].
    ///
    /// The reader must implement [`BufferIsEmpty`], which allows the `XonXoffReader` to check if
    /// the incoming stream buffer is empty or not.
    pub(crate) fn new(ctrl: XonXoffReaderCtrl<T>, reader: R) -> Self {
        Self {
            ctrl,
            reader,
            pending_drain_rate_update: false,
        }
    }

    /// Get a reference to the inner [`AsyncRead`].
    ///
    /// NOTE: This will bypass the [`XonXoffReader`] and may cause incorrect behaviour depending on
    /// how you use the returned reader (for example if it uses interior mutability).
    pub(crate) fn inner(&self) -> &R {
        &self.reader
    }

    /// Get a mutable reference to the inner [`AsyncRead`].
    ///
    /// NOTE: This will bypass the [`XonXoffReader`] and may cause incorrect behaviour depending on
    /// how you use the returned reader (for example if you read bytes directly).
    pub(crate) fn inner_mut(&mut self) -> &mut R {
        &mut self.reader
    }
}

impl<R: AsyncRead + BufferIsEmpty, T: DrainRateNotifier> AsyncRead for XonXoffReader<R, T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, Error>> {
        let mut self_ = self.project();

        // ensure that `drain_rate_request_stream` is a `FusedStream`,
        // which means that we don't need to worry about calling `poll_next()` repeatedly
        assert_val_impl_trait!(
            self_.ctrl.drain_rate_request_stream,
            futures::stream::FusedStream,
        );

        // check if the circuit reactor has requested a drain rate update
        if let Poll::Ready(Some(())) = self_
            .ctrl
            .as_mut()
            .project()
            .drain_rate_request_stream
            .poll_next(cx)
        {
            // a drain rate update was requested, so we need to send a drain rate update once we
            // have no more bytes buffered
            *self_.pending_drain_rate_update = true;
        }

        // try reading from the inner reader
        let res = self_.reader.as_mut().poll_read(cx, buf);

        // if we need to send a drain rate update and the stream buffer is empty, inform the reactor
        if *self_.pending_drain_rate_update && self_.reader.is_empty() {
            // TODO(arti#534): in the future we want to do rate estimation, but for now we'll just
            // send an "unlimited" drain rate
            self_
                .ctrl
                .drain_rate_notifier
                .notify(XonKbpsEwma::Unlimited)?;
            *self_.pending_drain_rate_update = false;
        }

        res
    }
}

/// Something that sends drain rate updates to the flow control logic (the `XonXoffFlowCtrl`).
pub(crate) trait DrainRateNotifier {
    /// Send the drain rate update.
    fn notify(&mut self, rate: XonKbpsEwma) -> Result<(), Error>;
}

impl DrainRateNotifier for StreamTarget {
    fn notify(&mut self, rate: XonKbpsEwma) -> Result<(), Error> {
        self.drain_rate_update(rate).map_err(Into::into)
    }
}

/// The control structure for a stream that partakes in XON/XOFF flow control.
///
/// Used to construct an [`XonXoffReader`].
///
/// This contains a mechanism for us to be asked for our drain rate,
/// and a mechanism of sending the drain rate in response.
///
/// The `DrainRateNotifier` is typically a `StreamTarget`,
/// which sends the drain rate to the circuit reactor so that it can be sent in an XON message.
/// We make this a trait to make unit testing possible.
#[derive(Debug)]
#[pin_project]
pub(crate) struct XonXoffReaderCtrl<T: DrainRateNotifier = StreamTarget> {
    /// Receive notifications when the reactor requests a new drain rate.
    /// When we do, we should begin waiting for the receive buffer to clear.
    /// Then when the buffer clears, we should send a new drain rate update to the reactor.
    #[pin]
    drain_rate_request_stream: NotifyReceiver<DrainRateRequest>,
    /// An abstract handle to the reactor for this stream.
    /// This allows us to send drain rate updates to the circuit reactor.
    drain_rate_notifier: T,
}

impl<T: DrainRateNotifier> XonXoffReaderCtrl<T> {
    /// Create a new [`XonXoffReaderCtrl`].
    ///
    /// The `drain_rate_request_stream` informs us when we need to send our drain rate,
    /// and `drain_rate_notifier` allows us to send that drain rate.
    pub(crate) fn new(
        drain_rate_request_stream: NotifyReceiver<DrainRateRequest>,
        drain_rate_notifier: T,
    ) -> Self {
        Self {
            drain_rate_request_stream,
            drain_rate_notifier,
        }
    }
}

/// Used by the [`XonXoffReader`] to decide when to send a drain rate update
/// (typically resulting in an XON message).
pub(crate) trait BufferIsEmpty {
    /// Returns `true` if there are no incoming bytes buffered on this stream.
    ///
    /// This takes a `&mut` so that implementers can
    /// [`unobtrusive_peek()`](tor_async_utils::peekable_stream::UnobtrusivePeekableStream::unobtrusive_peek)
    /// a stream if necessary.
    fn is_empty(self: Pin<&mut Self>) -> bool;
}

/// A marker type for a [`NotifySender`](crate::util::notify::NotifySender)
/// indicating that notifications are for new drain rate requests.
#[derive(Debug)]
pub(crate) struct DrainRateRequest;
