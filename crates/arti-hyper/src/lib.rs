use std::{pin::Pin, future::Future, io, task::{Context, Poll}};
use hyper::rt::{Read, Write};
use tower_service::Service;
use http::Uri;
use arti_client::{TorClient, IntoTorAddr};
use tor_rtcompat::Runtime;
use tor_proto::client::stream::DataStream;

#[cfg(feature="tokio")]
pub mod io_adapter_tokio;

#[cfg(all(feature="tokio", feature="rustls"))]
pub mod tls_rustls_tokio;

pub trait IoAdapter<S>: Send + Sync + 'static {
    type Io: Read + Write + Send + Unpin + 'static;
    fn adapt(&self, stream: S) -> Self::Io;
}

pub enum TlsMode { Plain, Tls }

pub enum MaybeTls<Plain, Tls> {
    Plain(Plain),
    Tls(Tls),
}

impl<P, T> Read for MaybeTls<P, T>
where
    P: Read + Unpin,
    T: Read + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<std::io::Result<()>> {
        unsafe {
            match self.get_unchecked_mut() {
                MaybeTls::Plain(p) => Pin::new_unchecked(p).poll_read(cx, buf),
                MaybeTls::Tls(t)   => Pin::new_unchecked(t).poll_read(cx, buf),
            }
        }
    }
}

impl<P, T> Write for MaybeTls<P, T>
where
    P: Write + Unpin,
    T: Write + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        unsafe {
            match self.get_unchecked_mut() {
                MaybeTls::Plain(p) => Pin::new_unchecked(p).poll_write(cx, buf),
                MaybeTls::Tls(t)   => Pin::new_unchecked(t).poll_write(cx, buf),
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        unsafe {
            match self.get_unchecked_mut() {
                MaybeTls::Plain(p) => Pin::new_unchecked(p).poll_flush(cx),
                MaybeTls::Tls(t)   => Pin::new_unchecked(t).poll_flush(cx),
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        unsafe {
            match self.get_unchecked_mut() {
                MaybeTls::Plain(p) => Pin::new_unchecked(p).poll_shutdown(cx),
                MaybeTls::Tls(t)   => Pin::new_unchecked(t).poll_shutdown(cx),
            }
        }
    }
}


pub trait TlsUpgrader<I>: Send + Sync + 'static {
    type Io: Send + Unpin + 'static;
    type Fut: Future<Output = io::Result<Self::Io>> + Send;
    fn upgrade(&self, host: &str, io: I, mode: TlsMode) -> Self::Fut;
}

#[derive(Clone)]
pub struct ArtiHttpConnector<R: Runtime, A, T> {
    client: TorClient<R>,
    io_adapter: A,
    tls: T,
}

impl<R: Runtime, A, T> ArtiHttpConnector<R, A, T> {
    pub fn new(client: TorClient<R>, io_adapter: A, tls: T) -> Self {
        Self { client, io_adapter, tls }
    }
}

pub struct ArtiHttpConnection<Io> {
    io: Io,
}

impl<Io: Read + Unpin> Read for ArtiHttpConnection<Io> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        unsafe { Pin::new_unchecked(&mut self.get_unchecked_mut().io) }.poll_read(cx, buf)
    }
}

impl<Io: Write + Unpin> Write for ArtiHttpConnection<Io> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        unsafe { Pin::new_unchecked(&mut self.get_unchecked_mut().io) }.poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        unsafe { Pin::new_unchecked(&mut self.get_unchecked_mut().io) }.poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        unsafe { Pin::new_unchecked(&mut self.get_unchecked_mut().io) }.poll_shutdown(cx)
    }
}


impl<Io: Read + Write + Send + Unpin + 'static> hyper_util::client::legacy::connect::Connection
    for ArtiHttpConnection<Io>
{
    fn connected(&self) -> hyper_util::client::legacy::connect::Connected {
        hyper_util::client::legacy::connect::Connected::new()
    }
}

impl<R, A, T> Service<Uri> for ArtiHttpConnector<R, A, T>
where
    R: Runtime + Clone + Send + Sync + 'static,
    A: IoAdapter<DataStream> + Clone,
    T: TlsUpgrader<<A as IoAdapter<DataStream>>::Io> + Clone,
{
    type Response = ArtiHttpConnection<<T as TlsUpgrader<<A as IoAdapter<DataStream>>::Io>>::Io>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output=Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut std::task::Context<'_>)
        -> std::task::Poll<Result<(), Self::Error>> { std::task::Poll::Ready(Ok(())) }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let client = self.client.clone();
        let io_adapter = self.io_adapter.clone();
        let tls = self.tls.clone();

        Box::pin(async move {
            let host = uri.host().ok_or_else(|| io_err("missing host"))?.to_string();
            let tls_mode = if uri.scheme_str().unwrap_or("http").eq_ignore_ascii_case("https") {
                TlsMode::Tls
            } else { TlsMode::Plain };
            let port = uri.port_u16().unwrap_or(if matches!(tls_mode, TlsMode::Tls) { 443 } else { 80 });

            let addr = (host.clone(), port).into_tor_addr()
                .map_err(|_| io_err("invalid address"))?;
            let arti_stream = client.connect(addr).await
                .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e.to_string()))?;

            let io = io_adapter.adapt(arti_stream);
            let io = tls.upgrade(&host, io, tls_mode).await?;
            Ok(ArtiHttpConnection { io })
        })
    }
}

fn io_err(msg: &str) -> io::Error { io::Error::new(io::ErrorKind::InvalidInput, msg) }

