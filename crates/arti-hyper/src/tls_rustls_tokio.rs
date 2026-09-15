// Implementation to upgrade TLS stream specifically for Tokio + Rustls.

use std::{pin::Pin, sync::Arc};
use std::future::Future;
use std::io;

use hyper::rt::{Read as Read, Write as Write};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::{
    rustls::{ClientConfig, RootCertStore},
    TlsConnector,
};
use webpki_roots::TLS_SERVER_ROOTS;

use crate::{TlsUpgrader, TlsMode, MaybeTls};
use crate::io_adapter_tokio::TokioCompat;


#[derive(Clone, Debug)]
pub struct TokioRustlsUpgrader;

impl<I> TlsUpgrader<I> for TokioRustlsUpgrader
where
    I: Read + Send + AsyncWrite + AsyncRead  + Unpin + 'static,
{
    type Io = MaybeTls<I, TokioCompat<tokio_rustls::client::TlsStream<I>>>;
    type Fut = Pin<Box<dyn Future<Output = io::Result<Self::Io>> + Send>>;

    fn upgrade(&self, host: &str, io: I, mode: TlsMode) -> Self::Fut {
        let host_owned = host.to_string();

        Box::pin(async move {
            if matches!(mode, TlsMode::Plain) {
                return Ok(MaybeTls::Plain(io));
            }

            let mut root_cert_store = RootCertStore::empty();
            root_cert_store.extend(TLS_SERVER_ROOTS.iter().cloned());

            let config = ClientConfig::builder()
                .with_root_certificates(root_cert_store)
                .with_no_client_auth();

            let connector = TlsConnector::from(Arc::new(config));

            let server_name = host_owned
                .try_into()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Bad DNS name"))?;

            let tls = connector.connect(server_name, io).await?;
            Ok(MaybeTls::Tls(TokioCompat(tls)))
        })
    }
}


