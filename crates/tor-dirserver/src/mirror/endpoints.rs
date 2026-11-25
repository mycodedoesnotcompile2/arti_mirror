//! HTTP endpoints for a directory mirror.

use std::sync::LazyLock;

use http::{Method, Request, Response};
use hyper::body::Incoming;
use itertools::chain;
use rusqlite::Transaction;
use tor_netdoc::doc::netstatus::{md, plain};

use crate::{
    database::{ConsensusMeta, DocumentId},
    err::DatabaseError,
    http::{Endpoint, EndpointFn},
    types::FlavoredConsensusUnverified,
};

/// Macro to generate an iterator of endpoints for consensus flavor endpoints.
///
/// We use a macro for this, because we would otherwise have to copy&paste
/// lots of data, as every consensus related endpoint is reachable via.
/// a `consensus`, `consensus-ns`, and `consensus-microdesc` path segment.
macro_rules! foreach_flavor {
    ($method:path, $prefix:literal, $suffix:literal, $cb:ident) => {{
        // We create two functions here so we can pass them as function items
        // to HttpServer.  This is necessary because we want to conveniently
        // return with errors such as DatabaseError inside the endpoint
        // implementations and convert them to Box<dyn std::error::Error>, which
        // is what the HTTP module expects.
        //
        // TODO DIRMIRROR: Right now, the http.rs module was designed in a way
        // to ignore but log all errors that occur in an HTTP endpoint.
        // Perhaps, this is not the best behavior, especially not if all
        // endpoints in here ought to return DatabaseError.  In the long run,
        // we probably want to no longer use Box<dyn std::error::Error> but
        // rather make the error types of the callbacks a generic parameter
        // to HttpServer, alongside a method that determines whether an error
        // should be ignored or be fatal.  However, this is something out of
        // scope for the endpoints and a matter of the HttpServer
        // implementation.  It also needs further consideration/coordination
        // with the dirauth implementation, as it also wants to make use of
        // that module.
        fn plain(
            tx: &Transaction<'_>,
            requ: &Request<Incoming>,
        ) -> Result<Response<Vec<DocumentId>>, Box<dyn std::error::Error>> {
            $cb::<plain::NetworkStatusUnverified>(tx, requ).map_err(|e| e.into())
        }
        fn md(
            tx: &Transaction<'_>,
            requ: &Request<Incoming>,
        ) -> Result<Response<Vec<DocumentId>>, Box<dyn std::error::Error>> {
            $cb::<md::NetworkStatusUnverified>(tx, requ).map_err(|e| e.into())
        }

        [
            (
                $method,
                concat!($prefix, "consensus", $suffix),
                plain as EndpointFn,
            ),
            ($method, concat!($prefix, "consensus-ns", $suffix), plain),
            (
                $method,
                concat!($prefix, "consensus-microdesc", $suffix),
                md,
            ),
        ]
        .into_iter()
    }};
}

/// Internal value used for [`default_endpoints()`].
static DEFAULT_ENDPOINTS: LazyLock<Box<[Endpoint]>> = LazyLock::new(|| {
    chain!(
        foreach_flavor!(
            Method::GET,
            "/tor/status-vote/current/",
            "",
            current_consensus
        ),
        // Add additional endpoints here.
    )
    .collect::<Vec<_>>()
    .into_boxed_slice()
});

/// Returns the default list of endpoints that can be passed to
/// [`crate::http::HttpServer::new()`].
pub(crate) fn default_endpoints() -> &'static [Endpoint] {
    DEFAULT_ENDPOINTS.as_ref()
}

/// Returns the most recent consensus.
///
/// # Implemented Endpoints
/// * `/tor/status-vote/current/consensus`
/// * `/tor/status-vote/current/consensus-<FLAVOR>`
// TODO DIRMIRROR: Modify http.rs to ensure an empty Vec here results in a 404.
fn current_consensus<Flavor: FlavoredConsensusUnverified>(
    tx: &Transaction<'_>,
    _requ: &Request<Incoming>,
) -> Result<Response<Vec<DocumentId>>, DatabaseError> {
    Ok(Response::new(
        ConsensusMeta::<Flavor>::query(tx)?
            .first()
            .into_iter()
            .map(|meta| meta.docid)
            .collect(),
    ))
}
