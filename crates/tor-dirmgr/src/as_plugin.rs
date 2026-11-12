//! TEMPORARY, EXPERIMENTAL implementation of a [`Store`]-backed [`DirBackendPlugin`].
//!
//! This is throw-away code. It exists so that arti relays can pretend to be rudimentary directory
//! caches before tor-dirserver is finished.
//!
//! [`Store`]: crate::storage::Store
//
// NOTE: There are several points where we say "LIMITATION" below to indicate a place
// where this implementation falls short of the specified standard.  We are NOT planning
// to fix these, since this is throw-away code.

use std::sync::{Arc, Mutex};
use tor_llcrypto::pk::rsa::RsaIdentity;
use tor_netdoc::{
    doc::{
        authcert::AuthCertKeyIds,
        microdesc::{self, MdDigest},
        netstatus::ConsensusFlavor,
    },
    types::FixedB64,
};

use crate::storage::DynStore;
use tor_dircommon::dir_plugin_backend::{DirBackendPlugin, DirBackendPluginError, http};
use tor_error::into_internal;
use web_time_compat::SystemTime;

// LIMITATION: There is no compression support.
//
// LIMITATION: We copy every object that we serve; memory usage would be terrible in production.
// LIMITATION: We grab the DB lock every time we have a request.
// LIMITATION: We make more DB queries than strictly necessary.
//
// LIMITATION: Since the DirMgr downloads on a client's schedule, we will fetch consensuses
// slightly later than a relay properly should.
//
// LIMITATION: We may cause lock contention.

/// An implementation of [`DirBackendPlugin`] based on a [`DirMgr`]'s sqlite database.
///
/// [`DirMgr`]: crate::DirMgr
#[derive(Clone)]
pub struct DirPlugin {
    /// The underlying storage.
    ///
    /// Typically this uses an underlying sqlite database.
    pub(crate) store: Arc<Mutex<DynStore>>,
}

impl DirBackendPlugin for DirPlugin {
    fn get(
        &self,
        request: &http::Request<()>,
    ) -> Result<http::Response<Box<[u8]>>, DirBackendPluginError> {
        match self.handle_request(request) {
            Ok(v) => Ok(v),
            Err(e) => e.into_response(),
        }
    }
}

impl DirPlugin {
    /// As [`DirBackendPlugin::get`], but return a [`ReqError`] on failure.
    fn handle_request(
        &self,
        request: &http::Request<()>,
    ) -> Result<http::Response<Box<[u8]>>, ReqError> {
        if request.method() != http::Method::GET {
            return Err(ReqError::Unhandled);
        }
        let what = UriInterpretation::interpret(request.uri().path())?;

        match what {
            UriInterpretation::MdsByDigest(items) => self.get_mds(&items[..]),
            UriInterpretation::LatestMdConsensus => self.get_md_consensus(request),
            UriInterpretation::AuthCertsByFpSk(items) => self.get_certs(&items[..]),
        }
    }

    /// Try to handle a request for microdescriptors
    fn get_mds(&self, items: &[MdDigest]) -> Result<http::Response<Box<[u8]>>, ReqError> {
        let store = self.store.lock().expect("poisoned lock");

        let mds = store.microdescs(items)?;
        if mds.is_empty() {
            Err(ReqError::NotFound)
        } else {
            let s: String = mds.values().map(|v| v.as_str()).collect();
            let mut r = http::Response::new(s.into_bytes().into());
            *r.status_mut() = http::StatusCode::OK;
            Ok(r)
        }
    }

    /// Try to handle a request for a microdescriptor consensus.
    fn get_md_consensus(
        &self,
        request: &http::Request<()>,
    ) -> Result<http::Response<Box<[u8]>>, ReqError> {
        // LIMITATION: We ignore which authority FPs the client believes in.
        // LIMITATION: We ignore any diff requests.

        let if_modified_since: Option<SystemTime> = request
            .headers()
            .get("If-Modified-Since")
            .map(|hv| parse_date(hv.as_bytes()))
            .transpose()?;
        let store = self.store.lock().expect("poisoned lock");

        if let Some(ims) = if_modified_since {
            let meta = store.latest_consensus_meta(ConsensusFlavor::Microdesc)?;
            let Some(meta) = meta else {
                return Err(ReqError::NotFound);
            };
            if meta.lifetime().valid_after() < ims {
                return Err(ReqError::NotModified);
            }
        }

        let pending_ok = Some(false);
        let latest = store.latest_consensus(ConsensusFlavor::Microdesc, pending_ok)?;
        let Some(latest) = latest else {
            return Err(ReqError::NotFound);
        };

        // LIMITATION: We just copy the whole whole multi-megabyte consensus.
        let body = latest.as_ref().into();
        let mut r = http::Response::new(body);
        *r.status_mut() = http::StatusCode::OK;
        Ok(r)
    }

    /// Try to handle a request for certificates.
    fn get_certs(&self, items: &[AuthCertKeyIds]) -> Result<http::Response<Box<[u8]>>, ReqError> {
        let store = self.store.lock().expect("poisoned lock");

        let certs = store.authcerts(items)?;
        if certs.is_empty() {
            Err(ReqError::NotFound)
        } else {
            let s: String = certs.values().map(|v| v.as_str()).collect();
            let mut r = http::Response::new(s.into_bytes().into());
            *r.status_mut() = http::StatusCode::OK;
            Ok(r)
        }
    }
}

/// An accepted interpretation of a directory URI.
enum UriInterpretation {
    /// A request for one or more microdescriptors by their SHA256 digest.
    MdsByDigest(Vec<MdDigest>),
    /// A request for the latest MD consensus.
    LatestMdConsensus,
    /// A request for one or more authcerts by fingerprint digest and signing-key digest.
    AuthCertsByFpSk(Vec<AuthCertKeyIds>),
}

impl UriInterpretation {
    /// Based on a relative path, figure out what the client is asking for.
    fn interpret(path: &str) -> Result<Self, ReqError> {
        // Remove optional "tor" part.
        // LIMITATION: Maybe this is no longer optional? I didn't check. It will be fine.
        let path = path.strip_prefix("/tor").unwrap_or(path);

        // LIMITATION: We ignore the ".z" suffix since we're not doing compression.
        let (path, _dot_z) = match path.strip_suffix(".z") {
            Some(p) => (p, true),
            None => (path, false),
        };

        // A microdesc consensus, possibly followed by a list of authority fingerprints. See
        // https://spec.torproject.org/dir-spec/general-use-http-urls.html for details.
        let md_consensus = path
            .strip_prefix("/status-vote/current/consensus-microdesc")
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'));

        if md_consensus {
            // LIMITATION: URIs matching "/diff/" also match, giving a complete consensus; C tor
            //    responds with a 404 if no such diff exists.
            // LIMITATION: We don't serve "ns" consensuses.
            // LIMITATION: We ignore the list of fingerprints that follow this part of the path.

            Ok(Self::LatestMdConsensus)
        } else if let Some(remainder) = path.strip_prefix("/micro/d/") {
            // LIMITATION: C tor skips any digests it fails to parse; we return a 400 status code on
            //    the entire request.
            let mut digests: Vec<_> = remainder
                .split('-')
                .map(decode_md_digest)
                .collect::<Result<Vec<_>, _>>()
                .map_err(ReqError::Invalid)?;
            digests.sort();
            Ok(UriInterpretation::MdsByDigest(digests))
        } else if let Some(remainder) = path.strip_prefix("/keys/fp-sk/") {
            // LIMITATION: We do not process any other "keys" URIs. When C tor does not have an
            //    existing certificate for an authority, it requests the "/keys/fp/<F>" URI (in
            //    `authority_certs_fetch_missing()`). When that fails here, it retries later, maybe
            //    from a different directory.
            let mut pairs: Vec<_> = remainder
                .split('+')
                .map(decode_fp_pair)
                .collect::<Result<Vec<_>, _>>()
                .map_err(ReqError::Invalid)?;
            pairs.sort();
            Ok(UriInterpretation::AuthCertsByFpSk(pairs))
        } else {
            // This is some type of URI we don't handle.
            // LIMITATION: This also includes "/tor/robots.txt", for which C tor replies with a 200.
            Err(ReqError::Unhandled)
        }
    }
}

/// Try to parse a base64 MD digest as it appears in URIs.
fn decode_md_digest(s: &str) -> Result<MdDigest, &'static str> {
    let d: FixedB64<{ microdesc::DOC_DIGEST_LEN }> = s.parse().map_err(|_| "Invalid MD base64")?;
    Ok(d.0)
}

/// Try to parse an authority fingerprint pair as it appears in URIs.
fn decode_fp_pair(s: &str) -> Result<AuthCertKeyIds, &'static str> {
    let Some((fp, sk)) = s.split_once('-') else {
        return Err("misformed fingerprint pair");
    };
    let fp = RsaIdentity::from_hex(fp).ok_or("Invalid fp in fingerprint pair")?;
    let sk = RsaIdentity::from_hex(sk).ok_or("Invalid sk in fingerprint pair")?;
    Ok(AuthCertKeyIds {
        id_fingerprint: fp,
        sk_fingerprint: sk,
    })
}

/// Try to parse an HTTP date.
fn parse_date(b: &[u8]) -> Result<SystemTime, ReqError> {
    let s = str::from_utf8(b).map_err(|_| ReqError::Invalid("invalid date"))?;
    httpdate::parse_http_date(s).map_err(|_| ReqError::Invalid("invalid date"))
}

/// An error that has occurred while trying to answer a request.
#[derive(Clone, Debug, thiserror::Error)]
#[allow(clippy::large_enum_variant)] // LIMITATION
enum ReqError {
    /// We found an error while parsing the request.
    #[error("Request was not valid: {0}")]
    Invalid(&'static str),

    /// The user specified an If-Modified-Since header, and the
    /// document was older than that.
    #[error("Not modified since If-Modified-Since")]
    NotModified,

    /// We tried looking for the requested document but it wasn't there.
    #[error("No document present")]
    NotFound,

    /// Some kind of error occurred while looking up an object in the `Store`.
    #[error("Database failure")]
    DbFailed(#[from] crate::Error),

    /// The URI or method was something we don't  deal with.
    #[error("We don't handle this kind of request")]
    Unhandled,
}

impl ReqError {
    /// Convert this error into _either_ a response (if we know what to tell the client)
    /// or a [`DirBackendPluginError`] (if we don't).
    fn into_response(self) -> Result<http::Response<Box<[u8]>>, DirBackendPluginError> {
        match self {
            ReqError::Invalid(msg) => {
                let mut r = http::Response::new(msg.as_bytes().into());
                *r.status_mut() = http::StatusCode::BAD_REQUEST;
                Ok(r)
            }
            ReqError::NotModified => {
                let mut r = http::Response::new("Not modified".as_bytes().into());
                *r.status_mut() = http::StatusCode::NOT_MODIFIED;
                Ok(r)
            }
            ReqError::NotFound => {
                let mut r = http::Response::new("Not found".as_bytes().into());
                *r.status_mut() = http::StatusCode::NOT_FOUND;
                Ok(r)
            }
            ReqError::Unhandled => Err(DirBackendPluginError::UriNotHandledByPlugin),
            ReqError::DbFailed(e) => Err(DirBackendPluginError::Bug(into_internal!(
                "Database failed"
            )(e))),
        }
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
    use crate::docmeta::ConsensusMeta;
    use crate::storage::Store as _;
    use crate::storage::sqlite::test::new_empty;
    use std::time::Duration;
    use tor_netdoc::doc::netstatus::Lifetime;

    /// GET `uri` on a plugin with a store containing `consensus` as the most recent md consensus.
    fn get_with_md_consensus(
        consensus: &str,
        uri: &str,
    ) -> Result<http::Response<Box<[u8]>>, DirBackendPluginError> {
        let (_tmp_dir, mut store) = new_empty().unwrap();
        let valid_after = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let hour = Duration::from_secs(60 * 60);
        let lifetime = Lifetime::new(valid_after, valid_after + hour, valid_after + 3 * hour);
        let meta = ConsensusMeta::new(lifetime.unwrap(), [0xAB; 32], [0xBC; 32]);
        store
            .store_consensus(&meta, ConsensusFlavor::Microdesc, false, consensus)
            .unwrap();

        let plugin = DirPlugin {
            store: Arc::new(Mutex::new(Box::new(store))),
        };
        let request = http::Request::builder().uri(uri).body(()).unwrap();
        plugin.get(&request)
    }

    #[test]
    fn md_consensus_urls() {
        let consensus = "network-status-version 3 microdesc\nvote-status consensus\n";

        // The first one was constructed by C tor's `directory_get_consensus_url()` (taken from the
        // log of a C tor client running on a test network). It consists of the first three bytes of
        // each authority's v3 identity, followed by ".z". The next two requests come from Arti's
        // own `ConsensusRequest`.
        for uri in [
            "/tor/status-vote/current/consensus-microdesc/026B34+575CF9+CF80E4+E2FA26.z",
            "/tor/status-vote/current/consensus-microdesc",
            "/tor/status-vote/current/consensus-microdesc/03479e93ebf3ff2c58c1c9dbf2de9de9c2801b3e",
        ] {
            let response = get_with_md_consensus(consensus, uri).unwrap();
            assert_eq!(response.status(), http::StatusCode::OK, "{uri}");
            assert_eq!(&response.body()[..], consensus.as_bytes(), "{uri}");
        }

        // As we do not have an "ns" consensus, we must not substitute the md consensus.
        let uri = "/tor/status-vote/current/consensus/026B34+575CF9+CF80E4+E2FA26.z";
        assert!(matches!(
            get_with_md_consensus(consensus, uri),
            Err(DirBackendPluginError::UriNotHandledByPlugin)
        ));

        // Nor is a flavor that merely begins with "microdesc", or the old "md".
        for uri in [
            "/tor/status-vote/current/consensus-microdescx",
            "/tor/status-vote/current/consensus-microdesc-x/026B34.z",
            "/tor/status-vote/current/consensus-md",
        ] {
            assert!(
                matches!(UriInterpretation::interpret(uri), Err(ReqError::Unhandled)),
                "{uri}"
            );
        }
    }

    #[test]
    fn c_tor_md_digests() {
        // Handcrafted and formatted the way C tor's `digest256_to_base64()` writes them: 43
        // character digests without padding. Digests may contain slashes, since "/" is part of the
        // standard alphabet.
        let uri = "/tor/micro/d/+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/s-\
                   AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8.z";
        let Ok(UriInterpretation::MdsByDigest(digests)) = UriInterpretation::interpret(uri) else {
            panic!("C tor's microdescriptor request not understood");
        };
        let low: MdDigest = std::array::from_fn(|i| i as u8);
        assert_eq!(digests, vec![low, [0xFB; 32]]);
    }
}
