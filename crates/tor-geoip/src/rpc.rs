//! RPC APIs for geoip functionality.

use std::net::IpAddr;
use std::{collections::HashMap, sync::Arc};

use tor_rpcbase as rpc;
use tor_rpcbase::derive_deftly::Deftly;

use crate::{CountryCode, GeoipDb};

/// Look up the country codes for a list of IP addresses.
///
/// The caller passes a list of addresses in the `address` field;
/// the method returns a map from addresses to country code.
///
/// If a country code is not known for some address,
/// then it is omitted from the map.
#[derive(Debug, serde::Deserialize, serde::Serialize, Deftly)]
#[derive_deftly(rpc::DynMethod)]
#[deftly(rpc(method_name = "arti:geoip_lookup_countries"))]
#[non_exhaustive]
struct GeoipLookupCountries {
    /// The addresses to look countries for.
    #[serde(default)]
    addresses: Vec<IpAddr>,
}

impl rpc::RpcMethod for GeoipLookupCountries {
    type Output = GeoipLookupResult;

    type Update = rpc::NoUpdates;
}

/// Result returned by the `arti:geoip_lookup_countries` method.
#[derive(Debug, serde::Serialize)]
#[non_exhaustive]
struct GeoipLookupResult {
    /// A map from addresses to country codes.
    ///
    /// Countries without known addresses are omitted.
    countries: HashMap<IpAddr, CountryCode>,
}

impl GeoipDb {
    /// Actually perform the geoip lookup for a given [`GeoipLookupCountries`] request.
    fn rpc_lookup_countries(&self, request: GeoipLookupCountries) -> GeoipLookupResult {
        let countries = request
            .addresses
            .into_iter()
            .filter_map(|a| Some((a, *self.lookup_country_code(a)?)))
            .collect();
        GeoipLookupResult { countries }
    }
}

/// Implementation for [`GeoipLookupCountries`] on [`GeoipDb`].
async fn geoip_lookup_on_geoipdb(
    db: Arc<GeoipDb>,
    method: Box<GeoipLookupCountries>,
    _ctx: Arc<dyn rpc::Context>,
) -> Result<GeoipLookupResult, rpc::RpcError> {
    Ok(db.rpc_lookup_countries(*method))
}

rpc::static_rpc_invoke_fn! {
    geoip_lookup_on_geoipdb;
}
