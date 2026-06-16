ADDED: `NetdocEncodableFields` for `AddrPolicy`
ADDED: `encode::ItemArgument` for `SpFingerprint`
ADDED: `ItemValueEncodable` for `ExtraInfoDigests`
ADDED: `ItemValueEncodable` for `RouterDescIntroItem`
ADDED: `ItemValueEncodable` for `OverloadGeneral`
ADDED: `ItemValueEncodable` for `RelayPlatform`
BREAKING: Replaced `ItemArgumentParseable` with `ItemValueParseable` for `RelayPlatform`
ADDED: `NtorOnionKeyCrossCert` type
ADDED: `RouterDesc::ntor_onion_key_crosscert`
ADDED: `HiddenServiceDirToken`
ADDED: `RouterDesc::hidden_service_dir`
ADDED: `CachesExtraInfoToken`
ADDED: `TunnelledDirServerToken`
BREAKING: `RouterDesc::caches_extra_info` stored as `CachesExtraInfoToken`
BREAKING: `RouterDesc::tunnelled_dir_server` stored as `TunnelledDirServerToken`
ADDED: `Ed25519NtorCrossCert` type
ADDED: `ItemPresent` type
ADDED: `RouterDesc::extra_info_digest` field
ADDED: `RouterDesc::contact` field
ADDED: `RouterDesc::overload_general` field
ADDED: `RouterDesc::hibernating` field
ADDED: `Display` for `RelayPlatform`
BREAKING: `RelayPlatform::Tor` now stores the platform as `Option<String>`
BREAKING: `NetdocUnverified` trait is now `NetdocParseableUnverified`
ADDED: `ParseInput` improved: accessors, `retain_unknown_values`, `Clone`, `Debug`
ADDED: `RouterStatus` and `RouterStatusIntroItem` implement netdoc encoding traits
ADDED: `RouterStatus` and `netstatus::Signature` implement `EncodeOrd`
ADDED: `F64Finite` type
ADDED: `doc::netstatus::{plain, md, vote}::NetworkStatus`
BREAKING: `AuthCertUnverified::verify` doesn't take times; instead returns `TimerangeBound`
DEPRECATED: `parse2::check_validity_time` and `check_validity_time_tolerance`
ADDED: `impl From<std::convert::Infallible> for Error`
ADDED: `RouterStatus` fields `r.dir_port`, `p`, `id`, `stats`
ADDED: `plain::NetworkStatus` and `md::NetworkStatus` implement `NetdocEncodable`
ADDED: `plain::NetworkStatus` and `md::NetworkStatus` have `verify` methods
ADDED: `EmbeddedCert` implements `NetdocEncodable` and `NetdocParseable`
ADDED: `Microdesc`, `RelayFamily`, `RelayFamilyIds` are encodable
ADDED: `NetdocEncodable` derive, `#[deftly(netdoc(default(skip)))]` option
ADDED: `MicrodescIntroItem`
