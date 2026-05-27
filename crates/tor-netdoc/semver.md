BREAKING: `RouterDesc::family_ids()` now returns `RelayFamilyIds`
ADDED: `From<Ed25519Identity>` for `RelayFamilyId`
ADDED: `RouterDesc::family_cert`
BREAKING: `RouterDesc::or_address` now stored in a `Vec<SocketAddr>`
ADDED: `HsDesc::revision()`
BREAKING: `RouterDesc::identity_cert` renamed to `identity_ed25519`
BREAKING: `RouterDesc::rsa_identity` renamed to `fingerprint`
BREAKING: `RouterDesc::rsa_identity_key` renamed to `signing_key`
BREAKING: `RouterDesc::is_extrainfo_cache` renamed to `caches_extra_info`
BREAKING: `RouterDesc::ipv6addr` renamed to `or_address`
BREAKING: `RouterDesc::is_dircache` renamed to `tunnelled_dir_server`
BREAKING: `RouterDesc::rsa_identity()` now returns a copy
BREAKING: `RouterDesc::fingerprint()` now stored in a `Option<SpFingerprint>`
ADDED: `Fingerprint` et al implement `Ord` and `PartialOrd`
ADDED: `B16, B16U, B64, B16Fixed` et al implement `Ord` and `PartialOrd`
BREAKING: `netstatus::Preamble*` now contain new `SharedRandStatuses`, not individual fields
BREAKING: `nickname`, `ipv4addr`, `orport`, and `dirport` moved `RouterDesc::router`
BREAKING: `RouterDesc::published` now stored in a `Iso8601TimeSp`
BREAKING: `RouterDesc::ntor_onion_key` now stored in a `Curve25519Public`
ADDED: `Ed25519IdentityCert` type
ADDED: `Ed25519FamilyCert` type
ADDED: `Bandwidth` type
ADDED: `RouterDesc::bandwidth` field
ADDED: `NetworkStatusVersion`
BREAKING: `Footer` renamed to `ConsensusFooterFields`
BREAKING: `Footer.weights` renamed to `ConsensusFooterFields.bandwidth_weights`
ADDED: `ConsensusFooterFields` implements  construction, encoding, and parsing
ADDED: `netstatus::{plain,md,vote}::Footer` for the network status footer sections
ADDED: `NetworkStatusVersion`
ADDED: `DirectorySignaturesHashesAccu` fields are now pub.
BREAKING: `SignatureGroup` contains `DirectorySignaturesHashesAccu`, instead of hash fields
ADDED: `NoMoreArguments` parsing/encoding helper type (`NoFurtherArguments` now a deprecated alias)
ADDED: encoding implementation for `IgnoredPublicationTimeSp`
ADDED: encoding implementation for `rs::SoftwareVersion`
BREAKING: `NetdocParseableFields::finish` has an additional `ItemStream` argument
BREAKING: parsing/encoding impls for `NetParams` made generic
ADDED: `Unknown::into_retained` now available (always fails) even without `retain-unknown`
ADDED: `TryFrom<&NetParams<u32>> for RelayWeight`
BREAKING: `RouterStatus.weight` contains the new `RelayWeightsItem`
