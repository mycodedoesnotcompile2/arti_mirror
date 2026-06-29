BREAKING: Remove `Eq` on `RouterDesc` and `RouterDescSignatures`
BREAKING: Remove `Eq` on `EmbeddedCert` and `NtorOnionKeyCrossCert`
ADDED: `NetdocEncodable` for `RouterDesc`
ADDED: `NetdocEncodable` for `RouterDescSignatures`
ADDED: `ItemValueEncodable` for `RouterSignature`
ADDED: `types::policy::IpPattern`
ADDED: `types::policy::AddrPortPattern`: `addrs` and `ports` fields exposed
ADDED: `types::policy::AddrPortPattern`: impl `Hash`, provide `new`
ADDED: `types::policy::AddrPolicy::rules` accessor
ADDED: `types::policy::PortRange::from_range`, `to_range`
ADDED: `types::policy::PortRange` is `Copy`
ADDED: `types::policy::AddrPolicy::rules` returns a `DoubleEndedIterator`
ADDED: `rangemap_mutate_range`
