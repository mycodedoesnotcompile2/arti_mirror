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
