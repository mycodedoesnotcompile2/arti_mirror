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
