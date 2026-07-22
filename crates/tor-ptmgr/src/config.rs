//! Configuration logic for tor-ptmgr.
use std::net::SocketAddr;

use derive_deftly::Deftly;
use tor_config::ConfigBuildError;
use tor_config::derive::prelude::*;
use tor_config_path::CfgPath;
use tor_linkspec::PtTransportName;

#[cfg(feature = "tor-channel-factory")]
use {crate::PtClientMethod, tor_socksproto::SocksVersion};

/// A single pluggable transport.
///
/// Pluggable transports are programs that transform and obfuscate traffic on
/// the network between a Tor client and a Tor bridge, so that an adversary
/// cannot recognize it as Tor traffic.
///
/// A pluggable transport can be either _managed_ (run as an external process
/// that we launch and monitor), or _unmanaged_ (running on a local port, not
/// controlled by Arti).
#[derive(Clone, Debug, Deftly, Eq, PartialEq)]
#[derive_deftly(TorConfig)]
#[deftly(tor_config(no_default_trait, pre_build = "Self::validate"))]
pub struct TransportConfig {
    /// Names of the transport protocols that we are willing to use from this transport.
    ///
    /// (These protocols are arbitrary identifiers that describe which protocols
    /// we want. They must match names that the binary knows how to provide.)
    //
    // NOTE(eta): This doesn't use the list builder stuff, because you're not likely to
    //            set this field more than once.
    #[deftly(tor_config(no_magic, no_default))]
    pub(crate) protocols: Vec<PtTransportName>,

    /// The path to the binary to run, if any.
    ///
    /// This needs to be the path to some executable file on disk.
    ///
    /// Present only for managed transports.
    #[deftly(tor_config(default, setter(strip_option)))]
    pub(crate) path: Option<CfgPath>,

    /// One or more command-line arguments to pass to the binary.
    ///
    /// Meaningful only for managed transports.
    // TODO: Should this be OsString? That's a pain to parse...
    //
    // NOTE(eta): This doesn't use the list builder stuff, because you're not likely to
    //            set this field more than once.
    #[deftly(tor_config(no_magic, default))]
    pub(crate) arguments: Vec<String>,

    /// The location at which to contact this transport.
    ///
    /// Present only for unmanaged transports.
    #[deftly(tor_config(default, setter(strip_option)))]
    pub(crate) proxy_addr: Option<SocketAddr>,

    /// If true, launch this transport on startup.  Otherwise, we launch
    /// it on demand.
    ///
    /// Meaningful only for managed transports.
    #[deftly(tor_config(default))]
    pub(crate) run_on_startup: bool,
}

impl TransportConfigBuilder {
    /// Inspect the list of protocols (ie, transport names)
    ///
    /// If none have yet been specified, returns an empty list.
    pub fn get_protocols(&self) -> &[PtTransportName] {
        self.protocols.as_deref().unwrap_or_default()
    }

    /// Make sure that this builder is internally consistent.
    fn validate(&self) -> Result<(), ConfigBuildError> {
        // `path` can only be set if the `managed-pts` feature is enabled
        #[cfg(not(feature = "managed-pts"))]
        if self.path.is_some() {
            return Err(ConfigBuildError::NoCompileTimeSupport {
                field: "path".into(),
                problem:
                    "Indicates a managed transport, but support is not enabled by cargo features"
                        .into(),
            });
        }

        match (&self.path, &self.proxy_addr) {
            (Some(_), Some(_)) => Err(ConfigBuildError::Inconsistent {
                fields: vec!["path".into(), "proxy_addr".into()],
                problem: "Cannot provide both path and proxy_addr".into(),
            }),
            (None, None) => Err(ConfigBuildError::MissingOneOf {
                min_required: 1,
                fields: vec!["path".into(), "proxy_addr".into()],
            }),
            (None, Some(_)) => {
                if self.arguments.as_ref().is_some_and(|v| !v.is_empty()) {
                    Err(ConfigBuildError::Inconsistent {
                        fields: vec!["proxy_addr".into(), "arguments".into()],
                        problem: "Cannot provide arguments for an unmanaged transport".into(),
                    })
                } else if self.run_on_startup.is_some() {
                    Err(ConfigBuildError::Inconsistent {
                        fields: vec!["proxy_addr".into(), "run_on_startup".into()],
                        problem: "run_on_startup is meaningless for an unmanaged transport".into(),
                    })
                } else {
                    Ok(())
                }
            }
            (Some(_), None) => Ok(()),
        }
    }
}

/// The pluggable transport structure used internally. This is more type-safe than working with
/// `TransportConfig` directly, since we can't change `TransportConfig` as it's part of the public
/// API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum TransportOptions {
    /// Options for a managed PT transport.
    #[cfg(feature = "managed-pts")]
    Managed(ManagedTransportOptions),
    /// Options for an unmanaged PT transport.
    Unmanaged(UnmanagedTransportOptions),
}

impl TryFrom<TransportConfig> for TransportOptions {
    type Error = tor_error::Bug;
    fn try_from(config: TransportConfig) -> Result<Self, Self::Error> {
        // We rely on the validation performed in `TransportConfigBuilder::validate` to ensure that
        // mutually exclusive options were not set. We could do validation again here, but it would
        // be error-prone to duplicate the validation logic. We also couldn't check things like if
        // `run_on_startup` was `Some`/`None`, since that's only available to the builder.

        if let Some(path) = config.path {
            cfg_if::cfg_if! {
                if #[cfg(feature = "managed-pts")] {
                    Ok(TransportOptions::Managed(ManagedTransportOptions {
                        protocols: config.protocols,
                        path,
                        arguments: config.arguments,
                        run_on_startup: config.run_on_startup,
                    }))
                } else {
                    let _ = path;
                    Err(tor_error::internal!(
                        "Path is set but 'managed-pts' feature is not enabled. How did this pass builder validation?"
                    ))
                }
            }
        } else if let Some(proxy_addr) = config.proxy_addr {
            Ok(TransportOptions::Unmanaged(UnmanagedTransportOptions {
                protocols: config.protocols,
                proxy_addr,
            }))
        } else {
            Err(tor_error::internal!(
                "Neither path nor proxy are set. How did this pass builder validation?"
            ))
        }
    }
}

/// A pluggable transport that is run as an external process that we launch and monitor.
#[cfg(feature = "managed-pts")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedTransportOptions {
    /// See [TransportConfig::protocols].
    pub(crate) protocols: Vec<PtTransportName>,

    /// See [TransportConfig::path].
    pub(crate) path: CfgPath,

    /// See [TransportConfig::arguments].
    pub(crate) arguments: Vec<String>,

    /// See [TransportConfig::run_on_startup].
    pub(crate) run_on_startup: bool,
}

/// A pluggable transport running on a local port, not controlled by Arti.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UnmanagedTransportOptions {
    /// See [TransportConfig::protocols].
    pub(crate) protocols: Vec<PtTransportName>,

    /// See [TransportConfig::proxy_addr].
    pub(crate) proxy_addr: SocketAddr,
}

impl UnmanagedTransportOptions {
    /// A client method that can be used to contact this transport.
    #[cfg(feature = "tor-channel-factory")]
    pub(crate) fn cmethod(&self) -> PtClientMethod {
        PtClientMethod {
            // TODO: Someday we might want to support other protocols;
            // but for now, let's see if we can get away with just socks5.
            kind: SocksVersion::V5,
            endpoint: self.proxy_addr,
        }
    }

    /// Return true if this transport is configured on localhost.
    pub(crate) fn is_localhost(&self) -> bool {
        self.proxy_addr.ip().is_loopback()
    }
}

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
    #![allow(unused)]
    use super::*;
    use crate::config::{TransportConfig, TransportConfigBuilder};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tor_config::ConfigBuildError;
    use tor_config_path::CfgPath;
    use tor_rtcompat::PreferredRuntime;

    /// Test for TransportConfigBuilder which is generated by macro.
    #[test]
    fn builder_test() {
        #[cfg(feature = "managed-pts")]
        {
            let config: TransportConfig = TransportConfigBuilder::default()
                .protocols(vec!["obfs4".parse().unwrap(), "snowflake".parse().unwrap()])
                .path(CfgPath::new("/usr/bin/obfs4proxy".into()))
                .arguments(vec!["--log-min-severity=info".into()])
                .run_on_startup(true)
                .build()
                .unwrap();
            assert_eq!(
                config,
                TransportConfig {
                    protocols: vec!["obfs4".parse().unwrap(), "snowflake".parse().unwrap()],
                    path: Some(CfgPath::new("/usr/bin/obfs4proxy".into())),
                    arguments: vec!["--log-min-severity=info".into()],
                    proxy_addr: None,
                    run_on_startup: true,
                }
            );
        };
        let config: TransportConfig = TransportConfigBuilder::default()
            .protocols(vec!["obfs4".parse().unwrap(), "snowflake".parse().unwrap()])
            .proxy_addr("127.0.0.1:9050".parse().unwrap())
            .build()
            .unwrap();

        assert_eq!(
            config,
            TransportConfig {
                protocols: vec!["obfs4".parse().unwrap(), "snowflake".parse().unwrap()],
                path: None,
                arguments: vec![],
                proxy_addr: Some("127.0.0.1:9050".parse().unwrap()),
                run_on_startup: false,
            }
        );
        #[cfg(not(feature = "managed-pts"))]
        {
            let config: Result<TransportConfig, ConfigBuildError> =
                TransportConfigBuilder::default()
                    .protocols(vec!["obfs4".parse().unwrap(), "snowflake".parse().unwrap()])
                    .path(CfgPath::new("/usr/bin/obfs4proxy".into()))
                    .arguments(vec!["--log-min-severity=info".into()])
                    .run_on_startup(true)
                    .build();
            match config {
                Err(ConfigBuildError::NoCompileTimeSupport { field, problem }) => {
                    assert_eq!(field, "path".to_string());
                    assert_eq!(problem, "Indicates a managed transport, but support is not enabled by cargo features".to_string());
                }
                other => panic!("Expected NoCompileTimeSupport error, got {:?}", other),
            };
        }

        #[cfg(feature = "managed-pts")]
        {
            let config: Result<TransportConfig, ConfigBuildError> =
                TransportConfigBuilder::default()
                    .protocols(vec!["obfs4".parse().unwrap(), "snowflake".parse().unwrap()])
                    .path(CfgPath::new("/usr/bin/obfs4proxy".into()))
                    .arguments(vec!["--log-min-severity=info".into()])
                    .proxy_addr("127.0.0.1:9050".parse().unwrap())
                    .run_on_startup(true)
                    .build();
            match config {
                Err(ConfigBuildError::Inconsistent { fields, problem }) => {
                    assert_eq!(fields, vec!["path".to_string(), "proxy_addr".to_string()]);
                    assert_eq!(
                        problem,
                        "Cannot provide both path and proxy_addr".to_string()
                    );
                }
                other => panic!("Expected Inconsistent error, got {:?}", other),
            };
        }
    }
}
