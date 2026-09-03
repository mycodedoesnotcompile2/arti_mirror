//! Types representing events that are emitted to enable onionperf.
//!
//! These are intended to reflect the C Tor meanings of the similar events.

// It would be nice to include various IDs in these enums,
// but doing so would create a circular dependency,
// as the crates that define those types depend on rot-basic-utils.
#[derive(Debug)]
#[non_exhaustive]
/// An event that is intended to be ingested by onionperf.
pub enum OnionperfEvent {
    /// A stream-related event.
    ///
    /// Note that this somewhat conflates SOCKS proxy streams and data streams,
    /// as C Tor does the same.
    ///
    /// These can be distinguished, as the data streams have a stream ID set in
    /// the emitted events, while the SOCKS streams do not.
    Stream(OnionperfStreamStatus),
    /// A circuit-related event.
    Circuit(OnionperfCircuitStatus),
    /// A guard-related event.
    Guard(OnionperfGuardStatus),
}

#[derive(Debug)]
#[non_exhaustive]
/// A stream status that is intended to be ingested by onionperf.
pub enum OnionperfStreamStatus {
    /// A stream was newly created.
    New,
    /// A stream was closed.
    Closed,
    /// A stream has failed and been closed due to an error.
    Failed,
}

#[derive(Debug)]
#[non_exhaustive]
/// A circuit status that is intended to be ingested by onionperf.
pub enum OnionperfCircuitStatus {
    /// A new circuit was built.
    Built,
    /// This tunnel is now usable.
    Launched,
    /// This circuit was successfully extended by another hop.
    Extended,
    /// This circuit was closed, either cleanly or due to an error.
    Closed,
    /// This tunnel was not successfully created.
    Failed,
}

#[derive(Debug)]
#[non_exhaustive]
/// A guard status that is intended to be ingested by onionperf.
pub enum OnionperfGuardStatus {
    /// A new guard has been added to the set of available guards.
    New,
    /// This guard has been used successfully.
    Up,
    /// We attempted to use this guard but were not successful.
    Down,
    /// This guard was removed from the set of available guards.
    Dropped,
}
