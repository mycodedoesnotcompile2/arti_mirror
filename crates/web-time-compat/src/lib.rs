#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
// @@ begin lint list maintained by maint/add_warning @@
#![allow(renamed_and_removed_lints)] // @@REMOVE_WHEN(ci_arti_stable)
#![allow(unknown_lints)] // @@REMOVE_WHEN(ci_arti_nightly)
#![allow(clippy::cognitive_complexity)] // See arti#2556
#![allow(clippy::collapsible_if)] // See arti#2342
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::needless_lifetimes)] // See arti#1765
#![allow(clippy::needless_raw_string_hashes)] // complained-about code is fine, often best
#![allow(clippy::result_large_err)] // temporary workaround for arti#587
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
#![allow(clippy::uninlined_format_args)]
#![allow(mismatched_lifetime_syntaxes)] // temporary workaround for arti#2060
#![warn(missing_docs)]
#![warn(noop_method_call)]
#![warn(unreachable_pub)]
#![warn(clippy::all)]
#![warn(clippy::manual_ok_or)]
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![warn(clippy::rc_buffer)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::cargo_common_metadata)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::checked_conversions)]
#![deny(clippy::debug_assert_with_mut_call)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::exhaustive_structs)]
#![deny(clippy::expl_impl_clone_on_copy)]
#![deny(clippy::fallible_impl_from)]
#![deny(clippy::implicit_clone)]
#![deny(clippy::large_stack_arrays)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(clippy::mod_module_files)]
#![deny(clippy::print_stderr)]
#![deny(clippy::print_stdout)]
#![deny(clippy::ref_option_ref)]
#![deny(clippy::string_slice)] // See arti#2571
#![deny(clippy::unchecked_time_subtraction)]
#![deny(clippy::unnecessary_wraps)]
#![deny(clippy::unused_async)]
#![deny(clippy::unwrap_used)]
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

// We always use `SystemTime` for our data representation outside of this crate.
//
// The only time that we touch `SystemTime` is when we are constructing it with
// `SystemTimeExt::get`.
pub use std::time::SystemTime;

// "Duration" is the same type in web_time as it is in stdlib.
pub use std::time::Duration;

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
mod stdlib;

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub use stdlib::*;

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod wasm;

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub use wasm::*;

/// Module to hide "Sealed"
mod seal {
    /// Trait used to prevent implementing InstantExt or SystemTimeExt outside of this crate.
    #[allow(unreachable_pub)]
    pub trait Sealed {}
}

/// Extension trait for [`std::time::SystemTime`]
///
/// This trait adds a `get` method which works like `now`,
/// but also supports `wasm32-unknown-unknown` environments.
pub trait SystemTimeExt: seal::Sealed {
    /// Return the current time.
    fn get() -> std::time::SystemTime;
}

/// Extension trait for [`Instant`].
///
/// This trait adds a `get` method which works like `now`,
/// so we can make sure we aren't calling [`std::time::Instant::now`]
/// on`wasm32-unknown-unknown` environments.
///
/// ## Design note
///
/// Since we already replace the `std::time::Instant` type with
/// `web_time::Instant` in this crate, why do we also provide
/// an extension trait to rename its "now" method?
///
/// We do so for two reasons:
///
/// 1. Consistency.  With this approach, you don't have to remember
///    which type uses `get` and which uses `now`.
/// 2. Enforcement.  This approach makes it possible to use Clippy
///    to disallow `std::time::Instant::now()` unconditionally,
///    to make sure that you don't forget to use
///    the appropriate `web_time_compat::Instant` type instead.
pub trait InstantExt: seal::Sealed {
    /// Return the current time.
    fn get() -> crate::Instant;
}

impl seal::Sealed for std::time::SystemTime {}
impl seal::Sealed for crate::Instant {}
