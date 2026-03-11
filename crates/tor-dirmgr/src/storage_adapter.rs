//! Storage adapter helpers for `tor-dirmgr`.
//!
//! This module provides a backend-neutral storage API.
//! Applications can provide any adapter that implements [`StorageAdapter`].
//!
//! This API is mainly useful on `wasm32-unknown-unknown`, where `tor-dirmgr`
//! cannot rely on filesystem storage. On non-wasm targets, the current
//! `tor-dirmgr` implementation keeps using filesystem-backed storage.

use std::sync::Arc;

/// Backend-neutral storage interface exposing filesystem-like semantics.
///
/// All paths passed to this trait are UTF-8 relative paths within the
/// adapter-managed storage root.
///
/// Callers treat these operations as whole-file primitives. In particular,
/// `write_and_replace_file` should not expose partial contents to later
/// `read_file` calls, and `list_dir` must return only direct child names.
pub trait StorageAdapter: std::fmt::Debug + Send + Sync {
    /// Read a file.
    ///
    /// Return `Ok(None)` when `path` does not exist.
    fn read_file(&self, path: &str) -> std::result::Result<Option<Vec<u8>>, String>;

    /// Write or replace a file atomically.
    ///
    /// Callers expect to observe either the previous file contents or the new
    /// contents, never a partially written file.
    fn write_and_replace_file(
        &self,
        path: &str,
        contents: &[u8],
    ) -> std::result::Result<(), String>;

    /// Delete a file.
    ///
    /// Missing-file behavior is backend-defined, but treating an absent file as
    /// success is usually the most convenient choice.
    fn remove_file(&self, path: &str) -> std::result::Result<(), String>;

    /// List direct entries in a directory.
    ///
    /// The returned strings are entry names, not full paths.
    /// Nested descendants must not be flattened into the result.
    fn list_dir(&self, path: &str) -> std::result::Result<Vec<String>, String>;

    /// Try to acquire an exclusive lock for `path`.
    ///
    /// This method must not block.
    ///
    /// Returns true if the lock is held after this call.
    fn try_lock(&self, path: &str) -> std::result::Result<bool, String>;

    /// Release a lock for `path`.
    ///
    /// After a successful `unlock`, another caller should be able to acquire
    /// the same lock with `try_lock`.
    fn unlock(&self, path: &str) -> std::result::Result<(), String>;
}

/// Shared handle to a storage adapter.
///
/// This is the type accepted by `arti-client` and `tor-dirmgr` builder APIs.
pub type StorageAdapterHandle = Arc<dyn StorageAdapter>;
