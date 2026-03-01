//! Storage adapter helpers for `tor-dirmgr`.
//!
//! This module provides a backend-neutral storage API.
//! Applications can provide any adapter that implements [`StorageAdapter`].

use std::sync::Arc;

/// Backend-neutral storage interface exposing filesystem-like semantics.
///
/// All paths passed to this trait are UTF-8 relative paths within the
/// adapter-managed storage root.
pub trait StorageAdapter: std::fmt::Debug + Send + Sync {
    /// Read a file.
    fn read_file(&self, path: &str) -> std::result::Result<Option<Vec<u8>>, String>;

    /// Write or replace a file atomically.
    fn write_and_replace_file(
        &self,
        path: &str,
        contents: &[u8],
    ) -> std::result::Result<(), String>;

    /// Delete a file.
    fn remove_file(&self, path: &str) -> std::result::Result<(), String>;

    /// List direct entries in a directory.
    ///
    /// The returned strings are entry names, not full paths.
    fn list_dir(&self, path: &str) -> std::result::Result<Vec<String>, String>;

    /// Try to acquire an exclusive lock for `path`.
    ///
    /// Returns true if the lock is held after this call.
    fn try_lock(&self, path: &str) -> std::result::Result<bool, String>;

    /// Release a lock for `path`.
    fn unlock(&self, path: &str) -> std::result::Result<(), String>;
}

/// Shared handle to a storage adapter.
pub type StorageAdapterHandle = Arc<dyn StorageAdapter>;
