//! Backend-neutral storage adapter types used by `arti-client`.
//!
//! Applications usually let Arti store its state on the local filesystem.
//! [`crate::TorClientBuilder::storage_adapter`] lets you provide a different
//! storage backend when that is not possible or not desirable.
//!
//! This is primarily intended for `wasm32-unknown-unknown`, where Arti cannot
//! rely on normal filesystem APIs. On that target, a storage adapter is
//! required and is used for:
//!
//! - persistent client state managed through `tor_persist`
//! - directory-manager blobs and lock files
//!
//! On non-wasm targets, Arti currently keeps using its filesystem-backed
//! storage and ignores any configured adapter.
//!
//! # Minimal adapter shape
//!
//! The adapter is a small filesystem-like trait: it reads whole files, writes
//! whole-file replacements, lists direct directory entries, and exposes a
//! nonblocking lock API.
//!
//! ```
//! use arti_client::storage_adapter::{StorageAdapter, StorageAdapterHandle};
//! use std::collections::{HashMap, HashSet};
//! use std::sync::{Arc, Mutex};
//!
//! #[derive(Debug, Default)]
//! struct MemoryStorage {
//!     files: Mutex<HashMap<String, Vec<u8>>>,
//!     locks: Mutex<HashSet<String>>,
//! }
//!
//! impl StorageAdapter for MemoryStorage {
//!     fn read_file(&self, path: &str) -> Result<Option<Vec<u8>>, String> {
//!         Ok(self.files.lock().unwrap().get(path).cloned())
//!     }
//!
//!     fn write_and_replace_file(
//!         &self,
//!         path: &str,
//!         contents: &[u8],
//!     ) -> Result<(), String> {
//!         self.files
//!             .lock()
//!             .unwrap()
//!             .insert(path.to_owned(), contents.to_vec());
//!         Ok(())
//!     }
//!
//!     fn remove_file(&self, path: &str) -> Result<(), String> {
//!         self.files.lock().unwrap().remove(path);
//!         Ok(())
//!     }
//!
//!     fn list_dir(&self, path: &str) -> Result<Vec<String>, String> {
//!         let prefix = format!("{path}/");
//!         let mut entries = self
//!             .files
//!             .lock()
//!             .unwrap()
//!             .keys()
//!             .filter_map(|full_path| full_path.strip_prefix(&prefix))
//!             .filter(|entry| !entry.contains('/'))
//!             .map(str::to_owned)
//!             .collect::<Vec<_>>();
//!         entries.sort();
//!         entries.dedup();
//!         Ok(entries)
//!     }
//!
//!     fn try_lock(&self, path: &str) -> Result<bool, String> {
//!         let mut locks = self.locks.lock().unwrap();
//!         if locks.contains(path) {
//!             return Ok(false);
//!         }
//!         locks.insert(path.to_owned());
//!         Ok(true)
//!     }
//!
//!     fn unlock(&self, path: &str) -> Result<(), String> {
//!         self.locks.lock().unwrap().remove(path);
//!         Ok(())
//!     }
//! }
//!
//! let storage: StorageAdapterHandle = Arc::new(MemoryStorage::default());
//! # let _ = storage;
//! ```
//!
//! # End-to-end client wiring
//!
//! The same adapter can be passed directly to
//! [`crate::TorClientBuilder::storage_adapter`].
//!
//! ```no_run
//! use arti_client::config::TorClientConfigBuilder;
//! use arti_client::storage_adapter::{StorageAdapter, StorageAdapterHandle};
//! use arti_client::TorClient;
//! use std::collections::{HashMap, HashSet};
//! use std::sync::{Arc, Mutex};
//!
//! #[derive(Debug, Default)]
//! struct MemoryStorage {
//!     files: Mutex<HashMap<String, Vec<u8>>>,
//!     locks: Mutex<HashSet<String>>,
//! }
//!
//! impl StorageAdapter for MemoryStorage {
//!     fn read_file(&self, path: &str) -> Result<Option<Vec<u8>>, String> {
//!         Ok(self.files.lock().unwrap().get(path).cloned())
//!     }
//!
//!     fn write_and_replace_file(
//!         &self,
//!         path: &str,
//!         contents: &[u8],
//!     ) -> Result<(), String> {
//!         self.files
//!             .lock()
//!             .unwrap()
//!             .insert(path.to_owned(), contents.to_vec());
//!         Ok(())
//!     }
//!
//!     fn remove_file(&self, path: &str) -> Result<(), String> {
//!         self.files.lock().unwrap().remove(path);
//!         Ok(())
//!     }
//!
//!     fn list_dir(&self, path: &str) -> Result<Vec<String>, String> {
//!         let prefix = format!("{path}/");
//!         let mut entries = self
//!             .files
//!             .lock()
//!             .unwrap()
//!             .keys()
//!             .filter_map(|full_path| full_path.strip_prefix(&prefix))
//!             .filter(|entry| !entry.contains('/'))
//!             .map(str::to_owned)
//!             .collect::<Vec<_>>();
//!         entries.sort();
//!         entries.dedup();
//!         Ok(entries)
//!     }
//!
//!     fn try_lock(&self, path: &str) -> Result<bool, String> {
//!         let mut locks = self.locks.lock().unwrap();
//!         if locks.contains(path) {
//!             return Ok(false);
//!         }
//!         locks.insert(path.to_owned());
//!         Ok(true)
//!     }
//!
//!     fn unlock(&self, path: &str) -> Result<(), String> {
//!         self.locks.lock().unwrap().remove(path);
//!         Ok(())
//!     }
//! }
//!
//! let state_dir = tempfile::tempdir()?;
//! let cache_dir = tempfile::tempdir()?;
//! let config = TorClientConfigBuilder::from_directories(state_dir.path(), cache_dir.path())
//!     .build()?;
//! let storage: StorageAdapterHandle = Arc::new(MemoryStorage::default());
//!
//! // On native targets the adapter is currently ignored and filesystem-backed
//! // storage is still used. On wasm32-unknown-unknown, this is the storage
//! // backend the client will use.
//! let client = TorClient::builder()
//!     .config(config)
//!     .storage_adapter(storage)
//!     .create_unbootstrapped()?;
//! # let _ = client;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! When using this API from `arti-client`, pass the adapter to
//! [`crate::TorClientBuilder::storage_adapter`]. On
//! `wasm32-unknown-unknown`, you must also provide networking with either
//! [`crate::TorClientBuilder::tcp_provider`] or
//! `TorClientBuilder::custom_network_provider`.

pub use tor_dirmgr::storage_adapter::{StorageAdapter, StorageAdapterHandle};
