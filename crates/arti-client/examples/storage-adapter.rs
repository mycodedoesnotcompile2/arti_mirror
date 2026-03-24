// @@ begin example lint list maintained by maint/add_warning @@
#![allow(unknown_lints)] // @@REMOVE_WHEN(ci_arti_nightly)
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
//! <!-- @@ end example lint list maintained by maint/add_warning @@ -->

//! This example shows how to provide a custom storage adapter to `arti-client`.
//!
//! On `wasm32-unknown-unknown`, a storage adapter is required and becomes the
//! client's persistent backend. On native targets, this example still compiles
//! and shows the wiring, but Arti currently continues to use filesystem-backed
//! storage.

use anyhow::Result;
use arti_client::TorClient;
use arti_client::config::TorClientConfigBuilder;
use arti_client::storage_adapter::{StorageAdapter, StorageAdapterHandle};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use tokio_crate as tokio;

#[derive(Debug, Default)]
struct MemoryStorage {
    files: Mutex<HashMap<String, Vec<u8>>>,
    locks: Mutex<HashSet<String>>,
}

impl StorageAdapter for MemoryStorage {
    fn read_file(&self, path: &str) -> Result<Option<Vec<u8>>, String> {
        Ok(self.files.lock().expect("lock poisoned").get(path).cloned())
    }

    fn write_and_replace_file(&self, path: &str, contents: &[u8]) -> Result<(), String> {
        self.files
            .lock()
            .expect("lock poisoned")
            .insert(path.to_owned(), contents.to_vec());
        Ok(())
    }

    fn remove_file(&self, path: &str) -> Result<(), String> {
        self.files.lock().expect("lock poisoned").remove(path);
        Ok(())
    }

    fn list_dir(&self, path: &str) -> Result<Vec<String>, String> {
        let prefix = format!("{path}/");
        let mut entries = self
            .files
            .lock()
            .expect("lock poisoned")
            .keys()
            .filter_map(|full_path| full_path.strip_prefix(&prefix))
            .filter(|entry| !entry.contains('/'))
            .map(str::to_owned)
            .collect::<Vec<_>>();
        entries.sort();
        entries.dedup();
        Ok(entries)
    }

    fn try_lock(&self, path: &str) -> Result<bool, String> {
        let mut locks = self.locks.lock().expect("lock poisoned");
        if locks.contains(path) {
            return Ok(false);
        }
        locks.insert(path.to_owned());
        Ok(true)
    }

    fn unlock(&self, path: &str) -> Result<(), String> {
        self.locks.lock().expect("lock poisoned").remove(path);
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let state_dir = tempfile::tempdir()?;
    let cache_dir = tempfile::tempdir()?;
    let config =
        TorClientConfigBuilder::from_directories(state_dir.path(), cache_dir.path()).build()?;

    let storage: StorageAdapterHandle = Arc::new(MemoryStorage::default());

    let _client = TorClient::builder()
        .config(config)
        .storage_adapter(storage)
        .create_unbootstrapped()?;

    eprintln!("constructed a client with a custom storage adapter");
    Ok(())
}
