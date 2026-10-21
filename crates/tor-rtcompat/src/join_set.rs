//! Module exposing [`FuturesJoinSet`].

use async_trait::async_trait;
use futures::future::RemoteHandle;
use futures::stream::{FuturesUnordered, StreamExt};
use futures::task::SpawnError;

use std::io::Result as IoResult;

use crate::traits::{JoinSet, SpawnExt};

/// A [`futures`]-based [`JoinSet`] implementation.
pub struct FuturesJoinSet<T, R> {
    /// The runtime to spawn tasks on.
    runtime: R,
    /// The currently pending tasks.
    pending: FuturesUnordered<RemoteHandle<T>>,
}

impl<T, R> FuturesJoinSet<T, R>
where
    T: Send + Sync + 'static,
    R: SpawnExt + Send + Sync + 'static,
{
    /// Create a [`FuturesJoinSet`], for spawning tasks on `runtime`.
    pub fn new(runtime: R) -> Self {
        Self {
            runtime,
            pending: Default::default(),
        }
    }
}

#[async_trait]
impl<T, R> JoinSet<T> for FuturesJoinSet<T, R>
where
    T: Send + Sync + 'static,
    R: SpawnExt + Send + Sync + 'static,
{
    fn spawn<F>(&mut self, task: F) -> Result<(), SpawnError>
    where
        F: Future<Output = T> + Send + 'static,
    {
        let handle = self.runtime.spawn_with_handle(task)?;
        self.pending.push(handle);
        Ok(())
    }

    async fn join_next(&mut self) -> Option<IoResult<T>> {
        self.pending.next().await.map(Ok)
    }
}
