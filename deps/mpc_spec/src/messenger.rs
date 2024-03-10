use std::collections::{HashMap, HashSet};
use std::fmt::Display;

use super::ShardId;

use async_trait::async_trait;
use serde::{de::DeserializeOwned, Serialize};

#[async_trait]
pub trait Messenger {
    type E: Display + Send + Sync + 'static;

    async fn send<T>(
        &self,
        topic: &str,
        src: ShardId,
        dst: ShardId,
        obj: &T,
    ) -> Result<(), Self::E>
    where
        T: Serialize + DeserializeOwned + Send + Sync;

    async fn receive<T>(&self, topic: &str, src: ShardId, dst: ShardId) -> Result<T, Self::E>
    where
        T: Serialize + DeserializeOwned + Send + Sync;

    async fn scatter<T>(
        &self,
        topic: &str,
        src: ShardId,
        dsts: &HashSet<ShardId>,
        obj: &T,
    ) -> Result<(), Self::E>
    where
        T: Serialize + DeserializeOwned + Send + Sync;

    async fn gather<T>(
        &self,
        topic: &str,
        srcs: &HashSet<ShardId>,
        dst: ShardId,
    ) -> Result<HashMap<ShardId, T>, Self::E>
    where
        T: Serialize + DeserializeOwned + Send + Sync;
}
