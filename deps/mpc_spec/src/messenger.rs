use std::collections::{HashMap, HashSet};
use std::fmt::Display;

use super::MpcAddr;

use async_trait::async_trait;
use serde::{de::DeserializeOwned, Serialize};

#[async_trait]
pub trait Messenger {
    type E: Display + Send + Sync + 'static;

    async fn send<T>(
        &self,
        topic: &str,
        src: MpcAddr,
        dst: MpcAddr,
        obj: &T,
    ) -> Result<(), Self::E>
    where
        T: Serialize + DeserializeOwned + Send + Sync;

    async fn receive<T>(&self, topic: &str, src: MpcAddr, dst: MpcAddr) -> Result<T, Self::E>
    where
        T: Serialize + DeserializeOwned + Send + Sync;

    async fn scatter<T>(
        &self,
        topic: &str,
        src: MpcAddr,
        dsts: &HashSet<MpcAddr>,
        obj: &T,
    ) -> Result<(), Self::E>
    where
        T: Serialize + DeserializeOwned + Send + Sync;

    async fn gather<T>(
        &self,
        topic: &str,
        srcs: &HashSet<MpcAddr>,
        dst: MpcAddr,
    ) -> Result<HashMap<MpcAddr, T>, Self::E>
    where
        T: Serialize + DeserializeOwned + Send + Sync;
}
