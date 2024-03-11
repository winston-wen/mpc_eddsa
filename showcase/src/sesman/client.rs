use std::collections::{HashMap, HashSet};

use libexception::*;
use mpc_spec::*;
use serde::{de::DeserializeOwned, Serialize};

use super::{protogen::sesman::sesman_client::SesmanClient, GRPC_URL};
use crate::sesman::protogen::sesman::Message;

#[derive(Clone, Copy)]
pub struct ShowcaseSesmanClient;

#[async_trait]
impl Messenger for ShowcaseSesmanClient {
    type E = Box<Exception>;

    async fn send<T>(
        &self,        //
        topic: &str,  //
        src: MpcAddr, //
        dst: MpcAddr, //
        obj: &T,      //
    ) -> Outcome<()>
    where
        T: Serialize + DeserializeOwned + Send + Sync,
    {
        let mut cl = SesmanClient::connect(GRPC_URL)
            .await
            .map_err(|e| format!("ConnectionError: {:#?}", e))
            .catch_()?;

        let obj = serde_pickle::to_vec(obj, Default::default()).catch_()?;
        let req = Message {
            topic: topic.to_string(),
            src: src.as_primitive(),
            dst: dst.as_primitive(),
            obj: Some(obj),
        };

        cl.inbox(req).await.catch_()?;
        Ok(())
    }

    async fn receive<T>(
        &self,        //
        topic: &str,  //
        src: MpcAddr, //
        dst: MpcAddr, //
    ) -> Outcome<T>
    where
        T: Serialize + DeserializeOwned + Send + Sync,
    {
        let mut cl = SesmanClient::connect(GRPC_URL)
            .await
            .catch("ConnectionError", GRPC_URL)?;

        let msg = Message {
            topic: topic.to_string(),
            src: src.as_primitive(),
            dst: dst.as_primitive(),
            obj: None, // as index
        };
        loop {
            let resp = cl.outbox(msg.clone()).await.catch_()?.into_inner();
            if let Some(obj) = resp.obj {
                let obj = serde_pickle::from_slice(&obj, Default::default()).catch_()?;
                return Ok(obj);
            }
            use tokio::time::{sleep, Duration};
            sleep(Duration::from_millis(200)).await;
        }
    }

    async fn scatter<T>(
        &self,                   //
        topic: &str,             //
        src: MpcAddr,            //
        dsts: &HashSet<MpcAddr>, //
        obj: &T,                 //
    ) -> Outcome<()>
    where
        T: Serialize + DeserializeOwned + Send + Sync,
    {
        let mut cl = SesmanClient::connect(GRPC_URL)
            .await
            .catch("ConnectionError", GRPC_URL)?;

        let obj = serde_pickle::to_vec(obj, Default::default()).catch_()?;
        for dst in dsts.iter() {
            let req = Message {
                topic: topic.to_string(),
                src: src.as_primitive(),
                dst: dst.as_primitive(),
                obj: Some(obj.clone()),
            };
            cl.inbox(req).await.catch_()?;
        }
        Ok(())
    }

    async fn gather<T>(
        &self,                   //
        topic: &str,             //
        srcs: &HashSet<MpcAddr>, //
        dst: MpcAddr,            //
    ) -> Outcome<HashMap<MpcAddr, T>>
    where
        T: Serialize + DeserializeOwned + Send + Sync,
    {
        let mut cl = SesmanClient::connect(GRPC_URL)
            .await
            .catch("ConnectionError", GRPC_URL)?;

        let mut ret: HashMap<MpcAddr, T> = HashMap::new();
        for src in srcs.iter() {
            let msg = Message {
                topic: topic.to_string(),
                src: src.as_primitive(),
                dst: dst.as_primitive(),
                obj: None, // as index
            };
            loop {
                let resp = cl.outbox(msg.clone()).await.catch_()?.into_inner();
                if let Some(obj) = resp.obj {
                    let obj = serde_pickle::from_slice(&obj, Default::default()).catch_()?;
                    ret.insert(*src, obj);
                    break;
                }
                use tokio::time::{sleep, Duration};
                sleep(Duration::from_millis(500)).await;
            }
        }
        Ok(ret)
    }
}
