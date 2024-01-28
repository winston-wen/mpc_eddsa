pub mod exception;
pub mod prelude {
    pub use crate::exception::*;
    pub use crate::{assert_throw, throw};
    pub use crate::{gather, receive, scatter, send, Message, PARTY_ID_BCAST};
    pub use tokio;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Message {
    pub src: u16,
    pub dst: u16,
    pub topic: String,
    pub obj: Option<Vec<u8>>,
}

pub async fn scatter<T>(src: u16, dst_set: &HashSet<u16>, topic: &str, obj: &T) -> Outcome<()>
where
    T: Serialize + DeserializeOwned,
{
    let obj = obj.compress().catch_()?;
    let client = reqwest::Client::new();
    for dst in dst_set {
        let msg = Message {
            src,
            dst: *dst,
            topic: topic.to_string(),
            obj: Some(obj.clone()),
        };
        let _void = client.post(URL_SEND).json(&msg).send().await.catch_()?;
    }

    Ok(())
}

pub async fn gather<T>(src_set: &HashSet<u16>, dst: u16, topic: &str) -> Outcome<HashMap<u16, T>>
where
    T: Serialize + DeserializeOwned,
{
    let client = reqwest::Client::new();
    let mut ret: HashMap<u16, T> = HashMap::with_capacity(src_set.len());
    for src in src_set {
        let index = Message {
            src: *src,
            dst,
            topic: topic.to_string(),
            obj: None,
        };
        'inner: loop {
            let req = client.post(URL_RECV).json(&index);
            let resp = req.send().await.catch_()?;
            let msg: Message = resp.json().await.catch_()?;
            match msg.obj {
                Some(obj) => {
                    let obj = obj.decompress().catch_()?;
                    ret.insert(*src, obj);
                    break 'inner;
                }
                None => {
                    use tokio::time::{sleep, Duration};
                    sleep(Duration::from_millis(DEFAULT_POLL_SLEEP_MS)).await;
                }
            }
        }
    }
    Ok(ret)
}

pub async fn send<T>(src: u16, dst: u16, topic: &str, obj: &T) -> Outcome<()>
where
    T: Serialize + DeserializeOwned,
{
    let obj = obj.compress().catch_()?;
    let msg = Message {
        src,
        dst,
        topic: topic.to_string(),
        obj: Some(obj.clone()),
    };
    let client = reqwest::Client::new();
    let _void = client.post(URL_SEND).json(&msg).send().await.catch_()?;

    Ok(())
}

pub async fn receive<T>(src: u16, dst: u16, topic: &str) -> Outcome<T>
where
    T: Serialize + DeserializeOwned,
{
    let client = reqwest::Client::new();
    let index = Message {
        src,
        dst,
        topic: topic.to_string(),
        obj: None,
    };
    loop {
        let req = client.post(URL_RECV).json(&index);
        let resp = req.send().await.catch_()?;
        let msg: Message = resp.json().await.catch_()?;
        match msg.obj {
            Some(obj) => {
                let obj = obj.decompress().catch_()?;
                return Ok(obj);
            }
            None => {
                use tokio::time::{sleep, Duration};
                sleep(Duration::from_millis(DEFAULT_POLL_SLEEP_MS)).await;
            }
        }
    }
}

trait CompressAble {
    fn compress(&self) -> Outcome<Vec<u8>>;
}

trait DecompressAble<T> {
    fn decompress(&self) -> Outcome<T>;
}

impl<T> CompressAble for T
where
    T: Serialize + DeserializeOwned,
{
    fn compress(&self) -> Outcome<Vec<u8>> {
        let json = serde_json::to_string(&self).catch_()?;
        let bytes = compress_to_vec(json.as_bytes(), 7);
        Ok(bytes)
    }
}

impl<S, D> DecompressAble<D> for S
where
    S: AsRef<[u8]>,
    D: Serialize + DeserializeOwned,
{
    fn decompress(&self) -> Outcome<D> {
        let bytes = decompress_to_vec(self.as_ref()).catch_()?;
        let json = String::from_utf8(bytes).catch_()?;
        let obj = serde_json::from_str(&json).catch_()?;
        Ok(obj)
    }
}

use std::collections::{HashMap, HashSet};

use crate::prelude::*;
use miniz_oxide::{deflate::compress_to_vec, inflate::decompress_to_vec};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

pub const PARTY_ID_BCAST: u16 = 0;
const URL_SEND: &'static str = "http://127.0.0.1:14514/postmsg";
const URL_RECV: &'static str = "http://127.0.0.1:14514/getmsg";
const DEFAULT_POLL_SLEEP_MS: u64 = 200;
