use dashmap::DashMap;
use libexception::*;
use tonic::{transport::Server, Request, Response, Status};

use super::{
    protogen::sesman::{
        sesman_server::{Sesman, SesmanServer},
        Message, Void,
    },
    GRPC_URL,
};

pub struct ShowcaseSesmanServer {
    db: DashMap<String, Vec<u8>>,
}

impl ShowcaseSesmanServer {
    #[allow(dead_code)] // used by ../sesman_server.rs but rustc doesn't know
    pub async fn new() -> Outcome<Self> {
        let db = DashMap::new();
        Ok(Self { db })
    }

    #[allow(dead_code)] // used by ../sesman_server.rs but rustc doesdn't know
    pub async fn run(self) -> Outcome<()> {
        let serve_at = &GRPC_URL[7..];
        let serve_at = serve_at.parse().catch("InvalidUrl", serve_at)?;
        println!("SesmanServer will listen at {}", &serve_at);
        Server::builder()
            .add_service(SesmanServer::new(self))
            .serve(serve_at)
            .await
            .catch("ServiceIsDown", "")?;
        Ok(())
    }

    async fn biz_inbox(&self, msg: Request<Message>) -> Outcome<Response<Void>> {
        let msg = msg.into_inner();
        let obj = msg.obj.ifnone_()?;

        let k = format!("{}{}{}", msg.topic, msg.src, msg.dst);
        self.db.insert(k, obj);

        Ok(Response::new(Void::default()))
    }

    async fn biz_outbox(&self, msg: Request<Message>) -> Outcome<Response<Message>> {
        let mut msg = msg.into_inner();

        let k = format!("{}{}{}", msg.topic, msg.src, msg.dst);
        let obj: Option<Vec<u8>> = match self.db.get(&k) {
            Some(x) => Some(x.clone()), // sqlx::get
            None => None,
        };
        msg.obj = obj;

        Ok(Response::new(msg))
    }
}

#[tonic::async_trait] // equivalent to async_trait
impl Sesman for ShowcaseSesmanServer {
    async fn inbox(&self, msg: Request<Message>) -> Result<Response<Void>, Status> {
        self.biz_inbox(msg)
            .await
            .map_err(|e| Status::internal(e.to_string()))
    }

    async fn outbox(&self, msg: Request<Message>) -> Result<Response<Message>, Status> {
        self.biz_outbox(msg)
            .await
            .map_err(|e| Status::internal(e.to_string()))
    }
}
