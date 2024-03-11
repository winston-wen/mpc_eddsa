use libexception::*;
use sqlx::{Row, SqlitePool};
use tonic::{transport::Server, Request, Response, Status};

use crate::sesman::{DB_PATH, SQL_CREATE_TABLE};

use super::{
    protogen::sesman::{
        sesman_server::{Sesman, SesmanServer},
        Message, Void,
    },
    GRPC_URL, SQL_INSERT, SQL_SELECT,
};

pub struct ShowcaseSesmanServer {
    sqlite_pool: SqlitePool,
}

impl ShowcaseSesmanServer {
    #[allow(dead_code)] // used by ../sesman_server.rs but rustc doesn't know
    pub async fn new() -> Outcome<Self> {
        use tokio::fs::try_exists;
        use tokio::fs::{remove_file, File};

        if let Ok(true) = try_exists(DB_PATH).await {
            remove_file(DB_PATH)
                .await
                .catch("CannotRemoveFile", DB_PATH)?;
        }
        File::create(DB_PATH)
            .await
            .catch("CannotCreateFile", DB_PATH)?;

        let sqlite_pool = SqlitePool::connect(&DB_PATH)
            .await
            .catch("CannotConnectSqlite", DB_PATH)?;

        let _ = sqlx::query(SQL_CREATE_TABLE)
            .execute(&sqlite_pool)
            .await
            .catch("CannotCreateTable", DB_PATH)?;

        Ok(Self { sqlite_pool })
    }

    #[allow(dead_code)] // used by ../sesman_server.rs but rustc doesn't know
    pub async fn run(self) -> Outcome<()> {
        let listen_at = GRPC_URL[7..].parse().unwrap(); // remove "http://" prefix
        println!("SesmanServer will listen at {}", listen_at);
        Server::builder()
            .add_service(SesmanServer::new(self))
            .serve(listen_at)
            .await
            .catch("ServiceIsDown", "")?;
        Ok(())
    }

    async fn biz_inbox(&self, msg: Request<Message>) -> Outcome<Response<Void>> {
        let msg = msg.into_inner();
        let obj = msg.obj.ifnone_()?;

        sqlx::query(SQL_INSERT)
            .bind(&msg.topic)
            .bind(msg.src)
            .bind(msg.dst)
            .bind(&obj)
            .execute(&self.sqlite_pool)
            .await
            .catch_()?;

        Ok(Response::new(Void::default()))
    }

    async fn biz_outbox(&self, msg: Request<Message>) -> Outcome<Response<Message>> {
        let mut msg = msg.into_inner();

        let rows = sqlx::query(SQL_SELECT)
            .bind(&msg.topic)
            .bind(msg.src)
            .bind(msg.dst)
            .fetch_all(&self.sqlite_pool)
            .await
            .catch_()?;
        let obj: Option<Vec<u8>> = match rows.get(0) {
            Some(row) => Some(row.get(0)), // sqlx::get
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
