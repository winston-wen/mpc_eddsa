mod sesman;

use libexception::*;
use sesman::server::ShowcaseSesmanServer;

#[tokio::main]
async fn main() -> Outcome<()> {
    let server = ShowcaseSesmanServer::new().await.catch_()?;
    server.run().await.catch_()?;
    Ok(())
}
