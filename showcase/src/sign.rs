mod sesman;
use clap::{value_parser, Arg, ArgAction, Command};
use sesman::client::ShowcaseSesmanClient;
use sha2::{Digest, Sha512};

use std::collections::HashSet;

use libexception::*;
use mpc_algo::*;
use mpc_spec::{Shard, ShardId};

fn showcase_msg_hash() -> Vec<u8> {
    let msg = "Je ne veux pas travailler. Je ne veux pas déjeuner. Je veux seulement l'oublier. Et puis je fume.";
    let mut hasher = Sha512::new();
    hasher.update(msg.as_bytes());
    hasher.finalize().to_vec()
}

pub const MSG: &str =
    "Je ne veux pas travailler. Je ne veux pas déjeuner. Je veux seulement l'oublier. Et puis je fume.";

#[tokio::main] // `tokio` re-exported by `mpc_sesman::prelude::*`
async fn main() -> Outcome<()> {
    // parse command line arguments
    let matches = Command::new("demo_keygen")
        .arg(
            Arg::new("signer_id")
                .short('i')
                .required(true)
                .value_parser(value_parser!(u16))
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new("signers")
                .short('s')
                .required(true)
                .value_parser(value_parser!(u16))
                .num_args(1..)
                .value_delimiter(' ')
                .action(ArgAction::Set),
        )
        .get_matches();
    let my_id = *matches.get_one::<u16>("signer_id").ifnone_()?;
    let signers: Vec<u16> = matches
        .get_many::<u16>("signers")
        .ifnone_()?
        .cloned()
        .collect();
    println!("signer_id: {}, signers: {:?}", my_id, &signers);
    let my_id = ShardId::new(0, my_id);
    let signers: HashSet<ShardId> = signers.into_iter().map(|id| ShardId::new(0, id)).collect();

    // load keystore
    use tokio::{fs::File, io::AsyncReadExt};
    let path = &format!("keystore/{}.dat", my_id);
    let mut file = File::open(path).await.catch("", &path)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).await.catch_()?;
    let keystore: Shard<_, _> = serde_pickle::from_slice(&buf, Default::default()).catch_()?;

    // sign
    let client = ShowcaseSesmanClient {};
    let sig = algo_sign(
        &client,
        &signers,
        "m/1/14/514",
        &showcase_msg_hash(),
        &keystore,
    )
    .await
    .catch_()?;

    '_print: {
        let sig_r = bs58::encode(&sig.r.compress().as_bytes()).into_string();
        let sig_s = bs58::encode(&sig.s.as_bytes()).into_string();
        let tx_hash = bs58::encode(&sig.hash).into_string();
        println!("sig_r: {}", sig_r);
        println!("sig_s: {}", sig_s);
        println!("tx_hash: {}", tx_hash);
    }

    Ok(())
}
