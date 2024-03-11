mod sesman;
use clap::{Arg, ArgAction, Command};
use sesman::client::ShowcaseSesmanClient;
use sha2::{Digest, Sha512};

use std::collections::{HashMap, HashSet};

use libexception::*;
use mpc_algo::*;
use mpc_spec::MpcAddr;

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
    let matches = Command::new("demo_sign")
        .arg(
            Arg::new("member_name")
                .short('n')
                .required(true)
                .action(ArgAction::Set),
        )
        .get_matches();

    let member_name = matches.get_one::<String>("member_name").ifnone_()?.clone();
    let ses_arch = showcase_ses_arch();

    // load keystore
    use tokio::{fs::File, io::AsyncReadExt};
    let path = &format!("keystore/{}.dat", &member_name);
    let mut file = File::open(path).await.catch("", &path)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).await.catch_()?;
    let keystore = serde_pickle::from_slice(&buf, Default::default()).catch_()?;

    // sign
    let client = ShowcaseSesmanClient {};
    let sig = algo_sign(
        &client,
        &ses_arch,
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

fn showcase_ses_arch() -> HashMap<u16, HashSet<MpcAddr>> {
    let mut res = HashMap::new();
    let gid_members_list = vec![
        (1, vec![1, 2, 3, 6, 7, 8, 10]),
        (2, vec![1, 2, 3]),
        (3, vec![1, 2, 3, 5]),
    ];

    for (gid, members) in gid_members_list {
        let members = members.into_iter().map(|i| MpcAddr::new(gid, i)).collect();
        res.insert(gid, members);
    }

    res
}
