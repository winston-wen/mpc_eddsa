#[tokio::main] // `tokio` re-exported by `mpc_sesman::prelude::*`
async fn main() -> Outcome<()> {
    let matches = Command::new("demo_keygen")
        .arg(
            Arg::new("member_id")
                .short('i')
                .required(true)
                .value_parser(value_parser!(u16))
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new("threshold")
                .short('t')
                .required(true)
                .value_parser(value_parser!(u16))
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new("members")
                .short('m')
                .required(true)
                .value_parser(value_parser!(u16))
                .num_args(1..)
                .value_delimiter(' ')
                .action(ArgAction::Set),
        )
        .get_matches();

    let member_id = *matches.get_one::<u16>("member_id").ifnone_()?;
    let threshold = *matches.get_one::<u16>("threshold").ifnone_()?;
    let members: HashSet<u16> = matches
        .get_many::<u16>("members")
        .ifnone_()? // iterator of `&u16`
        .cloned()
        .collect();

    println!(
        "member_id: {}, threshold: {}, members: {:?}",
        member_id, threshold, &members
    );

    let keystore: KeyStore = algo_keygen(member_id, threshold, &members, "demo_keygen")
        .await
        .catch_()?;

    let path = &format!("assets/{}@demo_keygen.keystore", member_id);
    create_dir_all("assets").await.catch_()?;
    let mut file = File::create(path).await.catch_()?;
    let buf = serde_json::to_vec(&keystore).catch_()?;
    file.write_all(&buf).await.catch_()?;

    Ok(())
}

use std::collections::HashSet;

use clap::{value_parser, Arg, ArgAction, Command};
use mpc_algo::{algo_keygen, KeyStore};
use mpc_sesman::prelude::tokio::{fs::create_dir_all, fs::File, io::AsyncWriteExt};
use mpc_sesman::prelude::*;
