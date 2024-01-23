#[tokio::main] // `tokio` re-exported by `mpc_sesman::prelude::*`
async fn main() -> Outcome<()> {
    let matches = Command::new("demo_keygen")
        .arg(
            Arg::new("member_id")
                .short('m')
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
            Arg::new("n_members")
                .short('n')
                .required(true)
                .value_parser(value_parser!(u16))
                .action(ArgAction::Set),
        )
        .get_matches();

    let member_id = *matches.get_one::<u16>("member_id").ifnone_()?;
    let threshold = *matches.get_one::<u16>("threshold").ifnone_()?;
    let n_members = *matches.get_one::<u16>("n_members").ifnone_()?;

    println!("member_id: {member_id}, threshold: {threshold}, n_members: {n_members}");

    let keystore: KeyStore = algo_keygen(member_id, threshold, n_members, "demo_keygen")
        .await
        .catch_()?;

    let path = &format!("assets/{}@demo_keygen.keystore", member_id);
    create_dir_all("assets").await.catch_()?;
    let mut file = File::create(path).await.catch_()?;
    let buf = serde_json::to_vec(&keystore).catch_()?;
    file.write_all(&buf).await.catch_()?;

    Ok(())
}

use clap::{value_parser, Arg, ArgAction, Command};
use mpc_algo::{algo_keygen, KeyStore};
use mpc_sesman::prelude::tokio::{fs::create_dir_all, fs::File, io::AsyncWriteExt};
use mpc_sesman::prelude::*;
