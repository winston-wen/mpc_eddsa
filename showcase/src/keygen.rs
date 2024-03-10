mod sesman;
use sesman::client::ShowcaseSesmanClient;

use std::collections::HashSet;

use libexception::*;
use mpc_algo::*;
use mpc_spec::ShardId;

#[tokio::main] // `tokio` re-exported by `mpc_sesman::prelude::*`
async fn main() -> Outcome<()> {
    use clap::{value_parser, Arg, ArgAction, Command};
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

    let my_id = *matches.get_one::<u16>("member_id").ifnone_()?;
    let my_id = ShardId::new(0, my_id);
    let th = *matches.get_one::<u16>("threshold").ifnone_()?;
    let members: Vec<u16> = matches
        .get_many::<u16>("members")
        .ifnone_()? // iterator of `&u16`
        .cloned()
        .collect();
    let members: HashSet<ShardId> = members.into_iter().map(|id| ShardId::new(0, id)).collect();

    println!(
        "member_id: {}, threshold: {}, members: {:?}",
        my_id, th, &members
    );

    let client = ShowcaseSesmanClient {};
    let keystore = algo_keygen(&client, my_id, th, &members, "showcase")
        .await
        .catch_()?;

    use tokio::{
        fs::{create_dir_all, File},
        io::AsyncWriteExt,
    };
    create_dir_all("keystore").await.catch_()?;
    let path = format!("keystore/{}.dat", my_id);
    let mut file = File::create(path).await.catch_()?;
    let buf = serde_pickle::to_vec(&keystore, Default::default()).catch_()?;
    file.write_all(&buf).await.catch_()?;

    Ok(())
}
