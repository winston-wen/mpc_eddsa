mod sesman;
use sesman::client::ShowcaseSesmanClient;

use std::collections::{HashMap, HashSet};

use libexception::*;
use mpc_algo::*;
use mpc_spec::MpcAddr;

#[tokio::main] // `tokio` re-exported by `mpc_sesman::prelude::*`
async fn main() -> Outcome<()> {
    use clap::{Arg, ArgAction, Command};
    let matches = Command::new("demo_keygen")
        .arg(
            Arg::new("member_name")
                .short('n')
                .required(true)
                .action(ArgAction::Set),
        )
        .get_matches();

    let name = matches.get_one::<String>("member_name").ifnone_()?.clone();
    let key_arch = showcase_key_arch();
    let whoami = showcase_name_id(&name).catch_()?;

    let client = ShowcaseSesmanClient {};
    let keystore = algo_keygen(&client, &key_arch, &whoami, "showcase")
        .await
        .catch_()?;

    use tokio::{
        fs::{create_dir_all, File},
        io::AsyncWriteExt,
    };
    create_dir_all("keystore").await.catch_()?;
    let path = format!("keystore/{}.dat", &name);
    let mut file = File::create(path).await.catch_()?;
    let buf = serde_pickle::to_vec(&keystore, Default::default()).catch_()?;
    file.write_all(&buf).await.catch_()?;

    Ok(())
}

fn showcase_key_arch() -> HashMap<u16, (usize, HashSet<MpcAddr>)> {
    let mut res = HashMap::new();

    let gid_th_n_list = vec![(1, 7, 10), (2, 3, 5), (3, 3, 5)];
    for (gid, th, n) in gid_th_n_list {
        let members = (1..=n).map(|i| MpcAddr::new(gid, i)).collect();
        res.insert(gid, (th, members));
    }

    res
}

#[rustfmt::skip]
fn showcase_name_id(name: &str) -> Outcome<Vec<MpcAddr>> {
    match name {
        "Li" => Ok(vec![MpcAddr::new(1,  1), MpcAddr::new(2, 1)]),
        "Na" => Ok(vec![MpcAddr::new(1,  2), MpcAddr::new(2, 2)]),
        "K"  => Ok(vec![MpcAddr::new(1,  3), MpcAddr::new(2, 3)]),
        "Rb" => Ok(vec![MpcAddr::new(1,  4), MpcAddr::new(2, 4)]),
        "Cs" => Ok(vec![MpcAddr::new(1,  5), MpcAddr::new(2, 5)]),
        "Be" => Ok(vec![MpcAddr::new(1,  6), MpcAddr::new(3, 1)]),
        "Mg" => Ok(vec![MpcAddr::new(1,  7), MpcAddr::new(3, 2)]),
        "Ca" => Ok(vec![MpcAddr::new(1,  8), MpcAddr::new(3, 3)]),
        "Sr" => Ok(vec![MpcAddr::new(1,  9), MpcAddr::new(3, 4)]),
        "Ba" => Ok(vec![MpcAddr::new(1, 10), MpcAddr::new(3, 5)]),
        _ => throw!(
            "NameNotSupported",
            format!("This showcase has no member named {}", name)
        ),
    }
}
