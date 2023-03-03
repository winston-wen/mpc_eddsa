#![allow(non_snake_case)]
#![feature(proc_macro_hygiene, decl_macro)]
use std::fs;

use curve25519_dalek::ristretto::RistrettoPoint;

use clap::{Arg, ArgAction, Command};

use crate::common::party_i::{KeyGenDKGCommitment, KeyInitial, KeyPair};
use common::{keygen, manager, sign, Params};

mod common;

fn main() {
    let matches =
        Command::new("MPC_EDDSA-FROST")
            .version("0.1.0")
            .author("TAIYI TECH")
            .subcommand_required(true)
            .arg_required_else_help(true)
            .subcommands(vec![
                Command::new("manager").about("Run state manager"),
                Command::new("keygen")
                    .about("Run keygen")
                    .arg(
                        Arg::new("keysfile")
                            .index(1)
                            .required(true)
                            .num_args(1)
                            .help("Target keys file"),
                    )
                    .arg(
                        Arg::new("params")
                            .index(2)
                            .required(true)
                            .num_args(1)
                            .help("Threshold params: threshold/parties (t/n). E.g. 1/3."),
                    )
                    .arg(
                        Arg::new("manager_addr")
                            .short('a')
                            .long("addr")
                            .num_args(1)
                            .help("URL to manager. E.g. http://127.0.0.2:8002"),
                    ),
                Command::new("sign")
                    .about("Run sign")
                    .arg(
                        Arg::new("keysfile")
                            .index(1)
                            .required(true)
                            .num_args(1)
                            .help("Keys file"),
                    )
                    .arg(Arg::new("params").index(2).required(true).num_args(1).help(
                        "Threshold params: threshold/parties/share_count (t/t'/n). E.g. 1/2/3.",
                    ))
                    .arg(
                        Arg::new("message")
                            .index(3)
                            .required(true)
                            .num_args(1)
                            .help("Message to sign in hex format"),
                    )
                    .arg(
                        Arg::new("path")
                            .short('p')
                            .long("path")
                            .num_args(1)
                            .help("Derivation path"),
                    )
                    .arg(
                        Arg::new("manager_addr")
                            .short('a')
                            .long("addr")
                            .num_args(1)
                            .help("URL to manager"),
                    ),
            ])
            .get_matches();

    match matches.subcommand() {
        Some(("sign", sub_matches)) => {
            let keysfile_path = sub_matches
                .get_one::<String>("keysfile")
                .map(|s| s.as_str())
                .unwrap_or("");

            // Read data from keys file
            let data = fs::read_to_string(keysfile_path).expect(
                format!("Unable to load keys file at location: {}", keysfile_path).as_str(),
            );
            let (party_key, signing_key, party_id, mut valid_com_vec, y_sum): (
                KeyInitial,
                KeyPair,
                u32,
                Vec<KeyGenDKGCommitment>,
                RistrettoPoint,
            ) = serde_json::from_str(&data).unwrap();

            // // Get root pub key or HD non-hardened pub key at specified path
            // let path = sub_matches
            //     .get_one::<String>("path")
            //     .map(|s| s.as_str())
            //     .unwrap_or("");
            // let (tweak_sk, y_sum) = match path.is_empty() {
            //     true => (Scalar::<Secp256k1>::zero(), y_sum),
            //     false => call_hd_key(path, y_sum, chain_code),
            // };

            // Parse message to sign
            let message_str = sub_matches
                .get_one::<String>("message")
                .map(|s| s.as_str())
                .unwrap_or("");
            let message = match hex::decode(message_str.clone()) {
                Ok(x) => x,
                Err(_e) => message_str.as_bytes().to_vec(),
            };
            let message = &message[..];
            let manager_addr = sub_matches
                .get_one::<String>("manager_addr")
                .map(|s| s.as_str())
                .unwrap_or("http://127.0.0.1:8001")
                .to_string();

            // Parse threshold params
            let params: Vec<&str> = sub_matches
                .get_one::<String>("params")
                .map(|s| s.as_str())
                .unwrap_or("")
                .split("/")
                .collect();
            let params = Params {
                threshold: params[0].to_string(),
                parties: params[1].to_string(),
                share_count: params[2].to_string(),
            };
            sign::run_sign(
                &manager_addr,
                &params,
                party_key,
                signing_key,
                y_sum,
                &mut valid_com_vec,
                party_id,
                &message,
            )
        }
        Some(("manager", _matches)) => {
            manager::run_manager();
        }
        Some(("keygen", sub_matches)) => {
            let addr = sub_matches
                .get_one::<String>("manager_addr")
                .map(|s| s.as_str())
                .unwrap_or("http://127.0.0.1:8001")
                .to_string();
            let keysfile_path = sub_matches
                .get_one::<String>("keysfile")
                .map(|s| s.as_str())
                .unwrap_or("")
                .to_string();
            let params: Vec<&str> = sub_matches
                .get_one::<String>("params")
                .map(|s| s.as_str())
                .unwrap_or("")
                .split("/")
                .collect();
            keygen::run_keygen(&addr, &keysfile_path, &params);
        }
        _ => {}
    }
}
