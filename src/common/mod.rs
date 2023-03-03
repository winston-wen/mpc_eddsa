pub mod keygen;
pub mod manager;
pub mod party_i;
pub mod sign;

use std::{iter::repeat, thread, time, time::Duration};

use aes_gcm::aead::{Aead, NewAead, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::{rngs::OsRng, RngCore};

use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};

use curve25519_dalek::scalar::Scalar;

pub type Key = String;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct AEAD {
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct PartySignup {
    pub number: u32,
    pub uuid: String,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Index {
    pub key: Key,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Entry {
    pub key: Key,
    pub value: String,
}

#[derive(Debug)]
pub struct Parameters {
    pub threshold: u32,   //t
    pub share_count: u32, //n
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Params {
    pub threshold: String,
    pub parties: String,
    pub share_count: String,
}

#[allow(dead_code)]
pub fn aes_encrypt(key: &[u8], plaintext: &[u8]) -> AEAD {
    let mut full_length_key: [u8; 32] = [0; 32];
    full_length_key[(32 - key.len())..].copy_from_slice(key); // pad key with zeros

    let aes_key = aes_gcm::Key::from_slice(full_length_key.as_slice());
    let cipher = Aes256Gcm::new(aes_key);

    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let nonce = Nonce::from_slice(&nonce);

    // reserve for later changes when a non-empty aad could be imported
    let aad: Vec<u8> = repeat(0).take(16).collect();
    let payload = Payload {
        msg: plaintext,
        aad: &aad.as_slice(),
    };

    let ciphertext = cipher.encrypt(nonce, payload).expect("encryption failure!"); // NOTE: handle this error to avoid panics!

    AEAD {
        ciphertext: ciphertext,
        tag: nonce.to_vec(),
    }
}

#[allow(dead_code)]
pub fn aes_decrypt(key: &[u8], aead_pack: AEAD) -> Vec<u8> {
    let mut full_length_key: [u8; 32] = [0; 32];
    full_length_key[(32 - key.len())..].copy_from_slice(key); // Pad key with zeros

    let aes_key = aes_gcm::Key::from_slice(full_length_key.as_slice());
    let nonce = Nonce::from_slice(&aead_pack.tag);
    let gcm = Aes256Gcm::new(aes_key);

    // reserve for later changes when a non-empty aad could be imported
    let aad: Vec<u8> = repeat(0).take(16).collect();
    let payload = Payload {
        msg: aead_pack.ciphertext.as_slice(),
        aad: aad.as_slice(),
    };

    // NOTE: no error reported but return a value NONE when decrypt key is wrong
    let out = gcm.decrypt(nonce, payload);
    out.unwrap_or_default()
}

pub fn postb<T>(addr: &String, client: &Client, path: &str, body: T) -> Option<String>
where
    T: serde::ser::Serialize,
{
    let retries = 3;
    let retry_delay = time::Duration::from_millis(250);
    for _i in 1..retries {
        let addr = format!("{}/{}", addr, path);
        let res = client.post(&addr).json(&body).send();

        if let Ok(res) = res {
            return Some(res.text().unwrap());
        }
        thread::sleep(retry_delay);
    }
    None
}

pub fn broadcast(
    addr: &String,
    client: &Client,
    party_num: u32,
    round: &str,
    data: String,
    sender_uuid: String,
) -> Result<(), ()> {
    let key = format!("{}-{}-{}", party_num, round, sender_uuid);
    let entry = Entry {
        key: key.clone(),
        value: data,
    };

    let res_body = postb(&addr, &client, "set", entry).unwrap();
    serde_json::from_str(&res_body).unwrap()
}

pub fn sendp2p(
    addr: &String,
    client: &Client,
    party_from: u32,
    party_to: u32,
    round: &str,
    data: String,
    sender_uuid: String,
) -> Result<(), ()> {
    let key = format!("{}-{}-{}-{}", party_from, party_to, round, sender_uuid);

    let entry = Entry {
        key: key.clone(),
        value: data,
    };

    let res_body = postb(&addr, &client, "set", entry).unwrap();
    serde_json::from_str(&res_body).unwrap()
}

pub fn poll_for_broadcasts(
    addr: &String,
    client: &Client,
    party_num: u32,
    n: u32,
    delay: Duration,
    round: &str,
    sender_uuid: String,
) -> Vec<String> {
    let mut ans_vec = Vec::new();
    for i in 1..=n {
        if i != party_num {
            let key = format!("{}-{}-{}", i, round, sender_uuid);
            let index = Index { key };
            loop {
                // add delay to allow the server to process request:
                thread::sleep(delay);
                let res_body = postb(&addr, &client, "get", index.clone()).unwrap();
                let answer: Result<Entry, ()> = serde_json::from_str(&res_body).unwrap();
                if let Ok(answer) = answer {
                    ans_vec.push(answer.value);
                    println!("[{:?}] party {:?} => party {:?}", round, i, party_num);
                    break;
                }
            }
        }
    }
    ans_vec
}

pub fn poll_all_for_p2p(
    addr: &String,
    client: &Client,
    party_num: u32,
    n: u32,
    delay: Duration,
    round: &str,
    sender_uuid: String,
) -> Vec<String> {
    let mut ans_vec = Vec::new();
    for i in 1..=n {
        ans_vec.push(single_poll_for_p2p(
            addr,
            client,
            party_num,
            i,
            delay,
            round,
            sender_uuid.clone(),
        ));
    }
    ans_vec
}

pub fn poll_for_p2p(
    addr: &String,
    client: &Client,
    party_num: u32,
    n: u32,
    delay: Duration,
    round: &str,
    sender_uuid: String,
) -> Vec<String> {
    let mut ans_vec = Vec::new();
    for i in 1..=n {
        if i != party_num {
            ans_vec.push(single_poll_for_p2p(
                addr,
                client,
                party_num,
                i,
                delay,
                round,
                sender_uuid.clone(),
            ));
        }
    }
    ans_vec
}

pub fn single_poll_for_p2p(
    addr: &String,
    client: &Client,
    receiver_index: u32,
    sender_index: u32,
    delay: Duration,
    round: &str,
    sender_uuid: String,
) -> String {
    let mut ans = String::new();
    let key = format!(
        "{}-{}-{}-{}",
        sender_index, receiver_index, round, sender_uuid
    );
    let index = Index { key };
    loop {
        // add delay to allow the server to process request:
        thread::sleep(delay);
        let res_body = postb(&addr, &client, "get", index.clone()).unwrap();
        let answer: Result<Entry, ()> = serde_json::from_str(&res_body).unwrap();
        if let Ok(answer) = answer {
            ans = answer.value;
            println!(
                "[{:?}] party {:?} => party {:?}",
                round, sender_index, receiver_index
            );
            break;
        }
    }
    ans
}

// // check_sig by k256 crate (pk.verify() or pk.verify_digest())
// // msg = raw message
// #[allow(dead_code)]
// pub fn check_sig(
//     r: &Scalar<Secp256k1>,
//     s: &Scalar<Secp256k1>,
//     msg: &BigInt,
//     pk: &Point<Secp256k1>,
// ) {
//     // input parameter msg is the raw message to be signed

//     use k256::{
//         ecdsa::{signature::Verifier, Signature, VerifyingKey},
//         ScalarBytes,
//     };
//     use std::convert::TryFrom;
//     use std::ops::Deref;

//     let raw_pk = pk.to_bytes(false).to_vec();
//     let pk = VerifyingKey::from_sec1_bytes(&raw_pk).unwrap();
//     let secp_sig: Signature = Signature::from_scalars(
//         *ScalarBytes::try_from(r.to_bytes().deref())
//             .unwrap()
//             .as_bytes(),
//         *ScalarBytes::try_from(s.to_bytes().deref())
//             .unwrap()
//             .as_bytes(),
//     )
//     .unwrap();
//     assert!(pk
//         .verify(&BigInt::to_bytes(msg).as_slice(), &secp_sig)
//         .is_ok());
// }

pub fn scalar_split(num: &Scalar, count: &u32) -> Vec<Scalar> {
    let mut rng = rand::rngs::OsRng;
    let mut partition: Vec<Scalar> = Vec::new();
    for _j in 0..count - 1 {
        partition.push(Scalar::random(&mut rng));
    }
    let partial_sum: Scalar = partition.iter().sum();
    partition.push(num - partial_sum);
    partition
}
