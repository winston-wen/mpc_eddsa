#![allow(non_snake_case)]
use std::{fs, time};

use curve25519_dalek::ristretto::RistrettoPoint;
use rand::rngs::OsRng;
use std::collections::HashMap;

use reqwest::blocking::Client;
use serde_json::json;

use crate::common::party_i::{
    get_ith_pubkey, validate, KeyGenDKGCommitment, KeyInitial,
    KeyPair, Signature, SigningCommitmentPair, SigningResponse,
};
use crate::common::{broadcast, poll_for_broadcasts, Params, PartySignup};

pub fn run_sign(
    addr: &String,
    params: &Params,
    _party_key: KeyInitial,
    signing_key: KeyPair,
    y_sum: RistrettoPoint,
    valid_com_vec: &mut Vec<KeyGenDKGCommitment>,
    party_id: u32,
    message: &[u8],
) {
    let client = Client::new();
    let delay = time::Duration::from_millis(25);
    let threshold: u32 = params.threshold.parse::<u32>().unwrap();
    let parties: u32 = params.parties.parse::<u32>().unwrap();
    let share_count: u32 = params.share_count.parse::<u32>().unwrap();
    println!(
        "threshold: {}, parties: {}, share count: {}",
        threshold, parties, share_count
    );
    assert!(parties > threshold, "PARTIES smaller than THRESHOLD + 1");
    assert!(parties < share_count + 1, "PARTIES bigger than SHARE_COUNT");

    // Signup
    let (party_num_int, uuid) = match signup(&addr, &client, &params).unwrap() {
        PartySignup { number, uuid } => (number, uuid),
    };

    let debug = json!({"manager_addr": &addr, "party_num": party_num_int, "uuid": uuid});
    println!("{}", serde_json::to_string_pretty(&debug).unwrap());

    let mut rng = OsRng;

    // round 0: collect signer IDs
    assert!(broadcast(
        &addr,
        &client,
        party_num_int,
        "round0",
        serde_json::to_string(&party_id).unwrap(),
        uuid.clone(),
    )
    .is_ok());
    let round0_ans_vec = poll_for_broadcasts(
        &addr,
        &client,
        party_num_int,
        parties,
        delay,
        "round0",
        uuid.clone(),
    );
    let mut signers_vec = round0_ans_vec
        .iter()
        .map(|m| serde_json::from_str::<u32>(m).unwrap())
        .collect::<Vec<_>>();
    signers_vec.insert(party_num_int as usize - 1, party_id);

    let (signing_com_pair_i, mut signing_nonce_pair_i) =
        KeyPair::sign_preprocess(1, party_id, &mut rng).unwrap();

    // round 1: broadcast signing commitment pairs
    assert!(broadcast(
        &addr,
        &client,
        party_num_int,
        "round1",
        serde_json::to_string(&signing_com_pair_i[0]).unwrap(),
        uuid.clone(),
    )
    .is_ok());
    let round1_ans_vec = poll_for_broadcasts(
        &addr,
        &client,
        party_num_int,
        parties,
        delay,
        "round1",
        uuid.clone(),
    );
    let mut signing_com_pair_vec = round1_ans_vec
        .iter()
        .map(|m| serde_json::from_str::<SigningCommitmentPair>(m).unwrap())
        .collect::<Vec<_>>();
    signing_com_pair_vec.insert(party_num_int as usize - 1, signing_com_pair_i[0].clone());

    let response_i: SigningResponse = signing_key
        .sign_and_respond(
            &signing_com_pair_vec,
            &mut signing_nonce_pair_i,
            std::str::from_utf8(message).unwrap(),
        )
        .unwrap();

    // round 2: broadcast signing response
    assert!(broadcast(
        &addr,
        &client,
        party_num_int,
        "round2",
        serde_json::to_string(&response_i).unwrap(),
        uuid.clone(),
    )
    .is_ok());
    let round2_ans_vec = poll_for_broadcasts(
        &addr,
        &client,
        party_num_int,
        parties,
        delay,
        "round2",
        uuid.clone(),
    );
    let mut response_vec = round2_ans_vec
        .iter()
        .map(|m| serde_json::from_str::<SigningResponse>(m).unwrap())
        .collect::<Vec<_>>();
    response_vec.insert(party_num_int as usize - 1, response_i);

    // let signer_pubkeys: Vec<RistrettoPoint> = signers_vec
    //     .iter()
    //     .map(|index| get_ith_pubkey(*index, &valid_com_vec))
    //     .collect::<Vec<_>>();
    let mut signer_pubkeys: HashMap<u32, RistrettoPoint> =
        HashMap::with_capacity(signing_com_pair_vec.len());
    for counter in 0..signing_com_pair_vec.len() {
        let ith_pubkey = get_ith_pubkey(signers_vec[counter], &valid_com_vec);
        signer_pubkeys.insert(signers_vec[counter], ith_pubkey);
    }
    let group_sig: Signature = KeyPair::sign_aggregate_responses(
        std::str::from_utf8(message).unwrap(),
        &signing_com_pair_vec,
        &response_vec,
        &signer_pubkeys,
    )
    .unwrap();
    assert!(validate(
        std::str::from_utf8(message).unwrap(),
        &group_sig,
        signing_key.group_public
    )
    .is_ok());

    let ret_dict = json!({
        "r": hex::encode(group_sig.r.compress().as_bytes()),
        "s": hex::encode(group_sig.z.to_bytes().as_ref()),
        "status": "signature_ready",
        "pk": hex::encode(y_sum.compress().to_bytes().as_ref()),
        "msg_hex": hex::encode(message.as_ref()),
    });
    fs::write("signature".to_string(), ret_dict.to_string()).expect("Unable to save!");
    println!("party {:?} Output Signature: \n", party_num_int);
    println!("r: {:#?}", hex::encode(group_sig.r.compress().as_bytes()));
    println!("s: {:#?} \n", hex::encode(group_sig.z.to_bytes().as_ref()));
    println!(
        "pk: {:#?}",
        hex::encode(y_sum.compress().to_bytes().as_ref())
    );
    println!("msg_hex: {}", hex::encode(message.as_ref()));
}

pub fn postb<T>(addr: &String, client: &Client, path: &str, body: T) -> Option<String>
where
    T: serde::ser::Serialize,
{
    let res = client
        .post(&format!("{}/{}", addr, path))
        .json(&body)
        .send();
    Some(res.unwrap().text().unwrap())
}

pub fn signup(addr: &String, client: &Client, params: &Params) -> Result<PartySignup, ()> {
    let res_body = postb(&addr, &client, "signupsign", params).unwrap();
    let answer: Result<PartySignup, ()> = serde_json::from_str(&res_body).unwrap();
    return answer;
}
