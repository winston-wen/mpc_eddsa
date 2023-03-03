#![allow(non_snake_case)]
use std::{fs, time};

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use std::u32;

use reqwest::blocking::Client;

use crate::common::party_i::{
    generate_dkg_challenge, KeyGenDKGCommitment, KeyGenDKGProposedCommitment, KeyInitial, KeyPair,
    Share, Signature,
};
use crate::common::{
    aes_decrypt, aes_encrypt, broadcast, poll_for_broadcasts, poll_for_p2p, postb, sendp2p,
    Parameters, Params, PartySignup, AEAD,
};

pub fn run_keygen(addr: &String, keysfile_path: &String, params: &Vec<&str>) {
    let threshold: u32 = params[0].parse::<u32>().unwrap();
    let parties: u32 = params[1].parse::<u32>().unwrap();

    let client = Client::new();

    // delay
    let delay = time::Duration::from_millis(25);

    // signup
    let tn_params = Params {
        threshold: threshold.to_string(),
        parties: parties.to_string(),
        share_count: parties.to_string(),
    };
    let (party_num_int, uuid) = match keygen_signup(&addr, &client, &tn_params).unwrap() {
        PartySignup { number, uuid } => (number, uuid),
    };

    println!("number: {:?}, uuid: {:?}", party_num_int, uuid);

    let mut rng = OsRng;

    let party_key = KeyInitial::new(party_num_int, &mut rng);

    let (shares_com, shares) = party_key
        .generate_shares(parties, threshold, &mut rng)
        .unwrap();
    let context = "ed25519";
    let challenge =
        generate_dkg_challenge(party_num_int, context, party_key.g_u_i, party_key.g_k).unwrap();
    let sigma = &party_key.k + &party_key.u_i * challenge;

    let dkg_commitment = KeyGenDKGProposedCommitment {
        index: party_num_int,
        shares_commitment: shares_com,
        zkp: Signature {
            r: party_key.g_k,
            z: sigma,
        },
    };

    // round 1: send public commitment to coeffs and a proof of knowledge to u_i
    assert!(broadcast(
        &addr,
        &client,
        party_num_int,
        "round1",
        serde_json::to_string(&dkg_commitment).unwrap(),
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

    let mut dkg_com_vec = round1_ans_vec
        .iter()
        .map(|m| serde_json::from_str::<KeyGenDKGProposedCommitment>(m).unwrap())
        .collect::<Vec<_>>();
    dkg_com_vec.insert(party_num_int as usize - 1, dkg_commitment);

    let (invalid_peer_ids, valid_com_vec): (Vec<u32>, Vec<KeyGenDKGCommitment>) =
        KeyInitial::keygen_receive_commitments_and_validate_peers(dkg_com_vec, &context).unwrap();
    assert!(invalid_peer_ids.len() == 0);

    let mut enc_keys: Vec<RistrettoPoint> = Vec::new();
    for i in 1..=parties {
        if i != party_num_int {
            enc_keys.push(
                &valid_com_vec[i as usize - 1].shares_commitment.commitment[0] * &party_key.u_i,
            );
        }
    }

    let (head, tail) = valid_com_vec.split_at(1);
    let y_sum = tail
        .iter()
        .fold(head[0].shares_commitment.commitment[0].clone(), |acc, x| {
            acc + x.shares_commitment.commitment[0]
        });

    // round 2: send secret shares via aes-p2p
    let mut j = 0;
    for (k, i) in (1..=parties).enumerate() {
        if i != party_num_int {
            // prepare encrypted share for party i
            let key_i = &enc_keys[j].compress().to_bytes();
            let plaintext = shares[k].get_value().to_bytes();
            let aead_pack_i = aes_encrypt(key_i, &plaintext);
            assert!(sendp2p(
                &addr,
                &client,
                party_num_int,
                i,
                "round2",
                serde_json::to_string(&aead_pack_i).unwrap(),
                uuid.clone(),
            )
            .is_ok());
            j += 1;
        }
    }
    let round2_ans_vec = poll_for_p2p(
        &addr,
        &client,
        party_num_int,
        parties,
        delay,
        "round2",
        uuid.clone(),
    );

    let mut j = 0;
    let mut party_shares: Vec<Share> = Vec::new();
    for i in 1..=parties {
        if i == party_num_int {
            party_shares.push(shares[(i - 1) as usize].clone());
        } else {
            let aead_pack: AEAD = serde_json::from_str(&round2_ans_vec[j]).unwrap();
            let key_i = &enc_keys[j].compress().to_bytes();
            let out = aes_decrypt(key_i, aead_pack);
            let mut out_arr = [0u8; 32];
            out_arr.copy_from_slice(&out);
            let out_fe = Share::new_from(i, party_num_int, Scalar::from_bytes_mod_order(out_arr));
            party_shares.push(out_fe);
            j += 1;
        }
    }

    let signing_key: KeyPair = KeyInitial::keygen_verify_share_construct_keypair(
        party_shares,
        valid_com_vec.clone(),
        party_num_int,
    )
    .unwrap();

    let keygen_json = serde_json::to_string(&(
        party_key,
        signing_key,
        party_num_int,
        valid_com_vec,
        y_sum.compress().to_bytes(),
    ))
    .unwrap();
    println!("Keys data written to file: {:?}", keysfile_path);
    fs::write(&keysfile_path, keygen_json.clone()).expect("Unable to save !");
}

pub fn keygen_signup(addr: &String, client: &Client, params: &Params) -> Result<PartySignup, ()> {
    let res_body = postb(&addr, &client, "signupkeygen", params).unwrap();
    serde_json::from_str(&res_body).unwrap()
}
