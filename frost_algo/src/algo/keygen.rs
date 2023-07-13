#![allow(non_snake_case)]
use std::{fs, time};

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;

use reqwest::blocking::Client;

use luban_core::*;
use xuanmi_base_support::*;

use super::party_i::{
    generate_dkg_challenge, KeyGenDKGCommitment, KeyGenDKGProposedCommitment, KeyGenZKP,
    KeyInitial, KeyPair, Share,
};

use crate::algo::data_structure::KeyStore;
use crate::{
    DKGChallengeGenFailed, InvalidCommitment, InvalidConfigs, InvalidKeyGenZKP, SharesGenFailed,
    SignUpFailed,
};

use super::aes;

pub fn algo_keygen(server: &str, tr_uuid: &str, tn_config: &[u16; 2]) -> Outcome<KeyStore> {
    let (threshold, share_count, parties) = (tn_config[0], tn_config[1], tn_config[1]);
    println!(
        "Start keygen with \n\tthreshold={}, share_count={}",
        threshold, share_count,
    );
    if threshold >= share_count {
        throw!(
            name = InvalidConfigs,
            ctx = &format!(
                "t/n config should satisfy t<n.\n\tHowever, {}/{} were provided",
                threshold, share_count,
            )
        );
    }

    // #region signup for keygen
    let messenger =
        MpcClientMessenger::signup(server, "keygen", tr_uuid, threshold, parties, share_count)
            .catch(
                SignUpFailed,
                &format!(
                    "Cannot sign up for key geneation with server={}, tr_uuid={}.",
                    server, tr_uuid
                ),
            )?;
    let party_num_int = messenger.my_id();
    println!(
        "MPC Server \"{}\" designated this party with \n\tparty_id={}, tr_uuid={}",
        server,
        party_num_int,
        messenger.uuid()
    );
    let mut round: u16 = 1;
    let exception_location = &format!(
        " (at party_id={}, tr_uuid={}).",
        party_num_int,
        messenger.uuid()
    );
    // #endregion

    let mut rng = OsRng;

    let party_key = KeyInitial::new(party_num_int, &mut rng);

    let (shares_com, shares) = match party_key.generate_shares(parties, threshold, &mut rng) {
        Ok(_ok) => _ok,
        Err(_) => throw!(
            name = SharesGenFailed,
            ctx = &(("Failed to generate key shares").to_owned() + exception_location)
        ),
    };
    let context = "ed25519";
    let challenge =
        match generate_dkg_challenge(party_num_int, context, party_key.g_u_i, party_key.g_k) {
            Ok(_ok) => _ok,
            Err(_) => throw!(
                name = DKGChallengeGenFailed,
                ctx = &(("Failed to generate DKG challenge").to_owned() + exception_location)
            ),
        };
    let sigma = &party_key.k + &party_key.u_i * challenge;

    let dkg_commitment = KeyGenDKGProposedCommitment {
        index: party_num_int,
        shares_commitment: shares_com,
        zkp: KeyGenZKP {
            g_k: party_key.g_k,
            sigma,
        },
    };

    // #region round 1: send public commitment to coeffs and a proof of knowledge to u_i
    messenger.send_broadcast(party_num_int, round, &obj_to_json(&dkg_commitment)?)?;
    let round1_ans_vec = messenger.recv_broadcasts(party_num_int, parties, round);
    let mut dkg_com_vec: Vec<KeyGenDKGProposedCommitment> = round1_ans_vec
        .iter()
        .map(|m| json_to_obj(m))
        .collect::<Result<Vec<KeyGenDKGProposedCommitment>, _>>()?;
    dkg_com_vec.insert(party_num_int as usize - 1, dkg_commitment);
    println!("Finished keygen round {round}");
    round += 1;
    // #endregion

    let (invalid_peer_ids, valid_com_vec): (Vec<u16>, Vec<KeyGenDKGCommitment>) =
        match KeyInitial::keygen_receive_commitments_and_validate_peers(dkg_com_vec, &context) {
            Ok(_ok) => _ok,
            Err(_) => throw!(
                name = DKGChallengeGenFailed,
                ctx = &(("Failed to generate DKG challenge").to_owned() + exception_location)
            ),
        };
    if invalid_peer_ids.len() > 0 {
        throw!(
            name = InvalidKeyGenZKP,
            ctx =
                &(format!("Invalid zkp from parties {:?}", invalid_peer_ids) + exception_location)
        );
    }

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

    // #region round 2: send secret shares via aes-p2p
    let mut j = 0;
    for (k, i) in (1..=parties).enumerate() {
        if i != party_num_int {
            // prepare encrypted share for party i
            let key_i = &enc_keys[j].compress().to_bytes();
            let plaintext = shares[k].get_value().to_bytes();
            let aead_pack_i = aes::aes_encrypt(key_i, &plaintext)?;
            messenger.send_p2p(party_num_int, i, round, &obj_to_json(&aead_pack_i)?)?;
            j += 1;
        }
    }
    let round2_ans_vec = messenger.gather_p2p(party_num_int, parties, round);
    println!("Finished keygen round {round}");
    // #endregion

    let mut j = 0;
    let mut party_shares: Vec<Share> = Vec::new();
    for i in 1..=parties {
        if i == party_num_int {
            party_shares.push(shares[(i - 1) as usize].clone());
        } else {
            let aead_pack: aes::AEAD = json_to_obj(&round2_ans_vec[j])?;
            let key_i = &enc_keys[j].compress().to_bytes();
            let out = aes::aes_decrypt(key_i, &aead_pack)?;
            let mut out_arr = [0u8; 32];
            out_arr.copy_from_slice(&out);
            let out_fe = Share::new_from(i, party_num_int, Scalar::from_bytes_mod_order(out_arr));
            party_shares.push(out_fe);
            j += 1;
        }
    }

    let signing_key: KeyPair = match KeyInitial::keygen_verify_share_construct_keypair(
        party_shares,
        valid_com_vec.clone(),
        party_num_int,
    ) {
        Ok(_ok) => _ok,
        Err(_) => throw!(
            name = InvalidCommitment,
            ctx = &(("Invalid commitment to key share").to_owned() + exception_location)
        ),
    };

    let keystore = KeyStore {
        party_key,
        signing_key,
        party_num_int,
        valid_com_vec,
        y_sum,
    };
    println!("Finished keygen");
    Ok(keystore)
}
