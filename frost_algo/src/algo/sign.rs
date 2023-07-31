#![allow(non_snake_case)]

use bip32::ChainCode;
use curve25519_dalek::{constants, ristretto::RistrettoPoint, scalar::Scalar};
use rand::rngs::OsRng;
use sha2::{Digest, Sha512};
use std::collections::HashMap;

use luban_core::MpcClientMessenger;
use xuanmi_base_support::*;

use super::party_i::{
    get_ith_pubkey, validate, KeyPair, Signature, SigningCommitmentPair, SigningResponse,
};

use super::{data_structure::KeyStore, hd};
use crate::{
    ChildKeyDerivationFailed, InvalidConfigs, InvalidKeystore, InvalidMessage, InvalidSignature,
    SignFailed, SignUpFailed, SignatureAggregateFailed, SigningComGenFailed,
};

pub fn algo_sign(
    server: &str,
    tr_uuid: &str,
    tcn_config: &[u16; 3],
    derive: &str,
    msg_hashed: &[u8],
    keystore: &KeyStore,
) -> Outcome<Signature> {
    if msg_hashed.len() > 64 {
        let mut msg = String::from("The sign algorithm **assumes** its input message be hashed.\n");
        msg += &format!("However, the algorithm received a message with length = {}, indicating the message is probably un-hashed.\n", msg_hashed.len());
        msg += "Did the caller forget to hash the message?";
        throw!(name = InvalidMessage, ctx = &msg);
    }

    let (threshold, parties, share_count) = (tcn_config[0], tcn_config[1], tcn_config[2]);
    let mut signing_key = keystore.signing_key;
    let mut valid_com_vec = keystore.valid_com_vec.clone();
    let party_id = keystore.party_num_int;
    println!(
        "Start sign with threshold={}, parties={}, share_count={}",
        threshold, parties, share_count,
    );
    let cond = threshold + 1 <= parties && parties <= share_count;
    if !cond {
        throw!(
            name = InvalidConfigs,
            ctx = &format!(
                "t/c/n config should satisfy t<c<=n.\n\tHowever, {}/{}/{} was provided",
                threshold, parties, share_count
            )
        );
    }

    // #region signup for signing
    let messenger =
        MpcClientMessenger::signup(server, "sign", tr_uuid, threshold, parties, share_count)
            .catch(
                SignUpFailed,
                &format!(
                    "Cannot sign up for key geneation with server={}, tr_uuid={}.",
                    server, tr_uuid
                ),
            )?;
    let party_num_int = messenger.my_id();
    println!(
        "MPC Server {} designated this party with\n\tparty_id={}, tr_uuid={}",
        server,
        party_num_int,
        messenger.uuid()
    );
    let exception_location = &format!(
        " (at party_id={}, tr_uuid={}).",
        party_num_int,
        messenger.uuid()
    );
    let mut round: u16 = 1;
    let mut rng = OsRng;
    // #endregion

    // #region round 1: collect signer IDs
    messenger.send_broadcast(party_num_int, round, &obj_to_json(&party_id)?)?;
    let round1_ans_vec = messenger.recv_broadcasts(party_num_int, parties, round);
    let mut signers_vec: Vec<u16> = round1_ans_vec
        .iter()
        .map(|text| json_to_obj(text))
        .collect::<Result<Vec<u16>, _>>()?;
    if signers_vec.contains(&party_id) {
        throw!(
            name = InvalidKeystore,
            ctx = &(format!("Duplicated keyshare") + exception_location)
        );
    }
    signers_vec.insert(party_num_int as usize - 1, party_id);
    println!("Finished sign round {round}");
    round += 1;
    // #endregion

    // #region Derive child keys
    let y_sum_bytes_small = signing_key.group_public.compress().to_bytes().to_vec();
    let chain_code: ChainCode = match Sha512::digest(&y_sum_bytes_small).get(..32) {
        Some(arr) => arr.try_into().unwrap(),
        None => {
            throw!(
                name = ChildKeyDerivationFailed,
                ctx = &(format!(
                    "Bad Sha512 digest for ChainCode, input_bytes_hex={}",
                    hex::encode(&y_sum_bytes_small)
                ) + exception_location)
            )
        }
    };
    let (tweak_sk, child_pk) = match derive.is_empty() {
        true => (Scalar::zero(), signing_key.group_public),
        false => hd::algo_get_hd_key(derive, &signing_key.group_public, &chain_code).catch(
            ChildKeyDerivationFailed,
            &format!(
                "Failed to {} where server=\"{}\", uuid=\"{}\", share_count=\"{}\", threshold=\"{}\"",
                "get_hd_key", server, tr_uuid, share_count, threshold
            ),
        )?,
    };
    signing_key.group_public = child_pk;
    signing_key.x_i += &tweak_sk;
    signing_key.g_x_i += &constants::RISTRETTO_BASEPOINT_TABLE * &tweak_sk;
    valid_com_vec[signers_vec[0] as usize - 1]
        .shares_commitment
        .commitment[0] += &constants::RISTRETTO_BASEPOINT_TABLE * &tweak_sk;
    // #endregion

    // #region round 2: broadcast signing commitment pairs
    let (signing_com_pair_i, mut signing_nonce_pair_i) =
        match KeyPair::sign_preprocess(1, party_id, &mut rng) {
            Ok(_ok) => _ok,
            Err(_) => throw!(
                name = SigningComGenFailed,
                ctx = &(("Failed to generate signing commitment").to_owned() + exception_location)
            ),
        };

    messenger.send_broadcast(party_num_int, round, &obj_to_json(&signing_com_pair_i[0])?)?;
    let round2_ans_vec = messenger.recv_broadcasts(party_num_int, parties, round);
    let mut signing_com_pair_vec: Vec<SigningCommitmentPair> = round2_ans_vec
        .iter()
        .map(|text| json_to_obj(text))
        .collect::<Result<Vec<SigningCommitmentPair>, _>>()?;
    signing_com_pair_vec.insert(party_num_int as usize - 1, signing_com_pair_i[0].clone());
    println!("Finished sign round {round}");
    round += 1;
    // #endregion

    // #region round 3: broadcast signing response
    let response_i: SigningResponse = match signing_key.sign_and_respond(
        &signing_com_pair_vec,
        &mut signing_nonce_pair_i,
        msg_hashed,
    ) {
        Ok(_ok) => _ok,
        Err(err) => throw!(
            name = SignFailed,
            ctx = &(format!("Failed to sign the message, particularly \"{}\"", err)
                + exception_location)
        ),
    };
    messenger.send_broadcast(party_num_int, round, &obj_to_json(&response_i)?)?;
    let round3_ans_vec = messenger.recv_broadcasts(party_num_int, parties, round);
    let mut response_vec: Vec<SigningResponse> = round3_ans_vec
        .iter()
        .map(|text| json_to_obj(text))
        .collect::<Result<Vec<SigningResponse>, _>>()?;
    response_vec.insert(party_num_int as usize - 1, response_i);
    println!("Finished sign round {round}");
    // #endregion

    // #region: combine signature shares and verify
    let mut signer_pubkeys: HashMap<u16, RistrettoPoint> =
        HashMap::with_capacity(signing_com_pair_vec.len());
    for counter in 0..signing_com_pair_vec.len() {
        let ith_pubkey = get_ith_pubkey(signers_vec[counter], &valid_com_vec);
        let _ = signer_pubkeys.insert(signers_vec[counter], ith_pubkey);
    }
    let group_sig: Signature = match KeyPair::sign_aggregate_responses(
        msg_hashed,
        &signing_com_pair_vec,
        &response_vec,
        &signer_pubkeys,
    ) {
        Ok(_ok) => _ok,
        Err(err) => throw!(
            name = SignatureAggregateFailed,
            ctx = &(format!(
                "Failed to aggregate signature shares, particularly \"{}\"",
                err
            ) + exception_location)
        ),
    };
    if !validate(&group_sig, signing_key.group_public).is_ok() {
        throw!(
            name = InvalidSignature,
            ctx = &(format!("Invalid Schnorr signature") + exception_location)
        );
    }
    // #endregion

    println!("Finished sign");
    Ok(group_sig)
}
