pub async fn algo_sign(
    my_signer_id: u16, // ID within 1..=n_signers. Used as messenger's ID.
    n_signers: u16,
    drv_path: &str,
    msg_hash: &[u8],
    keystore: &KeyStore,
) -> Outcome<Signature> {
    assert_throw!(
        msg_hash.len() <= 64,
        "ToSignInvalidMessage",
        "msg_hash is too long to be pre-hashed!"
    );
    assert_throw!((1..=n_signers).contains(&my_signer_id));

    let mut signing_key = keystore.signing_key.clone();
    let mut valid_com_vec = keystore.valid_com_vec.clone();
    let _n_keygen_members = keystore.valid_com_vec.len() as u16;
    let my_keygen_id = keystore.member_id;
    let mut topic: &str;
    let mut rng = OsRng;

    topic = "my_keygen_id";
    send_bcast(my_signer_id, topic, &my_keygen_id)
        .await
        .catch_()?;
    let mut keygen_id_vec: Vec<u16> = recv_bcast_wo_src(my_signer_id, n_signers, topic)
        .await
        .catch_()?;
    assert_throw!(
        false == keygen_id_vec.contains(&my_keygen_id),
        "detected other signers using my keygen id"
    );
    keygen_id_vec.insert(my_signer_id as usize - 1, my_keygen_id);
    println!("Finished exchanging keygen_id");

    // #region Derive child keys
    let pk_bytes_short: Vec<u8> = signing_key.group_public.compress().to_bytes().to_vec();
    let chain_code: ChainCode = Sha512::digest(&pk_bytes_short)
        .get(..32)
        .ifnone_()?
        .try_into()
        .unwrap();
    let (tweak_sk, child_pk) = match drv_path.is_empty() {
        true => (Scalar::zero(), signing_key.group_public),
        false => non_hardened_derive(drv_path, &signing_key.group_public, &chain_code).catch_()?,
    };
    signing_key.group_public = child_pk;
    signing_key.x_i += &tweak_sk;
    signing_key.g_x_i += &constants::RISTRETTO_BASEPOINT_TABLE * &tweak_sk;
    valid_com_vec[keygen_id_vec[0] as usize - 1]
        .shares_commitment
        .commitment[0] += &constants::RISTRETTO_BASEPOINT_TABLE * &tweak_sk;
    println!("Finished non-hardened derivation");
    // #endregion

    // #region round 2: broadcast signing commitment pairs
    let _obj: _ = KeyPair::sign_preprocess(1, my_keygen_id, &mut rng).catch_()?;
    let signing_com_pair_i: Vec<SigningCommitmentPair> = _obj.0;
    let mut signing_nonce_pair_i: Vec<SigningNoncePair> = _obj.1;

    topic = "signing_com_pair_i";
    send_bcast(my_signer_id, topic, &signing_com_pair_i[0])
        .await
        .catch_()?;
    let signing_com_pair_vec: Vec<SigningCommitmentPair> =
        recv_bcast(n_signers, topic).await.catch_()?;
    // #endregion

    // #region round 3: broadcast signing response
    let response_i: SigningResponse = signing_key
        .sign_and_respond(&signing_com_pair_vec, &mut signing_nonce_pair_i, msg_hash)
        .catch_()?;

    topic = "response_i";
    send_bcast(my_signer_id, topic, &response_i)
        .await
        .catch_()?;
    let response_vec: Vec<SigningResponse> = recv_bcast(n_signers, topic).await.catch_()?;
    println!("Finished sign round {topic}");
    // #endregion

    // #region: combine signature shares and verify
    let mut signer_pubkeys: HashMap<u16, RistrettoPoint> =
        HashMap::with_capacity(signing_com_pair_vec.len());
    for counter in 0..signing_com_pair_vec.len() {
        let ith_pubkey = get_ith_pubkey(keygen_id_vec[counter], &valid_com_vec);
        let _ = signer_pubkeys.insert(keygen_id_vec[counter], ith_pubkey);
    }
    let group_sig: Signature = KeyPair::sign_aggregate_responses(
        msg_hash,
        &signing_com_pair_vec,
        &response_vec,
        &signer_pubkeys,
    )
    .catch("", "Failed to aggregate signature shares")?;

    validate(&group_sig, &signing_key.group_public)
        .catch("InvalidSignature", "Most probably lack of signers")?;
    // verify_solana(&group_sig, &child_pk).catch("", "Failed at verify_solana()")?;
    println!("Finished aggregating signature shares");
    // #endregion

    Ok(group_sig)
}

pub fn verify_solana(sig: &Signature, pk: &RistrettoPoint) -> Outcome<()> {
    let msg = &sig.hash;
    let pk = {
        let pk_bytes = pk.to_bytes();
        let pk = ed25519_dalek::PublicKey::from_bytes(&pk_bytes).catch_()?;
        pk
    };
    let sig = {
        use ed25519_dalek::Signature as LibSignature;
        let r: EdwardsPoint = unsafe { transmute(sig.r) };
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&r.compress().to_bytes());
        sig_bytes[32..].copy_from_slice(&sig.z.to_bytes());
        let sig = LibSignature::from_bytes(&sig_bytes).catch_()?;
        sig
    };

    pk.verify_strict(msg, &sig).catch_()?;
    Ok(())
}

use bip32::{ChainCode, PublicKey};
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::{constants, ristretto::RistrettoPoint, scalar::Scalar};
use mpc_sesman::{recv_bcast, recv_bcast_wo_src, send_bcast};
use rand::rngs::OsRng;
use sha2::{Digest, Sha512};
use std::collections::HashMap;
use std::mem::transmute;

use super::{hd::non_hardened_derive, keygen::KeyStore};
use crate::party_i::{
    get_ith_pubkey, validate, KeyPair, Signature, SigningCommitmentPair, SigningNoncePair,
    SigningResponse,
};
use crate::prelude::*;
