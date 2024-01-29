pub async fn algo_sign(
    signers: &HashSet<u16>,
    drv_path: &str,
    msg_hash: &[u8],
    keystore: &KeyStore,
) -> Outcome<Signature> {
    assert_throw!(
        msg_hash.len() <= 64,
        "ToSignInvalidMessage",
        "msg_hash is too long to be pre-hashed!"
    );
    assert_throw!(signers.contains(&keystore.member_id));
    // let drv_path = "";
    let mut topic: &str;

    let mut signing_key = keystore.signing_key.clone();
    let mut valid_com_dict = keystore.valid_com_dict.clone();
    let my_id = keystore.member_id;
    let mut rng = OsRng;

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
    signing_key.g_x_i += &constants::ED25519_BASEPOINT_TABLE * &tweak_sk;
    let first_signer = signers.iter().min().ifnone_()?;
    valid_com_dict.get_mut(first_signer).ifnone_()?[0] +=
        &constants::ED25519_BASEPOINT_TABLE * &tweak_sk;
    println!("Finished non-hardened derivation");
    // #endregion

    // #region round 2: broadcast signing commitment pairs
    let _obj: _ = KeyPair::sign_preprocess(1, &mut rng).catch_()?;
    let signing_com_pair_i: Vec<SigningCommitmentPair> = _obj.0;
    let mut signing_nonce_pair_i: Vec<SigningNoncePair> = _obj.1;

    topic = "signing_com_pair_i";
    scatter(my_id, signers, topic, &signing_com_pair_i[0])
        .await
        .catch_()?;
    let com_pair_dict: HashMap<u16, SigningCommitmentPair> =
        gather(signers, my_id, topic).await.catch_()?;
    // #endregion

    // #region round 3: broadcast signing response
    let response_i: SigningResponse = signing_key
        .sign_and_respond(&com_pair_dict, &mut signing_nonce_pair_i, msg_hash)
        .catch_()?;

    topic = "response_i";
    scatter(my_id, signers, topic, &response_i).await.catch_()?;
    let resp_dict: HashMap<u16, SigningResponse> = gather(signers, my_id, topic).await.catch_()?;
    println!("Finished sign round {topic}");
    // #endregion

    // #region: combine signature shares and verify
    let mut signer_pubkeys: HashMap<u16, EdwardsPoint> = HashMap::with_capacity(signers.len());
    for id in signers.iter() {
        let ith_pk = get_ith_pubkey(*id, &valid_com_dict);
        signer_pubkeys.insert(*id, ith_pk);
    }
    let group_sig: Signature =
        KeyPair::sign_aggregate_responses(msg_hash, &com_pair_dict, &resp_dict, &signer_pubkeys)
            .catch("", "Failed to aggregate signature shares")?;

    validate(&group_sig, &signing_key.group_public)
        .catch("InvalidSignature", "Most probably lack of signers")?;
    // verify_solana(&group_sig, &child_pk).catch("", "Failed at verify_solana()")?;
    println!("Finished aggregating signature shares");
    // #endregion

    Ok(group_sig)
}

pub fn verify_solana(sig: &Signature, pk: &EdwardsPoint) -> Outcome<()> {
    let msg = &sig.hash;
    let pk = {
        let pk_bytes = pk.compress().to_bytes();
        let pk = ed25519_dalek::PublicKey::from_bytes(&pk_bytes).catch_()?;
        pk
    };
    let sig = {
        use ed25519_dalek::Signature as LibSignature;
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&sig.r.compress().to_bytes());
        sig_bytes[32..].copy_from_slice(&sig.s.to_bytes());
        let sig = LibSignature::from_bytes(&sig_bytes).catch_()?;
        sig
    };

    pk.verify_strict(msg, &sig).catch_()?;
    Ok(())
}

use bip32::ChainCode;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::{constants, scalar::Scalar};
use ed25519_dalek::PublicKey;
use mpc_sesman::{gather, scatter};
use rand::rngs::OsRng;
use sha2::{Digest, Sha512};
use std::collections::{HashMap, HashSet};

use super::{hd::non_hardened_derive, keygen::KeyStore};
use crate::party_i::{
    get_ith_pubkey, validate, KeyPair, Signature, SigningCommitmentPair, SigningNoncePair,
    SigningResponse,
};
use crate::prelude::*;
