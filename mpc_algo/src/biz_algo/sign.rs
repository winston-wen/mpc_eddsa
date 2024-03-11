use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::{constants, scalar::Scalar};
use libexception::*;
use mpc_spec::*;
use rand::rngs::OsRng;
use std::collections::{HashMap, HashSet};

use super::{hd::*, KeyStore};
use crate::frost::{
    eval_xi_com, sign_aggregate_responses, sign_and_respond, sign_preprocess, verify_signature,
    verify_solana, Signature, SigningCommitmentPair, SigningNoncePair,
};

pub async fn algo_sign(
    messenger: &impl Messenger,
    signers: &HashSet<ShardId>,
    drv_path: &str,
    msg_hash: &[u8],
    shard: &KeyStore,
) -> Outcome<Signature> {
    assert_throw!(
        msg_hash.len() <= 64,
        "MessageNotHashed",
        "msg_hash is too long to be pre-hashed!"
    );

    let my_id = shard.id;
    let pivot_id = signers.iter().min().ifnone_()?;
    let bcast_id = ShardId::bcast_id();
    let main_pk = shard.pk();
    let chain_code = eval_chain_code(&main_pk);
    let mut rng = OsRng;
    let mut x_i = shard.x_i.clone();
    let mut poly_com_dict = shard.vss_com_dict.clone();

    // #region Derive child keys
    let (tweak_sk, child_pk) = match drv_path.is_empty() {
        true => (Scalar::zero(), main_pk),
        false => non_hardened_derive(drv_path, &main_pk, &chain_code).catch_()?,
    };
    x_i += tweak_sk;
    poly_com_dict.get_mut(pivot_id).ifnone_()?[0] +=
        &constants::ED25519_BASEPOINT_TABLE * &tweak_sk;
    println!("Finished non-hardened derivation");
    // #endregion

    // #region round 2: broadcast signing commitment pairs
    let _obj: _ = sign_preprocess(1, &mut rng).catch_()?;
    let com_pair: Vec<SigningCommitmentPair> = _obj.0;
    let mut nonce_pair: Vec<SigningNoncePair> = _obj.1;
    messenger
        .send("com_pair", my_id, bcast_id, &com_pair[0])
        .await
        .catch_()?;
    let com_pair_dict: HashMap<ShardId, SigningCommitmentPair> = messenger
        .gather("com_pair", signers, bcast_id)
        .await
        .catch_()?;
    // #endregion

    // #region round 3: broadcast signing response
    let response_i: Scalar = sign_and_respond(
        my_id,
        &x_i,
        &com_pair_dict,
        &mut nonce_pair,
        &child_pk,
        msg_hash,
    )
    .catch_()?;
    messenger
        .send("response", my_id, bcast_id, &response_i)
        .await
        .catch_()?;
    let resp_dict: HashMap<ShardId, Scalar> = messenger
        .gather("response", signers, bcast_id)
        .await
        .catch_()?;
    println!("Finished sign_and_respond");
    // #endregion

    // #region: combine signature shares and verify
    let mut signer_pubkeys: HashMap<ShardId, EdwardsPoint> = HashMap::with_capacity(signers.len());
    for id in signers.iter() {
        let ith_pk = eval_xi_com(*id, &poly_com_dict);
        signer_pubkeys.insert(*id, ith_pk);
    }
    let group_sig: Signature = sign_aggregate_responses(
        msg_hash,
        &child_pk,
        &com_pair_dict,
        &resp_dict,
        &signer_pubkeys,
    )
    .catch("", "Failed to aggregate signature shares")?;

    verify_signature(&group_sig, &child_pk)
        .catch("InvalidSignature", "Most probably lack of signers")?;
    verify_solana(&group_sig, &child_pk).catch("", "Failed at verify_solana()")?;
    println!("Finished aggregating signature shares");
    // #endregion

    Ok(group_sig)
}
