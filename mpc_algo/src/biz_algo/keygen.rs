use std::collections::{HashMap, HashSet};

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use libexception::*;
use mpc_spec::*;
use rand::rngs::OsRng;
use zeroize::Zeroize;

use super::aes::*;
use crate::frost::{
    generate_dkg_challenge, generate_vss_share, keygen_validate_peers, merge_vss_share,
    KeyGenDKGProposedCommitment, KeyGenZKP, PartyKey,
};

pub type KeyStore = Shard<Scalar, EdwardsPoint>;

pub async fn algo_keygen(
    messenger: &impl Messenger,
    my_id: ShardId,
    th: u16, // At least `th` members during sign
    members: &HashSet<ShardId>,
    context: &str, // Other parties challenge against this ctx
) -> Outcome<KeyStore> {
    assert_throw!(1 <= th && usize::from(th) <= members.len());
    assert_throw!(members.contains(&my_id));
    let mut other_members = members.clone();
    other_members.remove(&my_id);

    // #region generate commitment and zkp for broadcasting
    let mut rng = OsRng;
    let party_key = PartyKey::new(&mut rng);
    if false {
        use bip32::{Language, Mnemonic};
        let mnemonic = Mnemonic::from_entropy(party_key.u_i.to_bytes(), Language::English);
        let phrase = mnemonic.phrase().to_string();
        drop(phrase);
    }
    let _obj: _ = generate_vss_share(&party_key.u_i, my_id, members, th, &mut rng).catch_()?;
    let shares_com: Vec<EdwardsPoint> = _obj.0;
    let mut shares: HashMap<ShardId, Scalar> = _obj.1;

    let challenge = generate_dkg_challenge(
        my_id,
        context,            // known to all participants
        &party_key.g_u_i(), // public key of shard
        &party_key.g_k(),   // commitment of shard
    )
    .catch_()?;
    let sigma = &party_key.k + &party_key.u_i * challenge;

    let dkg_commitment = KeyGenDKGProposedCommitment {
        shares_commitment: shares_com,
        zkp: KeyGenZKP {
            g_k: party_key.g_k(),
            sigma,
        },
    };
    println!("Generated commitments and zkp");
    // #endregion

    // #region round 1: send public commitment to coeffs and a proof of knowledge to u_i
    messenger
        .scatter("dkg_com", my_id, members, &dkg_commitment)
        .await
        .catch_()?;
    let mut proposed_com_dict: HashMap<ShardId, KeyGenDKGProposedCommitment> =
        messenger.gather("dkg_com", members, my_id).await.catch_()?;
    println!("Exchanged commitments");
    // #endregion

    // #region verify commitment and zkp from round 1 and construct aes keys
    let vss_com_dict: HashMap<ShardId, Vec<EdwardsPoint>> =
        keygen_validate_peers(&proposed_com_dict, &context).catch_()?;
    for com in proposed_com_dict.values_mut() {
        com.zeroize();
    }

    let mut aes_key_dict: HashMap<ShardId, [u8; 32]> = HashMap::new();
    for id in other_members.iter() {
        let com = vss_com_dict.get(id).ifnone_()?;
        let aes_key = com[0] * &party_key.u_i;
        let aes_key = aes_key.compress().to_bytes();
        aes_key_dict.insert(*id, aes_key);
    }
    // #endregion

    // #region round 2: send secret shares via aes-p2p
    for id in other_members.iter() {
        let aes_key = aes_key_dict.get(id).ifnone_()?;
        let plaintext = shares.get(id).ifnone_()?.to_bytes();
        let aead_pack_i = aes_encrypt(aes_key, &plaintext).catch_()?;
        messenger
            .send("aead_share", my_id, *id, &aead_pack_i)
            .await
            .catch_()?;
    }
    let aead_dict: HashMap<ShardId, AEAD> = messenger
        .gather("aead_share", &other_members, my_id)
        .await
        .catch_()?;
    println!("Finished keygen round aead_share");
    // #endregion

    // #region retrieve private signing key share
    let mut party_shares: HashMap<ShardId, Scalar> = HashMap::new();
    party_shares.insert(my_id, shares.get(&my_id).ifnone_()?.clone());
    for x in shares.values_mut() {
        x.zeroize();
    }
    for id in other_members.iter() {
        let aes_key = aes_key_dict.get(id).ifnone_()?;
        let aead_pack = aead_dict.get(id).ifnone_()?;
        let out = aes_decrypt(aes_key, &aead_pack).catch_()?;
        assert_throw!(out.len() == 32);
        let mut out_arr = [0u8; 32];
        out_arr.copy_from_slice(&out);
        let out_fe = Scalar::from_bytes_mod_order(out_arr);
        party_shares.insert(*id, out_fe);
    }

    let signing_key: Scalar = merge_vss_share(&party_shares, &vss_com_dict, my_id).catch_()?;
    for x in party_shares.values_mut() {
        x.zeroize();
    }
    // #endregion

    let keystore = KeyStore {
        u_i: party_key.u_i,
        x_i: signing_key,
        vss_com_dict,
        id: my_id,
        th,
        aux: None,
    };
    println!("Finished keygen");

    Ok(keystore)
}
