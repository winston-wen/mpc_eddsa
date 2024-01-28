#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct KeyStore {
    pub party_key: KeyInitial,
    pub signing_key: KeyPair,
    pub valid_com_dict: HashMap<u16, KeyGenDKGCommitment>,

    pub member_id: u16,
    pub th: u16,
}

pub async fn algo_keygen(
    my_id: u16,
    th: u16, // At least `th + 1` members during sign
    members: &HashSet<u16>,
    context: &str, // Other parties challenge against this ctx
) -> Outcome<KeyStore> {
    assert_throw!(usize::from(th) <= members.len());
    assert_throw!(members.contains(&my_id));
    let mut other_members = members.clone();
    other_members.remove(&my_id);
    let mut topic: &str;

    // #region generate commitment and zkp for broadcasting
    let mut rng = OsRng;
    let party_key = KeyInitial::new(my_id, &mut rng);
    if false {
        use bip32::{Language, Mnemonic};
        let mnemonic = Mnemonic::from_entropy(party_key.u_i.to_bytes(), Language::English);
        let phrase = mnemonic.phrase().to_string();
        drop(phrase);
    }
    let _obj: _ = party_key.generate_shares(members, th, &mut rng).catch_()?;
    let shares_com: SharesCommitment = _obj.0;
    let mut shares: HashMap<u16, Share> = _obj.1;

    let challenge = generate_dkg_challenge(
        my_id,
        context,          // known to all participants
        &party_key.g_u_i, // public key of shard
        &party_key.g_k,   // commitment of shard
    )
    .catch_()?;
    let sigma = &party_key.k + &party_key.u_i * challenge;

    let dkg_commitment = KeyGenDKGProposedCommitment {
        shares_commitment: shares_com,
        zkp: KeyGenZKP {
            g_k: party_key.g_k,
            sigma,
        },
    };
    println!("Generated commitments and zkp");
    // #endregion

    // #region round 1: send public commitment to coeffs and a proof of knowledge to u_i
    topic = "dkg_commitment";
    scatter(my_id, members, topic, &dkg_commitment)
        .await
        .catch_()?;
    let mut proposed_com_dict: HashMap<u16, KeyGenDKGProposedCommitment> =
        gather(members, my_id, topic).await.catch_()?;
    println!("Exchanged commitments");
    // #endregion

    // #region verify commitment and zkp from round 1 and construct aes keys
    let valid_com_dict: HashMap<u16, KeyGenDKGCommitment> =
        KeyInitial::keygen_validate_peers(&proposed_com_dict, &context).catch_()?;
    for com in proposed_com_dict.values_mut() {
        com.zeroize();
    }

    let mut aes_key_dict: HashMap<u16, [u8; 32]> = HashMap::new();
    for id in other_members.iter() {
        let com = valid_com_dict.get(id).ifnone_()?;
        let aes_key = com[0] * &party_key.u_i;
        let aes_key = aes_key.compress().to_bytes();
        aes_key_dict.insert(*id, aes_key);
    }
    // #endregion

    // #region round 2: send secret shares via aes-p2p
    topic = "aead_pack_i";
    for id in other_members.iter() {
        let aes_key = aes_key_dict.get(id).ifnone_()?;
        let plaintext = shares.get(id).ifnone_()?.to_bytes();
        let aead_pack_i = aes_encrypt(aes_key, &plaintext).catch_()?;
        send(my_id, *id, topic, &aead_pack_i).await.catch_()?;
    }
    let aead_dict: HashMap<u16, AEAD> = gather(&other_members, my_id, topic).await.catch_()?;
    println!("Finished keygen round {topic}");
    // #endregion

    // #region retrieve private signing key share
    let mut party_shares: HashMap<u16, Share> = HashMap::new();
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
        let out_fe = Share(Scalar::from_bytes_mod_order(out_arr));
        party_shares.insert(*id, out_fe);
    }

    let signing_key: KeyPair =
        KeyInitial::keygen_verify_share_construct_keypair(&party_shares, &valid_com_dict, my_id)
            .catch_()?;
    for x in party_shares.values_mut() {
        x.zeroize();
    }
    // #endregion

    let keystore = KeyStore {
        party_key,
        signing_key,
        valid_com_dict,

        member_id: my_id,
        th,
    };
    println!("Finished keygen");

    Ok(keystore)
}

use std::collections::{HashMap, HashSet};

use curve25519_dalek::scalar::Scalar;
use mpc_sesman::{gather, scatter, send};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::aes::*;
use crate::party_i::{
    generate_dkg_challenge, KeyGenDKGCommitment, KeyGenDKGProposedCommitment, KeyGenZKP,
    KeyInitial, KeyPair, Share, SharesCommitment,
};
use crate::prelude::*;
