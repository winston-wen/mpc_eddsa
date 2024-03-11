use std::collections::{HashMap, HashSet}; // keys are in ascending order to avoid deadlock.

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

pub type KeyStore = MultiShard<Scalar, EdwardsPoint>;

pub async fn algo_keygen(
    messenger: &impl Messenger,
    key_arch: &HashMap<u16 /*group_id*/, (usize /*th*/, HashSet<MpcAddr>)>,
    whoami: &[MpcAddr], // My shard_ids
    context: &str,      // Other parties challenge against this ctx
) -> Outcome<KeyStore> {
    let mut keystore = KeyStore::default();

    // shard_id should be traversed in ascending order to avoid deadlock.
    for my_id in whoami.iter() {
        // extract useful params
        let my_id = *my_id;
        let gid = my_id.group_id();
        let (th, members) = key_arch.get(&gid).ifnone("NoGroup", gid.to_string())?;
        let gcast_id = MpcAddr::gcast_id(gid);

        // print ids
        print!("Me: {} , Group members: ", my_id);
        for id in members.iter() {
            print!("{} ", id);
        }
        println!();

        // generate party key $u_i$ and ephemeral key $k_i$.
        let mut rng = OsRng;
        let party_key = PartyKey::new(&mut rng);
        if false {
            use bip32::{Language, Mnemonic};
            let mnemonic = Mnemonic::from_entropy(party_key.u_i.to_bytes(), Language::English);
            let phrase = mnemonic.phrase().to_string();
            drop(phrase);
        }

        // generate vss commmitment and vss shares
        let _obj: _ = generate_vss_share(&party_key.u_i, my_id, members, *th, &mut rng).catch_()?;
        let shares_com: Vec<EdwardsPoint> = _obj.0;
        let mut shares: HashMap<MpcAddr, Scalar> = _obj.1;

        // generate challenge
        let challenge = generate_dkg_challenge(
            my_id,
            context,            // known to all participants
            &party_key.g_u_i(), // public key of shard
            &party_key.g_k_i(), // commitment of shard
        )
        .catch_()?;

        // construct dkg commitment
        let dkg_commitment = KeyGenDKGProposedCommitment {
            shares_commitment: shares_com,
            zkp: KeyGenZKP {
                g_k_i: party_key.g_k_i(),
                sigma: &party_key.k_i + &party_key.u_i * challenge,
            },
        };

        messenger
            .send("dkg_com", my_id, gcast_id, &dkg_commitment)
            .await
            .catch_()?;
        let proposed_com_dict: HashMap<MpcAddr, KeyGenDKGProposedCommitment> = messenger
            .gather("dkg_com", members, gcast_id)
            .await
            .catch_()?;

        // verify and collect others' vss_com_dict
        let vss_com_dict: HashMap<MpcAddr, Vec<EdwardsPoint>> =
            keygen_validate_peers(&proposed_com_dict, &context).catch_()?;
        drop(proposed_com_dict);
        for (_, vss_com) in vss_com_dict.iter() {
            assert_throw!(vss_com.len() == *th); // to avoid DKG attack via increasing threshold on the fly.
        }

        // use others' pubkey to construct aes key
        let mut aes_key_dict: HashMap<MpcAddr, [u8; 32]> = HashMap::new();
        for j in members.iter() {
            let com = vss_com_dict.get(j).ifnone_()?;
            let aes_key = com[0] * &party_key.u_i; // aes_key = u_j * g_u_i
            let aes_key = aes_key.compress().to_bytes();
            aes_key_dict.insert(*j, aes_key);
        }

        // scatter vss shares via aes-gcm encrypted channel
        for id in members.iter() {
            let aes_key = aes_key_dict.get(id).ifnone_()?;
            let plaintext = shares.get(id).ifnone_()?.to_bytes();
            let aead_pack_i = aes_encrypt(aes_key, &plaintext).catch_()?;
            messenger
                .send("aead_share", my_id, *id, &aead_pack_i)
                .await
                .catch_()?;
        }
        let aead_dict: HashMap<MpcAddr, AEAD> = messenger
            .gather("aead_share", members, my_id)
            .await
            .catch_()?;

        for x in shares.values_mut() {
            x.zeroize();
        }
        drop(shares);

        // gather vss shares
        let mut party_shares: HashMap<MpcAddr, Scalar> = HashMap::new();
        for j in members.iter() {
            let aes_key = aes_key_dict.get(j).ifnone_()?;
            let aead_pack = aead_dict.get(j).ifnone_()?;
            let out = aes_decrypt(aes_key, &aead_pack).catch_()?;
            assert_throw!(out.len() == 32);
            let mut out_arr = [0u8; 32];
            out_arr.copy_from_slice(&out);
            let out_fe = Scalar::from_bytes_mod_order(out_arr);
            party_shares.insert(*j, out_fe);
        }

        // compute x_i
        let signing_key: Scalar = merge_vss_share(&party_shares, &vss_com_dict, my_id).catch_()?;
        for x in party_shares.values_mut() {
            x.zeroize();
        }

        keystore.ui_pergroup.insert(gid, party_key.u_i);
        keystore.xi_pergroup.insert(gid, signing_key);
        keystore.vss_com_grid.insert(gid, vss_com_dict);
    }

    // Fetch vss_com of members in other groups
    let mut key_arch = key_arch.clone();
    for my_id in whoami.iter() {
        let gid = my_id.group_id();
        key_arch.remove(&gid);
    }
    for (gid, (th, members)) in key_arch.iter() {
        let gcast_id = MpcAddr::gcast_id(*gid);
        let proposed_com_dict: HashMap<MpcAddr, KeyGenDKGProposedCommitment> = messenger
            .gather("dkg_com", members, gcast_id)
            .await
            .catch_()?;

        // verify and collect others' vss_com_dict
        let vss_com_dict: HashMap<MpcAddr, Vec<EdwardsPoint>> =
            keygen_validate_peers(&proposed_com_dict, &context).catch_()?;
        drop(proposed_com_dict);
        for (_, vss_com) in vss_com_dict.iter() {
            assert_throw!(vss_com.len() == *th); // to avoid DKG attack via increasing threshold on the fly.
        }

        keystore.vss_com_grid.insert(*gid, vss_com_dict);
    }

    // Archive my shard_ids
    keystore.ids = whoami.iter().cloned().collect();

    Ok(keystore)
}
