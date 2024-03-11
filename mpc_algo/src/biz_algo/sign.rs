use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::{constants, scalar::Scalar};
use libexception::*;
use mpc_spec::*;
use rand::rngs::OsRng;
use std::collections::{HashMap, HashSet};

use super::{hd::*, KeyStore};
use crate::frost::{
    agg_nonce_com, eval_xi_com, gen_rho_i, generate_challenge, is_valid_response, lagrange_lambda,
    sign_and_respond, sign_preprocess, verify_signature, verify_solana, Signature,
    SigningCommitmentPair, SigningNoncePair,
};

pub async fn algo_sign(
    messenger: &impl Messenger,
    ses_arch: &HashMap<u16, HashSet<MpcAddr>>,
    drv_path: &str,
    msg_hash: &[u8],
    keystore: &KeyStore,
) -> Outcome<Signature> {
    let bcast_id = MpcAddr::bcast_id();
    let mut whoami_asc: Vec<MpcAddr> = keystore.ids.iter().cloned().collect();
    whoami_asc.sort();
    let mut rng = OsRng;
    let mut group_ids_asc: Vec<u16> = ses_arch.keys().cloned().collect();
    group_ids_asc.sort();

    // Derive child pk
    let main_pk = keystore.pk().catch_()?;
    let chain_code = eval_chain_code(&main_pk);
    let (tweak_sk, child_pk) = match drv_path.is_empty() {
        true => (Scalar::zero(), main_pk),
        false => non_hardened_derive(drv_path, &main_pk, &chain_code).catch_()?,
    };

    // apply bip32 tweak
    let keystore = {
        let mut ks = keystore.clone();
        let xi_pergroup = &mut ks.xi_pergroup;
        let pivot_gid = xi_pergroup.keys().min().ifnone_()?.clone();
        let x_i = xi_pergroup.get_mut(&pivot_gid).ifnone_()?;
        *x_i += tweak_sk;

        let vss_com_grid = &mut ks.vss_com_grid;
        let pivot_id = vss_com_grid
            .get(&pivot_gid)
            .ifnone_()?
            .keys()
            .min()
            .ifnone_()?
            .clone();
        let vss_com = vss_com_grid
            .get_mut(&pivot_gid)
            .ifnone_()?
            .get_mut(&pivot_id)
            .ifnone_()?;
        vss_com[0] += &constants::ED25519_BASEPOINT_TABLE * &tweak_sk;

        ks
    };

    // Compute dict of $x_j * G$ without knowing $x_j$
    let mut xjg_dict: HashMap<MpcAddr, EdwardsPoint> = HashMap::new();
    for gid in group_ids_asc.iter() {
        let vss_com_dict = keystore.vss_com_grid.get(gid).ifnone(
            "InvalidGroup",
            format!(
                "Group {} not found in vss_com_grid {:?}",
                gid,
                keystore.vss_com_grid.keys().collect::<Vec<&u16>>()
            ),
        )?;
        let group_members = ses_arch.get(gid).ifnone_()?;
        for j in group_members.iter() {
            let xjg /* $x_j * G$ */ = eval_xi_com(*j, vss_com_dict);
            xjg_dict.insert(*j, xjg);
        }
    }

    // Generate nonce pair $(d, e)$, and broadcast $(dG, eG)$.
    let mut my_nonce_dict: HashMap<MpcAddr, SigningNoncePair> = HashMap::new();
    for my_id in whoami_asc.iter() {
        let _obj: _ = sign_preprocess(&mut rng).catch_()?;
        let nonce_com: SigningCommitmentPair = _obj.0;
        let nonce_pair: SigningNoncePair = _obj.1;
        my_nonce_dict.insert(*my_id, nonce_pair.clone());
        messenger
            .send("nonce_com", *my_id, bcast_id, &nonce_com)
            .await
            .catch_()?;
        println!("{} broadcast nonce_com", my_id);
    }

    // Gather $(dG, eG)$.
    let mut nonce_com_dict: HashMap<MpcAddr, SigningCommitmentPair> = HashMap::new();
    for gid in group_ids_asc.iter() {
        let group_members = ses_arch.get(gid).ifnone_()?;
        let obj = messenger
            .gather("nonce_com", group_members, bcast_id)
            .await
            .catch_()?;
        nonce_com_dict.extend(obj);
    }

    // Compute rho dict
    let mut rho_dict: HashMap<MpcAddr, Scalar> = HashMap::new();
    for (j, _) in nonce_com_dict.iter() {
        let rho_i = gen_rho_i(*j, msg_hash, &nonce_com_dict);
        rho_dict.insert(*j, rho_i);
    }

    // Aggregate sig.r
    let sig_r = agg_nonce_com(&nonce_com_dict, &rho_dict).catch_()?;

    // Generate and broadcast sign response
    for my_id in whoami_asc.iter() {
        let my_nonce = my_nonce_dict.get(my_id).ifnone_()?;
        let my_gid = my_id.group_id();
        let x_i = keystore.xi_pergroup.get(&my_gid).ifnone_()?;
        let group_members = ses_arch.get(&my_gid).ifnone_()?;
        let sign_resp = sign_and_respond(
            *my_id,
            x_i,
            &rho_dict,
            &sig_r,
            my_nonce,
            group_members,
            &child_pk,
            msg_hash,
        )
        .catch_()?;
        messenger
            .send("sign_resp", *my_id, bcast_id, &sign_resp)
            .await
            .catch_()?;
    }
    drop(my_nonce_dict);

    // Gather sign response
    let mut resp_dict: HashMap<MpcAddr, Scalar> = HashMap::new();
    for gid in group_ids_asc.iter() {
        let group_members = ses_arch.get(gid).ifnone_()?;
        let obj = messenger
            .gather("sign_resp", group_members, bcast_id)
            .await
            .catch_()?;
        resp_dict.extend(obj);
    }

    // Compute challenge
    let challenge = generate_challenge(msg_hash, &sig_r, &child_pk);

    // Validate each participant's response
    for (j, resp) in resp_dict.iter() {
        let rho_j = rho_dict.get(j).ifnone_()?;
        let signers = ses_arch.get(&j.group_id()).ifnone_()?;
        let lam_i = lagrange_lambda(*j, signers).catch_()?;
        let nonce_com = nonce_com_dict.get(j).ifnone_()?;
        let com = nonce_com.g_d + (nonce_com.g_e * rho_j);
        let xjg = xjg_dict.get(j).ifnone_()?; // $x_j * G$

        let resp_is_valid = is_valid_response(resp, xjg, &lam_i, &com, &challenge);
        assert_throw!(resp_is_valid, "Invalid signer response");
    }

    // Aggregate sig_s
    let mut sig_s = Scalar::zero();
    for resp in resp_dict.values() {
        sig_s += resp;
    }
    let sig = Signature {
        r: sig_r,
        s: sig_s,
        hash: msg_hash.to_vec(),
    };

    verify_signature(&sig, &child_pk).catch("InvalidSignature", "Most probably lack of signers")?;
    verify_solana(&sig, &child_pk).catch("", "Failed at verify_solana()")?;
    println!("Finished aggregating signature shares");
    // #endregion

    Ok(sig)
}
