use std::collections::HashMap;

use curve25519_dalek::{constants, edwards::EdwardsPoint, scalar::Scalar, traits::Identity};
use itertools::Itertools;
use libexception::*;
use mpc_spec::ShardId;
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256, Sha512};

use super::{Signature, SigningCommitmentPair, SigningNoncePair};

/// preprocess is performed by each participant; their commitments are published
/// and stored in an external location for later use in signing, while their
/// signing nonces are stored locally.
pub fn sign_preprocess<R: RngCore + CryptoRng>(
    cached_com_count: usize,
    rng: &mut R,
) -> Outcome<(Vec<SigningCommitmentPair>, Vec<SigningNoncePair>)> {
    let mut commitments = Vec::new();
    let mut nonces = Vec::new();

    for _ in 0..cached_com_count {
        let nonce_pair = SigningNoncePair::new(rng).catch_()?;
        let commitment =
            SigningCommitmentPair::new(nonce_pair.d.public, nonce_pair.e.public).catch_()?;
        commitments.push(commitment);
        nonces.push(nonce_pair);
    }

    Ok((commitments, nonces))
}

/// sign is performed by each participant selected for the signing
/// operation; these responses are then aggregated into the final FROST
/// signature by the signature aggregator performing the aggregate function
/// with each response.
pub fn sign_and_respond(
    my_id: ShardId,
    x_i: &Scalar,
    com_dict: &HashMap<ShardId, SigningCommitmentPair>, // B, but how to construct B???
    nonce_vec: &mut Vec<SigningNoncePair>,              // .len() == cached_com_count
    pk: &EdwardsPoint,
    msg: &[u8],
) -> Outcome<Scalar> {
    // no message checking???
    // no D_l and E_l checking???

    let i_nonce: usize;
    let my_nonce: &SigningNoncePair;
    {
        let my_comm = com_dict.get(&my_id).ifnone_()?;
        let mut found: Option<(usize, &SigningNoncePair)> = None;
        for (i, nonce) in nonce_vec.iter().enumerate() {
            if nonce.d.public == my_comm.g_d && nonce.e.public == my_comm.g_e {
                found = Some((i, nonce));
                break;
            }
        }
        let _obj = found.ifnone("", "No matching signing nonce for signer")?;
        i_nonce = _obj.0;
        my_nonce = _obj.1;
    }

    let response: Scalar = {
        let mut bindings: HashMap<ShardId, Scalar> = HashMap::with_capacity(com_dict.len());
        for id in com_dict.keys() {
            let rho_i = gen_rho_i(*id, msg, com_dict); // rho_l = H_1(l, m, B)
            let _ = bindings.insert(*id, rho_i); // (l, rho_l)
        }
        let com_agg = gen_group_commitment(com_dict, &bindings).catch_()?;
        let my_rho_i = bindings.get(&my_id).ifnone_()?;
        let signers: Vec<ShardId> = com_dict.keys().cloned().collect();

        // R = k * G = sum(D_l + E_l * rho_l)
        let lambda_i = lagrange_lambda(my_id, &signers).catch_()?;

        // c= H_2(R, Y, m)
        let c = generate_challenge(msg, &com_agg, pk);

        // z_i = d_i + (e_i * rho_i) + lambda_i * s_i * c
        my_nonce.d.secret + (my_nonce.e.secret * my_rho_i) + (lambda_i * x_i * c)
    };

    // Now that this nonce has been used, delete it
    nonce_vec.remove(i_nonce);

    Ok(response /* z_i */)
}

/// aggregate collects all responses from participants. It first performs a
/// validity check for each participant's response, and will return an error in the
/// case the response is invalid. If all responses are valid, it aggregates these
/// into a single signature that is published. This function is executed
/// by the entity performing the signature aggregator role.
pub fn sign_aggregate_responses(
    msg: &[u8],
    pubkey: &EdwardsPoint,
    com_dict: &HashMap<ShardId, SigningCommitmentPair>,
    resp_dict: &HashMap<ShardId, Scalar>,
    pubkey_dict: &HashMap<ShardId, EdwardsPoint>,
) -> Outcome<Signature> {
    let mut bindings: HashMap<ShardId, Scalar> = HashMap::new(); // rho-s
    for id in com_dict.keys() {
        let rho_i = gen_rho_i(*id, msg, com_dict);
        bindings.insert(*id, rho_i);
    }
    let group_commitment: EdwardsPoint = gen_group_commitment(&com_dict, &bindings).catch_()?;
    let challenge: Scalar = generate_challenge(msg, &group_commitment, pubkey);
    let signers: Vec<ShardId> = com_dict.keys().cloned().collect();

    // Validate each participant's response
    for (id, resp) in resp_dict {
        let ρi = bindings.get(id).ifnone_()?;
        let λi = lagrange_lambda(*id, &signers).catch_()?;

        let com = com_dict.get(id).ifnone_()?;
        let com = com.g_d + (com.g_e * ρi);
        let pk = pubkey_dict.get(id).ifnone_()?;

        let resp_is_valid = is_valid_response(resp, pk, &λi, &com, &challenge);
        assert_throw!(resp_is_valid, "Invalid signer response");
    }

    let mut group_resp: Scalar = Scalar::zero();
    for resp in resp_dict.values() {
        group_resp += resp;
    }

    Ok(Signature {
        r: group_commitment,
        s: group_resp,
        hash: msg.to_vec(),
    })
}

/// generates the lagrange coefficient for the ith participant. This allows
/// for performing Lagrange interpolation, which underpins threshold secret
/// sharing schemes based on Shamir secret sharing.
pub fn lagrange_lambda(id: ShardId, signers: &[ShardId]) -> Outcome<Scalar> {
    let mut num = Scalar::one();
    let mut den = Scalar::one();
    for j in signers {
        if *j == id {
            continue;
        }
        num *= Scalar::from(j.member_id());
        den *= Scalar::from(j.member_id()) - Scalar::from(id.member_id());
    }
    assert_throw!(den != Scalar::zero(), "Duplicate shares provided");

    Ok(num * den.invert())
}

// to be reviewed again? For H(m, R) instead of H(R, Y, m)???
/// generates the challenge value H(m, R) used for both signing and verification.
/// ed25519_ph hashes the message first, and derives the challenge as H(H(m), R),
/// this would be a better optimization but incompatibility with other
/// implementations may be undesirable.
pub fn generate_challenge(msg: &[u8], com: &EdwardsPoint, pk: &EdwardsPoint) -> Scalar {
    let mut ha = Sha512::new();
    ha.update(com.compress().to_bytes());
    ha.update(pk.compress().to_bytes());
    ha.update(msg);
    Scalar::from_hash(ha)
}

/// validate performs a plain Schnorr validation operation; this is identical
/// to performing validation of a Schnorr signature that has been signed by a
/// single party.
pub fn verify_signature(sig: &Signature, pubkey: &EdwardsPoint) -> Outcome<()> {
    let G = &constants::ED25519_BASEPOINT_TABLE;
    let challenge = generate_challenge(&sig.hash, &sig.r, &pubkey);
    let r = G * &sig.s - pubkey * challenge;
    assert_throw!(r == sig.r, "Signature is invalid");
    Ok(())
}

fn gen_rho_i(i: ShardId, msg: &[u8], com_dict: &HashMap<ShardId, SigningCommitmentPair>) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update("I".as_bytes());
    hasher.update(i.to_be_bytes());
    hasher.update(msg);

    let com_iter_id_asc: _ = com_dict.iter().sorted_by_key(|(id, _)| *id);
    for (j, com) in com_iter_id_asc {
        hasher.update(j.to_be_bytes());
        hasher.update(com.g_d.compress().as_bytes());
        hasher.update(com.g_e.compress().as_bytes());
    }
    let result = hasher.finalize();

    let rho_i = result
        .as_slice()
        .try_into()
        .expect("Error generating commitment!");
    Scalar::from_bytes_mod_order(rho_i)
}

fn gen_group_commitment(
    com_dict: &HashMap<ShardId, SigningCommitmentPair>,
    bindings: &HashMap<ShardId, Scalar>,
) -> Outcome<EdwardsPoint> {
    let mut group_com = EdwardsPoint::identity();
    for (id, com) in com_dict {
        let rho_i = bindings.get(id).ifnone_()?;
        group_com += com.g_d + (com.g_e * rho_i)
    }

    Ok(group_com)
}

pub fn is_valid_response(
    resp: &Scalar,
    pk: &EdwardsPoint,
    λi: &Scalar,
    commitment: &EdwardsPoint,
    challenge: &Scalar,
) -> bool {
    (&constants::ED25519_BASEPOINT_TABLE * resp) == (commitment + (pk * (challenge * λi)))
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
