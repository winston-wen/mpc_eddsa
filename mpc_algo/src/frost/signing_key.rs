use std::collections::{HashMap, HashSet};

use curve25519_dalek::{constants, edwards::EdwardsPoint, scalar::Scalar, traits::Identity};
use libexception::*;
use mpc_spec::MpcAddr;
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256, Sha512};

use super::{Signature, SigningCommitmentPair, SigningNoncePair};

/// preprocess is performed by each participant; their commitments are published
/// and stored in an external location for later use in signing, while their
/// signing nonces are stored locally.
pub fn sign_preprocess<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> Outcome<(SigningCommitmentPair, SigningNoncePair)> {
    let nonce = SigningNoncePair::new(rng).catch_()?;
    let com = SigningCommitmentPair::new(nonce.d.public, nonce.e.public).catch_()?;
    Ok((com, nonce))
}

/// sign is performed by each participant selected for the signing
/// operation; these responses are then aggregated into the final FROST
/// signature by the signature aggregator performing the aggregate function
/// with each response.
pub fn sign_and_respond(
    my_id: MpcAddr,
    x_i: &Scalar,
    rho_dict: &HashMap<MpcAddr, Scalar>,
    sig_r: &EdwardsPoint,
    nonce: &SigningNoncePair, // .len() == cached_com_count
    signers: &HashSet<MpcAddr>,
    main_pk: &EdwardsPoint,
    msg: &[u8],
) -> Outcome<Scalar> {
    let my_rho_i = rho_dict.get(&my_id).ifnone_()?;

    // R = k * G = sum(D_l + E_l * rho_l)
    println!(
        "my_id: {}, signers: {:?}",
        my_id,
        signers.iter().map(|x| x.to_string()).collect::<Vec<_>>()
    );
    let lambda_i = lagrange_lambda(my_id, &signers).catch_()?;

    // c= H_2(R, Y, m)
    let c = generate_challenge(msg, &sig_r, main_pk);

    // z_i = d_i + (e_i * rho_i) + lambda_i * s_i * c
    let response = nonce.d.secret + (nonce.e.secret * my_rho_i) + (lambda_i * x_i * c);

    Ok(response /* z_i */)
}

/// generates the lagrange coefficient for the ith participant. This allows
/// for performing Lagrange interpolation, which underpins threshold secret
/// sharing schemes based on Shamir secret sharing.
pub fn lagrange_lambda(id: MpcAddr, signers: &HashSet<MpcAddr>) -> Outcome<Scalar> {
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

pub fn agg_nonce_com(
    com_dict: &HashMap<MpcAddr, SigningCommitmentPair>,
    bindings: &HashMap<MpcAddr, Scalar>,
) -> Outcome<EdwardsPoint> {
    let mut group_com = EdwardsPoint::identity();
    for (id, com) in com_dict {
        let rho_i = bindings.get(id).ifnone_()?;
        group_com += com.g_d + (com.g_e * rho_i)
    }

    Ok(group_com)
}

pub fn gen_rho_i(
    i: MpcAddr,
    msg: &[u8],
    nonce_com_dict: &HashMap<MpcAddr, SigningCommitmentPair>,
) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update("I".as_bytes());
    hasher.update(i.to_be_bytes());
    hasher.update(msg);

    use itertools::Itertools;
    let nonce_com_it: _ = nonce_com_dict.iter().sorted_by_key(|(id, _)| *id);

    for (j, com) in nonce_com_it {
        hasher.update(j.to_be_bytes());
        hasher.update(com.g_d.compress().as_bytes());
        hasher.update(com.g_e.compress().as_bytes());
    }
    let result = hasher.finalize();

    let rho_i = result
        .as_slice()
        .try_into()
        .expect("Error generating rho_i!");
    Scalar::from_bytes_mod_order(rho_i)
}

pub fn is_valid_response(
    resp: &Scalar,
    xig: &EdwardsPoint,
    λi: &Scalar,
    commitment: &EdwardsPoint,
    challenge: &Scalar,
) -> bool {
    (&constants::ED25519_BASEPOINT_TABLE * resp) == (commitment + (xig * (challenge * λi)))
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
