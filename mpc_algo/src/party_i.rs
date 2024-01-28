#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SharesCommitment(pub Vec<RistrettoPoint>);

impl Deref for SharesCommitment {
    type Target = Vec<RistrettoPoint>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SharesCommitment {
    // type Target = Vec<RistrettoPoint>;
    // DerefMut 继承 Deref, 所以已经有了 Target 成员

    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenDKGProposedCommitment {
    pub shares_commitment: SharesCommitment,
    pub zkp: KeyGenZKP,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenDKGCommitment(pub SharesCommitment);

impl Deref for KeyGenDKGCommitment {
    type Target = SharesCommitment;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for KeyGenDKGCommitment {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Share(pub Scalar);

impl Deref for Share {
    type Target = Scalar;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Zeroize for Share {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct KeyInitial {
    pub id: u16,
    pub u_i: Scalar,
    pub k: Scalar,
    pub g_u_i: RistrettoPoint,
    pub g_k: RistrettoPoint,
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct KeyPair {
    pub id: u16,
    pub x_i: Scalar,
    pub g_x_i: RistrettoPoint,
    pub group_public: RistrettoPoint,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SigningResponse(pub Scalar);

impl Deref for SigningResponse {
    type Target = Scalar;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SigningCommitmentPair {
    g_d: RistrettoPoint,
    g_e: RistrettoPoint,
}

#[derive(Copy, Clone)]
pub struct SigningNoncePair {
    d: Nonce,
    e: Nonce,
}

#[derive(Copy, Clone)]
pub struct Nonce {
    secret: Scalar,
    pub public: RistrettoPoint,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenZKP {
    pub g_k: RistrettoPoint, // KeyGen: g_k
    pub sigma: Scalar,       // KeyGen: sigma
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signature {
    pub r: RistrettoPoint, // Sign: R
    pub z: Scalar,         // Sign: z
    pub hash: Vec<u8>,     // Sign: hashed message
}

impl Zeroize for KeyGenDKGProposedCommitment {
    fn zeroize(&mut self) {
        self.shares_commitment.zeroize();
        self.zkp.zeroize();
    }
}

impl Zeroize for SharesCommitment {
    fn zeroize(&mut self) {
        self.iter_mut().for_each(Zeroize::zeroize);
    }
}

impl Zeroize for KeyGenZKP {
    fn zeroize(&mut self) {
        self.g_k.zeroize();
        self.sigma.zeroize();
    }
}

impl KeyGenDKGProposedCommitment {
    pub fn is_valid_zkp(&self, challenge: Scalar) -> Outcome<()> {
        let valid_zkp = self.zkp.g_k
            == (&constants::RISTRETTO_BASEPOINT_TABLE * &self.zkp.sigma)
                - (self.get_commitment_to_secret() * challenge);
        assert_throw!(valid_zkp);
        Ok(())
    }

    pub fn get_commitment_to_secret(&self) -> RistrettoPoint {
        self.shares_commitment[0]
    }
}

impl Share {
    /// Verify that a share is consistent with a commitment.
    fn verify_share(&self, member_id: u16, com: &SharesCommitment) -> Outcome<()> {
        let f_result = &constants::RISTRETTO_BASEPOINT_TABLE * &self.0;

        let term = Scalar::from(member_id);
        let mut result = RistrettoPoint::identity();

        // Thanks to isis lovecruft for their simplification to Horner's method;
        // including it here for readability. Their implementation of FROST can
        // be found here: github.com/isislovecruft/frost-dalek
        for (k, com_k) in com.iter().rev().enumerate() {
            result += com_k;

            if k != com.len() - 1 {
                result *= term;
            }
        }
        assert_throw!(f_result == result, "Invalid share");

        Ok(())
    }
}

impl KeyInitial {
    pub fn new<R: RngCore + CryptoRng>(index: u16, rng: &mut R) -> Self {
        let u_i = Scalar::random(rng);
        let k = Scalar::random(rng);
        let g_u_i = &constants::RISTRETTO_BASEPOINT_TABLE * &u_i;
        let g_k = &constants::RISTRETTO_BASEPOINT_TABLE * &k;
        Self {
            id: index,
            u_i,
            k,
            g_u_i,
            g_k,
        }
    }

    pub fn create_from<R: RngCore + CryptoRng>(index: u16, rng: &mut R, u_i: Scalar) -> Self {
        let k = Scalar::random(rng);
        let g_u_i = &constants::RISTRETTO_BASEPOINT_TABLE * &u_i;
        let g_k = &constants::RISTRETTO_BASEPOINT_TABLE * &k;
        Self {
            id: index,
            u_i,
            k,
            g_u_i,
            g_k,
        }
    }

    /// Create secret shares for a given secret. This function accepts a secret to
    /// generate shares from. While in FROST this secret should always be generated
    /// randomly, we allow this secret to be specified for this internal function
    /// for testability
    pub fn generate_shares<R: RngCore + CryptoRng>(
        &self,
        members: &HashSet<u16>,
        th: u16,
        rng: &mut R,
    ) -> Outcome<(SharesCommitment, HashMap<u16, Share>)> {
        assert_throw!(members.contains(&self.id));
        assert_throw!(usize::from(th) < members.len());

        let mut coefficients: Vec<Scalar> = Vec::new();
        for _ in 0..th {
            coefficients.push(Scalar::random(rng));
        }

        let mut commitment: Vec<RistrettoPoint> = vec![self.g_u_i];
        for c in coefficients.iter() {
            commitment.push(&constants::RISTRETTO_BASEPOINT_TABLE * &c);
        }

        let mut shares: HashMap<u16, Share> = HashMap::new();
        for i in members.iter() {
            let id = Scalar::from(*i);
            let mut value = Scalar::zero();
            for c in coefficients.iter().rev() {
                value = id * (value + c);
            }
            value += self.u_i;
            let share = Share(value);
            shares.insert(*i, share);
        }

        for c in coefficients.iter_mut() {
            c.zeroize();
        }

        Ok((SharesCommitment(commitment), shares))
    }

    /// keygen_receive_commitments_and_validate_peers gathers commitments from
    /// peers and validates the zero knowledge proof of knowledge for the peer's
    /// secret term. It returns a list of all participants who failed the check,
    /// a list of commitments for the peers that remain in a valid state,
    /// and an error term.
    ///
    /// Here, we return a DKG commitmentment that is explicitly marked as valid,
    /// to ensure that this step of the protocol is performed before going on to
    /// keygen_finalize
    pub fn keygen_validate_peers(
        proposed_coms: &HashMap<u16, KeyGenDKGProposedCommitment>,
        context: &str,
    ) -> Outcome<HashMap<u16, KeyGenDKGCommitment>> {
        let mut invalid_ids = Vec::new();
        let mut valid_coms: HashMap<u16, KeyGenDKGCommitment> = HashMap::new();

        for (id, com) in proposed_coms.iter() {
            let challenge =
                generate_dkg_challenge(*id, context, &com.get_commitment_to_secret(), &com.zkp.g_k)
                    .catch_()?;

            if com.is_valid_zkp(challenge).is_ok() {
                let valid_com = KeyGenDKGCommitment(com.shares_commitment.clone());
                valid_coms.insert(*id, valid_com);
            } else {
                invalid_ids.push(*id);
            }
        }

        if invalid_ids.len() > 0 {
            let errmsg = format!("Invalid zkp from parties {:?}", invalid_ids);
            throw!("", &errmsg);
        }

        Ok(valid_coms)
    }

    pub fn keygen_verify_share_construct_keypair(
        party_shares: &HashMap<u16, Share>,
        share_coms: &HashMap<u16, KeyGenDKGCommitment>,
        member_id: u16,
    ) -> Outcome<KeyPair> {
        // first, verify the integrity of the shares
        for (id, share) in party_shares.iter() {
            let com = share_coms.get(id).ifnone_()?;
            share.verify_share(member_id, &com.0).catch_()?;
        }

        let mut x_i = Scalar::zero();
        for ps in party_shares.values() {
            x_i += ps.0;
        }
        let g_x_i = &constants::RISTRETTO_BASEPOINT_TABLE * &x_i;

        let mut group_public = RistrettoPoint::identity();
        for com in share_coms.values() {
            group_public += com.0[0];
        }

        Ok(KeyPair {
            id: member_id,
            x_i,
            g_x_i,
            group_public,
        })
    }
}

impl KeyPair {
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
        &self,
        com_dict: &HashMap<u16, SigningCommitmentPair>, // B, but how to construct B???
        nonce_vec: &mut Vec<SigningNoncePair>,          // .len() == cached_com_count
        msg: &[u8],
    ) -> Outcome<SigningResponse> {
        // no message checking???
        // no D_l and E_l checking???

        let i_nonce: usize;
        let my_nonce: &SigningNoncePair;
        {
            let my_comm = com_dict.get(&self.id).ifnone_()?;
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

        let response: Scalar;
        {
            let mut bindings: HashMap<u16, Scalar> = HashMap::with_capacity(com_dict.len());
            for id in com_dict.keys() {
                let rho_i = gen_rho_i(*id, msg, com_dict); // rho_l = H_1(l, m, B)
                let _ = bindings.insert(*id, rho_i); // (l, rho_l)
            }
            let group_commitment = gen_group_commitment(com_dict, &bindings).catch_()?;
            let my_rho_i = bindings.get(&self.id).ifnone_()?;
            let signers: Vec<u16> = com_dict.keys().cloned().collect();

            // R = k * G = sum(D_l + E_l * rho_l)
            let lambda_i = get_lagrange_coeff(0, self.id, &signers).catch_()?;

            // c= H_2(R, Y, m)
            let c = generate_challenge(msg, group_commitment);

            // z_i = d_i + (e_i * rho_i) + lambda_i * s_i * c
            response =
                my_nonce.d.secret + (my_nonce.e.secret * my_rho_i) + (lambda_i * self.x_i * c);
        }

        // Now that this nonce has been used, delete it
        nonce_vec.remove(i_nonce);

        Ok(SigningResponse(response /* z_i */))
    }

    /// aggregate collects all responses from participants. It first performs a
    /// validity check for each participant's response, and will return an error in the
    /// case the response is invalid. If all responses are valid, it aggregates these
    /// into a single signature that is published. This function is executed
    /// by the entity performing the signature aggregator role.
    pub fn sign_aggregate_responses(
        msg: &[u8],
        com_dict: &HashMap<u16, SigningCommitmentPair>,
        resp_dict: &HashMap<u16, SigningResponse>,
        pubkey_dict: &HashMap<u16, RistrettoPoint>,
    ) -> Outcome<Signature> {
        let mut bindings: HashMap<u16, Scalar> = HashMap::new(); // rho-s
        for id in com_dict.keys() {
            let rho_i = gen_rho_i(*id, msg, com_dict);
            bindings.insert(*id, rho_i);
        }
        let group_commitment: RistrettoPoint =
            gen_group_commitment(&com_dict, &bindings).catch_()?;
        let challenge: Scalar = generate_challenge(msg, group_commitment);
        let signers: Vec<u16> = com_dict.keys().cloned().collect();

        // Validate each participant's response
        for (id, resp) in resp_dict {
            let rho = bindings.get(id).ifnone_()?;
            let lambda_i = get_lagrange_coeff(0, *id, &signers).catch_()?;

            let com = com_dict.get(id).ifnone_()?;
            let com = com.g_d + (com.g_e * rho);
            let pk = pubkey_dict.get(id).ifnone_()?;

            let resp_is_valid = resp.is_valid(pk, lambda_i, &com, challenge);
            assert_throw!(resp_is_valid, "Invalid signer response");
        }

        let mut group_resp: Scalar = Scalar::zero();
        for resp in resp_dict.values() {
            group_resp += resp.0;
        }

        Ok(Signature {
            r: group_commitment,
            z: group_resp,
            hash: msg.to_vec(),
        })
    }
}

impl SigningResponse {
    pub fn is_valid(
        &self,
        pubkey: &RistrettoPoint,
        lambda_i: Scalar,
        commitment: &RistrettoPoint,
        challenge: Scalar,
    ) -> bool {
        (&constants::RISTRETTO_BASEPOINT_TABLE * &self.0)
            == (commitment + (pubkey * (challenge * lambda_i)))
    }
}

impl SigningCommitmentPair {
    pub fn new(g_d: RistrettoPoint, g_e: RistrettoPoint) -> Outcome<SigningCommitmentPair> {
        assert_throw!(
            g_d != RistrettoPoint::identity(),
            "Invalid signing commitment"
        );
        assert_throw!(
            g_e != RistrettoPoint::identity(),
            "Invalid signing commitment"
        );

        Ok(SigningCommitmentPair { g_d, g_e })
    }
}

impl SigningNoncePair {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Outcome<SigningNoncePair> {
        let (d, e) = (Scalar::random(rng), Scalar::random(rng));
        let (d_pub, e_pub) = (
            &constants::RISTRETTO_BASEPOINT_TABLE * &d,
            &constants::RISTRETTO_BASEPOINT_TABLE * &e,
        );

        assert_throw!(
            d_pub != RistrettoPoint::identity(),
            "Invalid nonce commitment"
        );
        assert_throw!(
            e_pub != RistrettoPoint::identity(),
            "Invalid nonce commitment"
        );

        Ok(SigningNoncePair {
            d: Nonce {
                secret: d,
                public: d_pub,
            },
            e: Nonce {
                secret: e,
                public: e_pub,
            },
        })
    }
}

pub fn generate_dkg_challenge(
    index: u16,
    context: &str,
    public: &RistrettoPoint,
    commitment: &RistrettoPoint,
) -> Outcome<Scalar> {
    let mut hasher = Sha256::new();
    // the order of the below may change to allow for EdDSA verification compatibility
    hasher.update(commitment.compress().to_bytes());
    hasher.update(public.compress().to_bytes());
    hasher.update(index.to_string());
    hasher.update(context);
    let result = hasher.finalize();

    let a: [u8; 32] = result
        .as_slice()
        .try_into()
        .expect("Error generating commitment!");

    Ok(Scalar::from_bytes_mod_order(a))
}

/// generates the lagrange coefficient for the ith participant. This allows
/// for performing Lagrange interpolation, which underpins threshold secret
/// sharing schemes based on Shamir secret sharing.
pub fn get_lagrange_coeff(x_coord: u16, signer_id: u16, signers: &[u16]) -> Outcome<Scalar> {
    let mut num = Scalar::one();
    let mut den = Scalar::one();
    for j in signers {
        if *j == signer_id {
            continue;
        }
        num *= Scalar::from(*j) - Scalar::from(x_coord);
        den *= Scalar::from(*j) - Scalar::from(signer_id);
    }

    assert_throw!(den != Scalar::zero(), "Duplicate shares provided");

    let lagrange_coeff = num * den.invert();

    Ok(lagrange_coeff)
}

// get g_x_i locally
pub fn get_ith_pubkey(index: u16, com_dict: &HashMap<u16, KeyGenDKGCommitment>) -> RistrettoPoint {
    let mut ith_pubkey = RistrettoPoint::identity();
    let term = Scalar::from(index);

    // iterate over each commitment
    for com in com_dict.values() {
        let mut part = RistrettoPoint::identity();
        let t = com.len() as u16;

        // iterate  over each element in the commitment
        for (inner_index, comm_i) in com.iter().rev().enumerate() {
            part += comm_i;

            // handle constant term
            if inner_index as u16 != t - 1 {
                part *= term;
            }
        }

        ith_pubkey += part;
    }

    ith_pubkey
}

/// validate performs a plain Schnorr validation operation; this is identical
/// to performing validation of a Schnorr signature that has been signed by a
/// single party.
// pub fn validate(msg: &str, sig: &Signature, pubkey: RistrettoPoint) -> Outcome<()> {
pub fn validate(sig: &Signature, pubkey: &RistrettoPoint) -> Outcome<()> {
    let challenge = generate_challenge(&sig.hash, sig.r);
    let sig_valid = sig.r == (&constants::RISTRETTO_BASEPOINT_TABLE * &sig.z) - pubkey * challenge;
    assert_throw!(sig_valid, "Signature is invalid");

    Ok(())
}

// to be reviewed again? For H(m, R) instead of H(R, Y, m)???
/// generates the challenge value H(m, R) used for both signing and verification.
/// ed25519_ph hashes the message first, and derives the challenge as H(H(m), R),
/// this would be a better optimization but incompatibility with other
/// implementations may be undesirable.
pub fn generate_challenge(msg: &[u8], group_commitment: RistrettoPoint) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(group_commitment.compress().to_bytes());
    hasher.update(msg);
    let result = hasher.finalize();

    let x = result
        .as_slice()
        .try_into()
        .expect("Error generating commitment!");
    Scalar::from_bytes_mod_order(x)
}

fn gen_rho_i(index: u16, msg: &[u8], com_dict: &HashMap<u16, SigningCommitmentPair>) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update("I".as_bytes());
    hasher.update(index.to_be_bytes());
    hasher.update(msg);

    let com_iter_id_asc = com_dict.iter().sorted_by_key(|(id, _)| *id);
    for (id, com) in com_iter_id_asc {
        hasher.update(id.to_be_bytes());
        hasher.update(com.g_d.compress().as_bytes());
        hasher.update(com.g_e.compress().as_bytes());
    }
    let result = hasher.finalize();

    let x = result
        .as_slice()
        .try_into()
        .expect("Error generating commitment!");
    Scalar::from_bytes_mod_order(x)
}

fn gen_group_commitment(
    com_dict: &HashMap<u16, SigningCommitmentPair>,
    bindings: &HashMap<u16, Scalar>,
) -> Outcome<RistrettoPoint> {
    let mut group_com = RistrettoPoint::identity();
    for (id, com) in com_dict {
        let rho_i = bindings.get(id).ifnone_()?;
        group_com += com.g_d + (com.g_e * rho_i)
    }

    Ok(group_com)
}

use curve25519_dalek::{constants, ristretto::RistrettoPoint, scalar::Scalar, traits::Identity};
use itertools::Itertools;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::ops::{Deref, DerefMut};
use zeroize::Zeroize;

use crate::prelude::*;
