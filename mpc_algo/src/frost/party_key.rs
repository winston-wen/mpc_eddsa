use std::collections::{HashMap, HashSet};

use curve25519_dalek::{constants, edwards::EdwardsPoint, scalar::Scalar, traits::Identity};
use libexception::*;
use mpc_spec::MpcAddr;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct PartyKey {
    pub u_i: Scalar,
    pub k_i: Scalar,
}

impl PartyKey {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let u_i = Scalar::random(rng);
        let k = Scalar::random(rng);
        Self { u_i, k_i: k }
    }

    pub fn g_u_i(&self) -> EdwardsPoint {
        &constants::ED25519_BASEPOINT_TABLE * &self.u_i
    }

    pub fn g_k_i(&self) -> EdwardsPoint {
        &constants::ED25519_BASEPOINT_TABLE * &self.k_i
    }

    #[allow(dead_code)]
    pub fn import<R: RngCore + CryptoRng>(u_i: Scalar, rng: &mut R) -> Self {
        let k = Scalar::random(rng);
        Self { u_i, k_i: k }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenDKGProposedCommitment {
    pub shares_commitment: Vec<EdwardsPoint>,
    pub zkp: KeyGenZKP,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenZKP {
    pub g_k_i: EdwardsPoint, // KeyGen: g_k
    pub sigma: Scalar,       // KeyGen: sigma
}

impl Zeroize for KeyGenDKGProposedCommitment {
    fn zeroize(&mut self) {
        self.shares_commitment.zeroize();
        self.zkp.zeroize();
    }
}

impl KeyGenDKGProposedCommitment {
    pub fn is_valid_zkp(&self, challenge: Scalar) -> Outcome<()> {
        let valid_zkp = self.zkp.g_k_i
            == (&constants::ED25519_BASEPOINT_TABLE * &self.zkp.sigma)
                - (self.get_commitment_to_secret() * challenge);
        assert_throw!(valid_zkp);
        Ok(())
    }

    pub fn get_commitment_to_secret(&self) -> EdwardsPoint {
        self.shares_commitment[0]
    }
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
    proposed_coms: &HashMap<MpcAddr, KeyGenDKGProposedCommitment>,
    context: &str,
) -> Outcome<HashMap<MpcAddr, Vec<EdwardsPoint>>> {
    let mut invalid_ids = Vec::new();
    let mut valid_coms = HashMap::new();

    for (id, com) in proposed_coms.iter() {
        let challenge = generate_dkg_challenge(
            *id,
            context,
            &com.get_commitment_to_secret(),
            &com.zkp.g_k_i,
        )
        .catch_()?;

        if com.is_valid_zkp(challenge).is_ok() {
            let valid_com = com.shares_commitment.clone();
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

pub fn merge_vss_share(
    party_shares: &HashMap<MpcAddr, Scalar>,
    share_coms: &HashMap<MpcAddr, Vec<EdwardsPoint>>,
    my_id: MpcAddr,
) -> Outcome<Scalar /* x_i, aka the signing key */> {
    // first, verify the integrity of the shares
    for (id, share) in party_shares.iter() {
        let com = share_coms.get(id).ifnone_()?;
        verify_vss_share(my_id, share, com).catch_()?;
    }

    let mut x_i = Scalar::zero();
    for ps in party_shares.values() {
        x_i += ps;
    }

    Ok(x_i)
}

pub fn generate_vss_share<R: RngCore + CryptoRng>(
    u_i: &Scalar,
    my_id: MpcAddr,
    members: &HashSet<MpcAddr>,
    th: usize, // At least `th` members during sign.
    rng: &mut R,
) -> Outcome<(Vec<EdwardsPoint>, HashMap<MpcAddr, Scalar>)> {
    assert_throw!(
        members.contains(&my_id),
        format!("{} not in members", my_id)
    );
    for i in members.iter() {
        assert_throw!(
            i.group_id() == my_id.group_id(),
            "vss_share: members not in same group"
        );
    }
    assert_throw!(1 <= th && th < members.len());

    // randomly generate a polynomial
    let mut poly: Vec<Scalar> = vec![u_i.clone()];
    for _ in 1..th {
        poly.push(Scalar::random(rng));
    }

    // commit to the polynomial
    let mut poly_com = Vec::new();
    for c in poly.iter() {
        poly_com.push(&constants::ED25519_BASEPOINT_TABLE * c);
    }

    // treat member ID as $x$,
    // and evaluate the polynomial at each $x$.
    let mut shares: HashMap<MpcAddr, Scalar> = HashMap::new();
    for i in members.iter() {
        let x = Scalar::from(i.member_id());
        let y = eval_poly(&poly, &x);
        shares.insert(*i, y);
    }

    for c in poly.iter_mut() {
        c.zeroize();
    }

    Ok((poly_com, shares))
}

/// This may vary from chain to chain, from protocol to protocol.
pub fn generate_dkg_challenge(
    index: MpcAddr,
    context: &str,
    public: &EdwardsPoint,
    commitment: &EdwardsPoint,
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

/// Verify that a share is consistent with a commitment.
/// i.e. verify that a share is computed from the polynomial represented by `com`.
pub fn verify_vss_share(id: MpcAddr, share: &Scalar, com: &[EdwardsPoint]) -> Outcome<()> {
    let polycom = &constants::ED25519_BASEPOINT_TABLE * share;

    let x = Scalar::from(id.member_id());
    let expanded_polycom = eval_polycom(com, &x);
    assert_throw!(polycom == expanded_polycom, "Invalid share");

    Ok(())
}

/// Evaluate $x_i \ast G$, without knowing $x_i$.
pub fn eval_xi_com(
    index: MpcAddr,
    vss_com_dict: &HashMap<MpcAddr, Vec<EdwardsPoint>>,
) -> EdwardsPoint {
    let mut gxi = EdwardsPoint::identity();
    let i = Scalar::from(index.member_id());
    for vss_com in vss_com_dict.values() {
        gxi += eval_polycom(vss_com, &i);
    }
    gxi
}

/// evaluate a polynomial using Qin Jiushao (秦久韶) / Horner's method.
/// NOTE: coefficients should be traversed in DEscending power of `x`.
fn eval_poly(poly: &[Scalar], x: &Scalar) -> Scalar {
    let mut y = Scalar::zero();
    for coef in poly.iter().rev() {
        y = y * x + coef;
    }
    y
}

fn eval_polycom(coef_coms: &[EdwardsPoint], x: &Scalar) -> EdwardsPoint {
    let mut polycom = EdwardsPoint::identity();
    for coef_com in coef_coms.iter().rev() {
        polycom = (polycom * x) + coef_com;
    }
    polycom
}
