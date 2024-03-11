mod party_key;
pub use party_key::*;
mod signing_key;
pub use signing_key::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SigningCommitmentPair {
    pub g_d: EdwardsPoint,
    pub g_e: EdwardsPoint,
}

#[derive(Copy, Clone)]
pub struct SigningNoncePair {
    d: Nonce,
    e: Nonce,
}

#[derive(Copy, Clone)]
pub struct Nonce {
    secret: Scalar,
    pub public: EdwardsPoint,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signature {
    pub r: EdwardsPoint,
    pub s: Scalar,
    pub hash: Vec<u8>,
}

impl Zeroize for KeyGenZKP {
    fn zeroize(&mut self) {
        self.g_k_i.zeroize();
        self.sigma.zeroize();
    }
}

impl SigningCommitmentPair {
    pub fn new(g_d: EdwardsPoint, g_e: EdwardsPoint) -> Outcome<SigningCommitmentPair> {
        assert_throw!(
            g_d != EdwardsPoint::identity(),
            "Invalid signing commitment"
        );
        assert_throw!(
            g_e != EdwardsPoint::identity(),
            "Invalid signing commitment"
        );

        Ok(SigningCommitmentPair { g_d, g_e })
    }
}

impl SigningNoncePair {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Outcome<SigningNoncePair> {
        let (d, e) = (Scalar::random(rng), Scalar::random(rng));
        let (d_pub, e_pub) = (
            &constants::ED25519_BASEPOINT_TABLE * &d,
            &constants::ED25519_BASEPOINT_TABLE * &e,
        );

        assert_throw!(
            d_pub != EdwardsPoint::identity(),
            "Invalid nonce commitment"
        );
        assert_throw!(
            e_pub != EdwardsPoint::identity(),
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

use curve25519_dalek::{constants, edwards::EdwardsPoint, scalar::Scalar, traits::Identity};
use libexception::*;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;
