use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use bip32::ChainCode;
use hmac::{Hmac, Mac, NewMac};
use sha2::Sha512;
use super::hd::algo_get_hd_key;
use crate::prelude::*;

pub type Pk = RistrettoPoint;
pub type PkRespT = AnyhowResult<Pk>; // derived path and pubkey

/// Fetch and compute the derived public key from root pubkey and chaincode.
pub fn algo_pubkey(
    keystore: &str,
    dpath: &str,
) -> AnyhowResult<Pk> {
    let (_, signing_key, _, _,): (
        KeyInitial, KeyPair, u16, Vec<KeyGenDKGCommitment>,
    ) = crate::ut::json_to_obj(keystore)?;
    let y_sum_bytes_small = signing_key.group_public.compress().to_bytes().to_vec();
    let chain_code: ChainCode = match Sha512::digest(&y_sum_bytes_small).get(..32) {
        Some(arr) => arr.try_into().unwrap(),
        None => {
            throw!(
                name = ChildKeyDerivationFailed,
                ctx = &(format!(
                    "Bad Sha512 digest for ChainCode, input_bytes_hex={}",
                    hex::encode(&y_sum_bytes_small)
                ) + exception_location)
            )
        }
    };
    if !dpath.is_empty() {
        match algo_get_hd_key(&dpath, &signing_key.group_public, &chaincode) {
            Ok((_, derived_pk)) => { 
                return Ok(derived_pk); 
            },
            Err(e) => { return Err(e); },
        }
    } else {
        return Ok(signing_key.group_public.clone());
    }
}
