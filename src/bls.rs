use crate::utils;
use crate::utils::calc_sha256_scalar;
use crate::utils::pj_pairing;
use bls12_381::G1Projective;
use bls12_381::G2Projective;
use bls12_381::Gt;
use bls12_381::Scalar;
use rand::RngCore;

pub type BLSSignature = G1Projective;
pub type BLSPrivateKey = Scalar;
pub type BLSPublicKey = G2Projective;

#[derive(Copy, Clone)]
pub struct BLSKeyPair {
    pub prikey: BLSPrivateKey,
    pub pubkey: BLSPublicKey,
}

pub fn bls_gen_key_pair(rng: &mut impl RngCore) -> BLSKeyPair {
    let prikey = utils::gen_rand_scalar(rng);
    let pubkey = BLSPublicKey::generator() * prikey;

    return BLSKeyPair { prikey, pubkey };
}

pub fn bls_sign(prikey: &BLSPrivateKey, msg: &[u8]) -> BLSSignature {
    let hash = calc_sha256_scalar(msg);
    G1Projective::generator() * prikey * hash
}

pub fn bls_verify(signature: &BLSSignature, pubkey: &BLSPublicKey, msg: &[u8]) -> bool {
    let hash = G1Projective::generator() * calc_sha256_scalar(msg);

    return pj_pairing(&signature, &G2Projective::generator()) == pj_pairing(&hash, &pubkey);
}

#[test]
fn test_bls() {
    use rand::thread_rng;
    let mut rng = thread_rng();
    let key_pair = bls_gen_key_pair(&mut rng);
    let msg = vec![1, 3, 4];

    let sig = bls_sign(&key_pair.prikey, &msg);
    let result = bls_verify(&sig, &key_pair.pubkey, &msg);

    assert_eq!(result, true);
}
