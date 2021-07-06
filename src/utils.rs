use bls12_381::pairing;
use bls12_381::G1Projective;
use bls12_381::G2Projective;
use bls12_381::Gt;
use bls12_381::Scalar;
use byteorder::{BigEndian, ByteOrder};
use ff::Field;
use group::Curve;
use rand::RngCore;
use sha2::{Digest, Sha256};

pub fn gen_rand_scalar(rng: &mut impl RngCore) -> Scalar {
    Scalar::random(rng)
}

pub fn calc_sha256_scalar(vec: &[u8]) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(vec);
    let hashed = hasher.finalize().to_vec();

    let mut schalar: Vec<u64> = vec![0; hashed.len() / 8];
    BigEndian::read_u64_into(&hashed, &mut schalar);
    let schalar = slice_as_array!(&schalar, [u64; 4]).unwrap();

    Scalar::from_raw(*schalar)
}

pub fn pj_pairing(g1: &G1Projective, g2: &G2Projective) -> Gt {
    pairing(&g1.to_affine(), &g2.to_affine())
}
