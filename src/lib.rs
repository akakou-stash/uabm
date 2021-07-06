#[macro_use]
extern crate slice_as_array;

use crate::bls::bls_gen_key_pair;
use crate::bls::bls_sign;
use crate::bls::bls_verify;
use crate::bls::BLSKeyPair;
use crate::bls::BLSPublicKey;
use crate::bls::BLSSignature;
use epid::core::GPK;
pub use epid::issuer::Issuer as GM;
use epid::join::IssuerJoinProcess;
use epid::join::PlatformJoinProcess;
use rand::RngCore;

use epid::core::Signature as EPIDSignature;
use epid::platform::Platform as EPIDPlatform;
use epid::verifier::Verifier as EPIDVerifier;

use bls12_381::G1Projective;
use bls12_381::G2Projective;
use bls12_381::Scalar;

use group::GroupEncoding;

use epid::core::Revocation;
mod bls;
mod utils;

#[derive(Clone)]
pub struct MemberCertificateRequest {
    public_key: BLSPublicKey,
    epid_signature: EPIDSignature,
}

#[derive(Clone)]
pub struct MemberCertificate {
    req: MemberCertificateRequest,
    veirier_signature: BLSSignature,
}

struct Verifier {
    ml: Vec<Revocation>,
    epid_verifier: EPIDVerifier,
    bls_keypair: BLSKeyPair,
}

impl Verifier {
    fn new(gpk: GPK, ml: &[Revocation], rng: &mut impl RngCore) -> Self {
        let verifier = EPIDVerifier::new(gpk);
        let bls_keypair = bls_gen_key_pair(rng);

        Self {
            ml: ml.to_vec(),
            epid_verifier: verifier,
            bls_keypair,
        }
    }
    fn register_member(&mut self, req: &MemberCertificateRequest) -> MemberCertificate {
        self.epid_verifier
            .verify(
                &req.epid_signature,
                req.public_key.to_bytes().as_ref(),
                &self.ml,
            )
            .expect("user exits");
        self.ml.push(Revocation {
            large_b: req.epid_signature.platform_attestation.large_b,
            large_k: req.epid_signature.platform_attestation.large_k,
        });
        MemberCertificate {
            req: req.clone(),
            veirier_signature: bls_sign(
                &self.bls_keypair.prikey,
                &req.public_key.to_bytes().as_ref(),
            ),
        }
    }

    pub fn verify(&self, signature: &Signature, msg: &[u8]) -> Result<(), ()> {
        let is_valid_msg = bls_verify(
            &signature.bls_signature,
            &signature.certificate.req.public_key,
            msg,
        );

        let is_valid_certificate = bls_verify(
            &signature.certificate.veirier_signature,
            &self.bls_keypair.pubkey,
            &signature.certificate.req.public_key.to_bytes().as_ref(),
        );

        if is_valid_certificate && is_valid_msg {
            Ok(())
        } else {
            Err(())
        }
    }
}

pub struct Signature {
    pub certificate: MemberCertificate,
    pub bls_signature: BLSSignature,
}

pub struct Member {
    pub certificate: MemberCertificate,
    pub key_pair: BLSKeyPair,
}

impl Member {
    fn new(certificate: MemberCertificate, key_pair: BLSKeyPair) -> Self {
        Self {
            certificate,
            key_pair,
        }
    }
    fn sign(&self, msg: &[u8]) -> Signature {
        let bls_signature = bls_sign(&self.key_pair.prikey, msg);

        Signature {
            bls_signature,
            certificate: self.certificate.clone(),
        }
    }
}

pub struct JoinMemberProcess {
    pub epid_member: EPIDPlatform,
    pub bls_keypair: BLSKeyPair,
}

impl JoinMemberProcess {
    pub fn new(platform: EPIDPlatform, rng: &mut impl RngCore) -> Self {
        Self {
            epid_member: platform,
            bls_keypair: bls_gen_key_pair(rng),
        }
    }

    pub fn gen_certificate_request(
        &self,
        ml: &[Revocation],
        rng: &mut impl RngCore,
    ) -> MemberCertificateRequest {
        let epid_signature =
            self.epid_member
                .sign(self.bls_keypair.pubkey.to_bytes().as_ref(), ml, rng);

        let public_key = self.bls_keypair.pubkey;

        MemberCertificateRequest {
            epid_signature,
            public_key,
        }
    }

    pub fn generate_member(&self, certificate: MemberCertificate) -> Member {
        Member {
            certificate: certificate,
            key_pair: self.bls_keypair,
        }
    }
}

#[test]
fn test_auth() {
    use rand::thread_rng;
    let mut rng = thread_rng();
    let gm = GM::random(&mut rng);
    let gpk = gm.gpk;

    let mut platform_join = PlatformJoinProcess::new(gpk);
    let join_req = platform_join.gen_request(&mut rng);
    let issuer_join = IssuerJoinProcess::new(gm, join_req);

    let join_resp = issuer_join
        .gen_join_response(&mut rng)
        .expect("genjoin resp error");

    let platform = platform_join
        .gen_platform(&join_resp)
        .expect("gen platform error");

    let mut verifier = Verifier::new(gpk, &vec![], &mut rng);

    let process = JoinMemberProcess::new(platform, &mut rng);
    let req = process.gen_certificate_request(&vec![], &mut rng);

    let resp = verifier.register_member(&req);
    let member = process.generate_member(resp);
    let signature = member.sign(&vec![2, 4, 5]);

    verifier.verify(&signature, &vec![2, 4, 5]).unwrap();

    match verifier.verify(&signature, &vec![2, 4, 4]) {
        Ok(_) => {
            assert!(false);
        }
        Err(_) => {}
    }
}
