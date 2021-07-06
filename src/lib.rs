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
    pub req: MemberCertificateRequest,
    pub verifier_signature: BLSSignature,
    pub checked_revocation_index: u8, // todo : fix
}

pub struct Verifier {
    pub ml: Vec<Revocation>,
    pub rl: Vec<Revocation>,
    pub epid_verifier: EPIDVerifier,
    pub bls_keypair: BLSKeyPair,
}

impl Verifier {
    pub fn new(gpk: GPK, ml: &[Revocation], rl: &[Revocation], rng: &mut impl RngCore) -> Self {
        let verifier = EPIDVerifier::new(gpk);
        let bls_keypair = bls_gen_key_pair(rng);

        Self {
            ml: ml.to_vec(),
            rl: rl.to_vec(),
            epid_verifier: verifier,
            bls_keypair,
        }
    }

    pub fn register_member(&mut self, req: &MemberCertificateRequest) -> MemberCertificate {
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

        self.generate_certificate(req, 0)
    }

    pub fn verify(&self, signature: &Signature, msg: &[u8]) -> Result<(), ()> {
        if usize::from(signature.certificate.checked_revocation_index) != self.rl.len() {
            return Err(());
        }

        if !bls_verify(
            &signature.bls_signature,
            &signature.certificate.req.public_key,
            msg,
        ) {
            return Err(());
        }

        self.check_valid_certificate(&signature.certificate)?;

        return Ok(());
    }

    pub fn update(&self, certificate: &MemberCertificate) -> Result<MemberCertificate, ()> {
        self.check_valid_certificate(certificate)?;
        self.check_new_revocation(certificate)?;

        Ok(self.generate_certificate(&certificate.req, self.rl.len() as u8))
    }

    fn check_new_revocation(&self, certificate: &MemberCertificate) -> Result<(), ()> {
        match self.epid_verifier.verify(
            &certificate.req.epid_signature,
            certificate.req.public_key.to_bytes().as_ref(),
            &self.rl[certificate.checked_revocation_index as usize..self.rl.len() as usize],
        ) {
            Ok(_) => Ok(()),
            Err(err) => {
                println!("{}", err);
                return Err(());
            }
        }
    }

    pub fn check_valid_certificate(&self, certificate: &MemberCertificate) -> Result<(), ()> {
        let mut bytes = certificate.req.public_key.to_bytes().as_ref().to_vec();
        bytes.push(certificate.checked_revocation_index);

        println!("A: {:?}", bytes);

        if bls_verify(
            &certificate.verifier_signature,
            &self.bls_keypair.pubkey,
            &bytes,
        ) {
            return Ok(());
        } else {
            return Err(());
        }
    }

    pub fn generate_certificate(
        &self,
        req: &MemberCertificateRequest,
        index: u8,
    ) -> MemberCertificate {
        let mut bytes = req.public_key.to_bytes().as_ref().to_vec();
        bytes.push(index);

        println!("B: {:?}", bytes);

        MemberCertificate {
            req: req.clone(),
            verifier_signature: bls_sign(&self.bls_keypair.prikey, &bytes),
            checked_revocation_index: index,
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
    pub epid_member: EPIDPlatform,
}

impl Member {
    fn new(
        certificate: MemberCertificate,
        key_pair: BLSKeyPair,
        epid_member: EPIDPlatform,
    ) -> Self {
        Self {
            certificate,
            key_pair,
            epid_member,
        }
    }
    fn sign(&self, msg: &[u8]) -> Signature {
        let bls_signature = bls_sign(&self.key_pair.prikey, msg);

        Signature {
            bls_signature,
            certificate: self.certificate.clone(),
        }
    }

    fn update(&mut self, rl: &[Revocation], rng: &mut impl RngCore) {
        let epid_signature =
            self.epid_member
                .sign(self.certificate.req.public_key.to_bytes().as_ref(), rl, rng);

        self.certificate.req.epid_signature = epid_signature;
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
            epid_member: self.epid_member,
        }
    }
}

#[test]
fn test_auth() {
    use rand::thread_rng;
    let mut rng = thread_rng();
    let gm = GM::random(&mut rng);
    let gpk = gm.gpk;

    let mut rl_platform_join = PlatformJoinProcess::new(gpk);
    let rl_join_req = rl_platform_join.gen_request(&mut rng);
    let rl_issuer_join = IssuerJoinProcess::new(gm, rl_join_req);
    let rl_join_resp = rl_issuer_join
        .gen_join_response(&mut rng)
        .expect("genjoin resp error");

    let rl_platform = rl_platform_join
        .gen_platform(&rl_join_resp)
        .expect("gen platform error");

    let msg = vec![1, 2, 3];
    let rl_signature = rl_platform.sign(&msg, &vec![], &mut rng);

    let rl = vec![Revocation {
        large_k: rl_signature.platform_attestation.large_k,
        large_b: rl_signature.platform_attestation.large_b,
    }];

    //////////

    let mut platform_join = PlatformJoinProcess::new(gpk);
    let join_req = platform_join.gen_request(&mut rng);
    let issuer_join = IssuerJoinProcess::new(gm, join_req);

    let join_resp = issuer_join
        .gen_join_response(&mut rng)
        .expect("genjoin resp error");

    let platform = platform_join
        .gen_platform(&join_resp)
        .expect("gen platform error");

    let mut verifier = Verifier::new(gpk, &vec![], &rl, &mut rng);

    let process = JoinMemberProcess::new(platform, &mut rng);
    let req = process.gen_certificate_request(&vec![], &mut rng);
    let resp = verifier.register_member(&req);

    /////////////////////////

    let mut member = process.generate_member(resp);

    member.update(&rl, &mut rng);
    println!(
        "C: {:?}",
        member.certificate.req.public_key.to_bytes().as_ref()
    );

    member.certificate = verifier.update(&member.certificate).unwrap();
    let signature = member.sign(&vec![2, 4, 5]);

    verifier.verify(&signature, &vec![2, 4, 5]).unwrap();

    /////////////////////////

    match verifier.verify(&signature, &vec![2, 4, 4]) {
        Ok(_) => {
            assert!(false);
        }
        Err(_) => {}
    }

    /// check rl
    let process = JoinMemberProcess::new(rl_platform, &mut rng);
    let req = process.gen_certificate_request(&verifier.ml, &mut rng);
    let resp = verifier.register_member(&req);

    let mut rl_platform = process.generate_member(resp);
    rl_platform.update(&rl, &mut rng);

    match verifier.update(&rl_platform.certificate) {
        Ok(_) => {
            assert!(false);
        }
        Err(_) => {}
    }
}
