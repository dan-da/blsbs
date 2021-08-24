use blst::min_pk::{SecretKey, PublicKey, Signature};
use blst::{blst_fr, blst_p1_affine, blst_p2, blst_p2_affine, blst_scalar, Pairing, BLST_ERROR};
use thiserror::Error;
use std::convert::TryInto;

type SignatureShare = Signature;
type Slip = Vec<u8>;

/// Specialisation of `std::Result`.
pub type Result<T, E = BlindSignatureError> = std::result::Result<T, E>;
pub type Error = BlindSignatureError;

#[allow(clippy::large_enum_variant)]
#[derive(Error, Debug)]
#[non_exhaustive]
/// Node error variants.
pub enum BlindSignatureError {
    #[error("An error occured when signing {0}")]
    Signing(String),

    #[error("blst error")]
    Blst(BLST_ERROR)
}

impl From<BLST_ERROR> for BlindSignatureError {
    fn from(e: BLST_ERROR) -> Self {
        Self::Blst(e)
    }
}



// impl Slip {
//     fn new(msg: Vec<u8>) -> Self {
//         Self {
//             msg,
//         }
//     }

//     fn place_in_envelope(self) -> Envelope {


//     }

//     fn combine_signature_shares(Vec<SignatureShare>) -> Signature

//     fn verify_signature(sig) -> Result<()>
// }

pub struct SlipPreparer {
    dst: Vec<u8>,
    blinding_factor: blst_scalar,
}

impl SlipPreparer {

    pub fn new() -> Self {

        let r_bytes = b"11111111111111111111111111111111"; // non-random for now.
        let r = blst_scalar { b: *r_bytes };

        Self {
            dst: b"My-DST".to_vec(),
            blinding_factor: r,
        }
    }

    pub fn blinding_factor(&self) -> blst_scalar {
        self.blinding_factor.clone()
    }

    pub fn place_slip_in_envelope(&self, slip: Slip) -> Envelope {

        let mut hash: blst_p2 = Default::default();
        let aug = b"";
        unsafe {
            blst::blst_hash_to_g2(
                &mut hash,
                slip.as_ptr(),
                slip.len(),
                self.dst.as_ptr(),
                self.dst.len(),
                aug.as_ptr(),
                aug.len(),
            )
        };

        let mut sig: blst_p2 = Default::default();
        unsafe { blst::blst_sign_pk_in_g1(&mut sig, &hash, &self.blinding_factor) };
        let mut slip_blinded: Vec<u8> = vec![0; 192];
        unsafe { blst::blst_p2_serialize(&mut slip_blinded[0], &sig) };

        slip_blinded
    }

    pub fn verify_slip_signature(&self, slip: &Slip, sig_share: SignatureShare, pk: &PublicKey) -> Result<()> {
        verify_signature(slip, &self.dst, sig_share, pk)
    }

}

pub type Envelope = Vec<u8>;

pub struct SignedEnvelopeShare {
    envelope: Envelope,
    sig_share: [u8; 192],
}

impl SignedEnvelopeShare {
    pub fn signature_share_for_envelope(&self) -> Result<SignatureShare> {
        SignatureShare::deserialize(&self.sig_share).map_err(|e| Error::from(e))
    }

    pub fn signature_share_for_slip(&self, blinding_factor: blst_scalar) -> Result<SignatureShare> {

        let mut mint_sig_affine: blst_p2_affine = Default::default();
        let rc = unsafe { blst::blst_p2_deserialize(&mut mint_sig_affine, &self.sig_share[0]) };
        assert_eq!(rc, BLST_ERROR::BLST_SUCCESS);

        let mut mint_sig_user_copy: blst_p2 = Default::default();
        unsafe { blst::blst_p2_from_affine(&mut mint_sig_user_copy, &mint_sig_affine) };

        let mut r_fr: blst_fr = Default::default();
        unsafe { blst::blst_fr_from_scalar(&mut r_fr, &blinding_factor) };

        let mut r_inverse_fr: blst_fr = Default::default();
        unsafe { blst::blst_fr_inverse(&mut r_inverse_fr, &r_fr) };

        let mut r_inverse: blst_scalar = Default::default();
        unsafe { blst::blst_scalar_from_fr(&mut r_inverse, &r_inverse_fr) };

        let mut signature: blst_p2 = Default::default();
        unsafe { blst::blst_sign_pk_in_g1(&mut signature, &mint_sig_user_copy, &r_inverse) };

        let mut sig_inverse = vec![0; 192];
        unsafe { blst::blst_p2_serialize(&mut sig_inverse[0], &signature) };

//        println!("signature_inverse: {:?}", sig_inverse);

        let s = Signature::deserialize(&sig_inverse)?;
        Ok(s)
    }

}



// User:

//     fn create_slip(msg) -> Slip

//     fn random_blinding_factor() -> blst_scalar

//     fn place_slip_in_envelope(slip, r) -> Envelope

//     fn slip_signature_share(signed_envelope) -> (SignatureShare)

//     fn combine_slip_signature_shares(shares) -> Signature

//     fn verify_slip_signature(signature, mint_pk) -> Result<()>





#[derive(Default)]
pub struct BlindSigner {
    sk: SecretKey,
}

impl BlindSigner {
    pub fn new() -> BlindSigner {

        let ikm = b"********************************"; // non-random for now.
        let ki = b"";
        let sk = SecretKey::key_gen(ikm, ki).unwrap();

        Self {
            sk
        }
    }

    pub fn public_key(&self) -> PublicKey {
        self.sk.sk_to_pk()
    }

    pub fn sk_bendian(&self) -> blst_scalar {
        let sk_scalar = blst_scalar {
            b: self.sk.to_bytes(),
        };

        let mut sk_be: [u8; 32] = Default::default();
        unsafe { blst::blst_bendian_from_scalar(&mut sk_be[0], &sk_scalar) };
        blst_scalar { b: sk_be }
    }

    pub fn sign_envelope(&self, e: Envelope) -> Result<SignedEnvelopeShare> {
        let mut user_sig_affine: blst_p2_affine = Default::default();
        let rc = unsafe { blst::blst_p2_deserialize(&mut user_sig_affine, &e[0]) };
        assert_eq!(rc, BLST_ERROR::BLST_SUCCESS);

        let mut user_sig: blst_p2 = Default::default();
        unsafe { blst::blst_p2_from_affine(&mut user_sig, &user_sig_affine) };

        // note: we sign with bigendian sk
        let mut mint_sig: blst_p2 = Default::default();
        unsafe { blst::blst_sign_pk_in_g1(&mut mint_sig, &user_sig, &self.sk_bendian()) };

        let mut sig_share_for_wire = vec![0; 192];
        unsafe { blst::blst_p2_serialize(&mut sig_share_for_wire[0], &mint_sig) };

        let signed_envelope = SignedEnvelopeShare {
            envelope: e,
            sig_share: sig_share_for_wire.try_into().unwrap(),
        };
        // println!("mint_sig_for_wire: {:?}", mint_sig_for_wire);

        Ok(signed_envelope)
    }
}


//    fn verify_signature(data, sig_shares: Vec<SignatureShare>, pk: PublicKey) -> Result<()> {  // data can be Envelope or Slip
fn verify_signature(data: &[u8], dst: &[u8], sig_share: SignatureShare, pk: &PublicKey) -> Result<()> {  // data can be Envelope or Slip

    let pk_affine = pk_rust_to_affine(pk);
    let sig_bytes = sig_share.serialize();

    let mut sig_affine: blst_p2_affine = Default::default();
    unsafe { blst::blst_p2_deserialize(&mut sig_affine, sig_bytes.as_ptr()) };

    println!("sig_affine: {:?}", sig_affine);

    let mut ctx = Pairing::new(true, dst);
    println!("data: {:?}", data);
    let rc = ctx.aggregate(&pk_affine, true, &sig_affine, true, data, &[]);
    assert_eq!(rc, BLST_ERROR::BLST_SUCCESS);
    ctx.commit();

    if !ctx.finalverify(None) {
        panic!("disaster");
    }

    println!("OK - client verified mint's blind sig");

    Ok(())
}

fn pk_rust_to_affine(pk: &PublicKey) -> blst_p1_affine {
    let pk_bytes = pk.serialize();

    let mut pk_affine: blst_p1_affine = Default::default();
    unsafe { blst::blst_p1_deserialize(&mut pk_affine, pk_bytes.as_ptr()) };

    pk_affine
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_signer() -> Result<()> {
        let official = BlindSigner::new();

        let voter = SlipPreparer::new();
        let slip: Slip = b"I vote for mickey mouse".to_vec();
        let envelope = voter.place_slip_in_envelope(slip.clone());

        let signed_envelope = official.sign_envelope(envelope)?;

        let slip_sig_share = signed_envelope.signature_share_for_slip(voter.blinding_factor())?;
        let result = voter.verify_slip_signature(&slip, slip_sig_share, &official.public_key());

        assert!(result.is_ok());

        Ok(())

        // todo: official needs to receive the unblinded slip and verify it
        // has the official's signature.
    }
}
