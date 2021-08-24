use crate::Result;
use blst::{blst_hash_to_g2, blst_p2, blst_p2_compress};
use blsttc::ff::{Field, PrimeField}; // for Fr trait
use blsttc::group::{CurveAffine, CurveProjective, EncodedPoint};
use blsttc::pairing::bls12_381::{Fr, FrRepr, G2Affine, G2};
use blsttc::{PublicKey, Signature};
use std::borrow::Borrow;

pub(crate) fn verify_signature(data: &[u8], sig: &Signature, pk: &PublicKey) -> Result<()> {
    // data can be Envelope or Slip

    let data_g2 = hash_g2_with_dst(data);

    // confirm the signature and message verify using the blind-signer's public key
    // ie the blind-signer has signed the message without knowing the message
    let verified = pk.verify_g2(sig, data_g2);
    println!("Msg verified using blind_signer_pk: {:?}", verified);

    assert!(verified);

    Ok(())
}

// blst equivalent of threshold_crypto pub(crate) fn hash_g2
// maybe we should add tis to blsttc lib.rs?
pub(crate) fn hash_g2_with_dst(msg: &[u8]) -> G2 {
    let mut msg_hash: blst_p2 = Default::default();
    let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
    let aug = b"";
    unsafe {
        blst_hash_to_g2(
            &mut msg_hash,
            msg.as_ptr(),
            msg.len(),
            dst.as_ptr(),
            dst.len(),
            aug.as_ptr(),
            aug.len(),
        )
    };
    let mut msg_g2_bytes = [0u8; 96];
    unsafe { blst_p2_compress(&mut msg_g2_bytes[0], &msg_hash) }
    be_bytes_to_g2(msg_g2_bytes)
}

// see blsttc util.rs
pub(crate) fn fr_from_be_bytes(bytes: [u8; 32]) -> Fr {
    let mut le_bytes = bytes;
    le_bytes.reverse();
    let mut fr_u64s = [0u64; 4];
    for i in 0..4 {
        let mut next_u64_bytes = [0u8; 8];
        for j in 0..8 {
            next_u64_bytes[j] = le_bytes[i * 8 + j];
        }
        fr_u64s[i] = u64::from_le_bytes(next_u64_bytes);
    }
    Fr::from_repr(FrRepr(fr_u64s)).unwrap()
}

// y = x * r
pub(crate) fn blind(g2: G2, r: Fr) -> G2 {
    g2.into_affine().mul(r)
}

// x = y * 1/r
pub(crate) fn unblind(g2: G2, r: Fr) -> G2 {
    g2.into_affine().mul(r.inverse().unwrap())
}

// see blsttc Signature from_bytes
pub(crate) fn be_bytes_to_g2(bytes: [u8; 96]) -> G2 {
    let mut compressed: <G2Affine as CurveAffine>::Compressed = EncodedPoint::empty();
    compressed.as_mut().copy_from_slice(bytes.borrow());
    let opt_affine = compressed.into_affine().ok();
    opt_affine.unwrap().into_projective()
}

// see blsttc Signature to_bytes
pub(crate) fn g2_to_be_bytes(g2: G2) -> [u8; 96] {
    let mut bytes = [0u8; 96];
    bytes.copy_from_slice(g2.into_affine().into_compressed().as_ref());
    bytes
}

// This is not equivalent to blst::secret_key::sign because
// that does the hash_into_g2 which we have already done to get
// see blsttc libs.rs SecretKey.sign_g2
pub(crate) fn sign_g2(g2: G2, sk: Fr) -> G2 {
    g2.into_affine().mul(sk)
}
