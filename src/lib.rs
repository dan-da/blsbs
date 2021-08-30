//! This crate implements a simple API for working with Chaumian Blind Signatures
//! using BLS cryptography.
//!
//! The API supports both single key signatures and multi-party m-of-n style
//! signatures.  This is based on the SecretKeyShare and SignatureShare
//! from the blsttc crate, originally implemented in the threshold_crypto crate.
//!
//! This API embraces the metaphor of a `Slip` of paper that is enclosed in
//! a carbon-lined envelope.  The SlipPreparer puts a message on the Slip and
//! places it in the envelope, then sends it to another party, the BlindSigner.
//! The BlindSigner signs the outside of the envelope without seeing the Slip
//! inside, then returns it to the SlipPreparer.  The SlipPreparer opens the
//! envelope, removes the slip, and can then verify with the BlindSigner's public
//! key that both the envelope and the Slip has the BlindSigner's signature.
//! Any party with a copy of the Slip and BlindSigner's public key can perform
//! this verification.
//!
//! See Chaum's original paper for a fuller discussion.
//! <https://www.chaum.com/publications/Chaum-blind-signatures.PDF>
//!
//! The m-of-n API extends the above metaphor with the idea that at least
//! m BlindSigners must sign the Envelope for the signatures to be considered
//! valid.

mod blind_sigs;
mod error;
mod shares;
mod utils;

pub use crate::blind_sigs::{
    BlindSigner, Envelope, SignatureExaminer, SignedEnvelope, Slip, SlipPreparer,
};
pub use crate::error::{Error, Result};
pub use crate::shares::{BlindSignerShare, SignedEnvelopeShare};
pub use blsttc::pairing::bls12_381::Fr;
