use crate::error::{Error, Result};
use crate::utils::*;
use blsttc::pairing::bls12_381::{Fr, G2};
use blsttc::{PublicKey, SecretKey, Signature};
use std::convert::TryFrom;
use std::convert::TryInto;

/// Represents a paper Slip that will
/// be stuffed inside an Envelope.
pub type Slip = Vec<u8>;

/// Represents the party that creates the Slip
#[derive(Clone, Debug)]
pub struct SlipPreparer {
    blinding_factor: Fr,
}

impl SlipPreparer {
    /// creates a new SlipPreparer with a random blinding factor
    pub fn new() -> Self {
        let sk = SecretKey::random();

        Self {
            blinding_factor: fr_from_be_bytes(sk.to_bytes()),
        }
    }

    /// returns the blinding_factor used to hide the Slip in the Envelope
    pub fn blinding_factor(&self) -> Fr {
        self.blinding_factor
    }

    /// places a Slip into an opaque Envelope
    ///
    /// the message is blinded using Self::blinding_factor()
    #[allow(clippy::ptr_arg)]
    pub fn place_slip_in_envelope(&self, slip: &Slip) -> Envelope {
        let msg_g2 = hash_g2_with_dst(&slip);

        let blinded_msg = blind(msg_g2, self.blinding_factor);

        Envelope::from(blinded_msg)
    }

    /// Verifies with pk that sig is valid for slip
    #[allow(clippy::ptr_arg)]
    pub fn verify_slip_signature(
        &self,
        slip: &Slip,
        sig: &Signature,
        pk: &PublicKey,
    ) -> Result<()> {
        verify_signature(slip, sig, pk)
    }
}

impl Default for SlipPreparer {
    /// creates a new SlipPreparer with a random blinding factor
    fn default() -> Self {
        Self::new()
    }
}

impl From<[u8; 32]> for SlipPreparer {
    /// creates a new SlipPreparer from byte array with len = 32.
    fn from(b: [u8; 32]) -> Self {
        Self {
            blinding_factor: fr_from_be_bytes(b),
        }
    }
}

/// An Envelope holds a Slip inside without
/// revealing the Slip's contents.
#[derive(Clone, Debug)]
pub struct Envelope {
    blinded_msg: G2,
}

impl Envelope {
    /// returns the blinded message/slip.
    pub fn blinded_msg(&self) -> G2 {
        self.blinded_msg
    }
}

impl From<G2> for Envelope {
    /// creates Envelope from a G2
    fn from(blinded_msg: G2) -> Self {
        Self { blinded_msg }
    }
}

impl From<[u8; 96]> for Envelope {
    /// creates Envelope from byte array of len = 96
    fn from(b: [u8; 96]) -> Self {
        Self::from(be_bytes_to_g2(b))
    }
}

impl TryFrom<&[u8]> for Envelope {
    type Error = Error;

    /// creates Envelope from &[u8]
    fn try_from(b: &[u8]) -> Result<Self> {
        let bytes: [u8; 96] = b.try_into()?;
        Ok(Self::from(bytes))
    }
}

/// An Envelope which has a signature written
/// on it by the BlindSigner party.
///
/// This is a special envelope that is lined with
/// carbon paper, such that a signature on the envelope
/// also signs the Slip inside, even though the
/// BlindSigner party has never seen the Slip.
pub struct SignedEnvelope {
    pub envelope: Envelope,
    signature: Signature,
}

impl SignedEnvelope {
    /// returns the signature written on Envelope
    pub fn signature_for_envelope(&self) -> &Signature {
        &self.signature
    }

    /// returns the signature written on Slip.  requires knowledge of
    /// SlipPreparer's blinding_factor.
    pub fn signature_for_slip(&self, blinding_factor: Fr) -> Result<Signature> {
        // unblind the BlindSigner's sig
        let blinded_sig_g2 = be_bytes_to_g2(self.signature.to_bytes());
        let unblinded_sig_g2 = unblind(blinded_sig_g2, blinding_factor);

        // Convert the unblinded G2 into a Signature
        let unblinded_bytes = g2_to_be_bytes(unblinded_sig_g2);
        let unblinded_sig = Signature::from_bytes(unblinded_bytes).unwrap();

        println!("Unblinded signature: {:?}", unblinded_bytes);

        Ok(unblinded_sig)
    }
}

/// Represents the party that signs the Envelope
/// without seeing the Slip inside.
#[derive(Default)]
pub struct BlindSigner {
    sk: SecretKey,
}

impl BlindSigner {
    /// Creates a new BlindSigner with a random SecretKey
    pub fn new() -> Self {
        Self {
            sk: SecretKey::random(),
        }
    }

    /// returns the PublicKey
    pub fn public_key(&self) -> PublicKey {
        self.sk.public_key()
    }

    /// converts SecretKey to big-endian bytes.
    fn sk_bendian(&self) -> Fr {
        fr_from_be_bytes(self.sk.to_bytes())
    }

    /// sign an Envelope to create a SignedEnvelope
    pub fn sign_envelope(&self, e: Envelope) -> Result<SignedEnvelope> {
        // Note we are signing a G2, not message bytes, so we can't
        // use blsttc:SecretKey.sign(msg);
        let bs_sig_g2 = sign_g2(e.blinded_msg(), self.sk_bendian());

        // return bs sig on the wire
        let bs_sig_bytes = g2_to_be_bytes(bs_sig_g2);
        println!(
            "BlindSigner's signature of blinded message: {:?}",
            bs_sig_bytes
        );

        let signed_envelope = SignedEnvelope {
            envelope: e,
            signature: Signature::from_bytes(bs_sig_bytes)?,
        };

        Ok(signed_envelope)
    }
}

impl From<[u8; 32]> for BlindSigner {
    /// creates a BlindSigner from byte array of len = 32
    fn from(b: [u8; 32]) -> Self {
        let sk = SecretKey::from_bytes(b).unwrap();
        Self { sk }
    }
}

impl From<SecretKey> for BlindSigner {
    /// creates a BlindSigner from a SecretKey
    fn from(sk: SecretKey) -> Self {
        Self { sk }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_signer() -> Result<()> {
        let official = BlindSigner::from(*b"********************************");

        let voter = SlipPreparer::from(*b"11111111111111111111111111111111");
        let slip: Slip = b"I vote for mickey mouse".to_vec();
        let envelope = voter.place_slip_in_envelope(&slip);

        let signed_envelope = official.sign_envelope(envelope)?;

        let slip_sig = signed_envelope.signature_for_slip(voter.blinding_factor())?;
        let result = voter.verify_slip_signature(&slip, &slip_sig, &official.public_key());

        assert!(result.is_ok());

        Ok(())

        // todo: official needs to receive the unblinded slip and verify it
        // has the official's signature.
    }
}
