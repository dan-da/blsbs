use crate::error::{Error, Result};
use crate::utils::*;
use blsttc::pairing::bls12_381::{Fr, G2};
use blsttc::IntoFr;
use blsttc::{PublicKey, SecretKey, Signature};
use std::convert::TryFrom;
use std::convert::TryInto;
use std::hash::{Hash, Hasher};

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

    pub fn from_fr<V: IntoFr>(v: V) -> Self {
        Self {
            blinding_factor: into_fr(v),
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
        let msg_g2 = hash_g2_with_dst(slip);

        let blinded_msg = blind(msg_g2, self.blinding_factor);

        Envelope::from(blinded_msg)
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
//
// note: presently the Envelope does not actually hold the Slip
//       contents but only a blinded version of it.  So the
//       SlipPreparer must keep the Slip around while waiting
//       for BlindSigner response and also the Envelope metaphor
//       breaks down a little bit.
//
//       We could possibly alter this such that the envelope
//       also contains a Ciphertext of the Slip encrypted to
//       the SlipPreparer.  Then the SlipPreparer could truly
//       open the SignedEnvelope and read the Slip.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    blinded_msg: G2,
}

impl Envelope {
    /// returns the blinded message/slip.
    pub fn blinded_msg(&self) -> G2 {
        self.blinded_msg
    }

    pub fn to_bytes(&self) -> [u8; 96] {
        g2_to_be_bytes(self.blinded_msg)
    }
}

#[allow(clippy::derive_hash_xor_eq)]
impl Hash for Envelope {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let bytes = g2_to_be_bytes(self.blinded_msg);
        bytes.hash(state);
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

#[allow(clippy::from_over_into)]
impl Into<[u8; 96]> for Envelope {
    fn into(self) -> [u8; 96] {
        g2_to_be_bytes(self.blinded_msg)
    }
}

#[allow(clippy::from_over_into)]
impl Into<Vec<u8>> for Envelope {
    fn into(self) -> Vec<u8> {
        let bytes: [u8; 96] = self.into();
        bytes.to_vec()
    }
}

/// An Envelope which has a signature written
/// on it by the BlindSigner party.
///
/// This is a special envelope that is lined with
/// carbon paper, such that a signature on the envelope
/// also signs the Slip inside, even though the
/// BlindSigner party has never seen the Slip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedEnvelope {
    pub envelope: Envelope,
    signature: Signature,
}

impl SignedEnvelope {
    /// returns the signature written on Envelope
    pub fn signature_on_envelope(&self) -> &Signature {
        &self.signature
    }

    /// returns the signature written on Slip.  requires knowledge of
    /// SlipPreparer's blinding_factor.
    pub fn signature_on_slip(&self, blinding_factor: Fr) -> Result<Signature> {
        // unblind the BlindSigner's sig
        let blinded_sig_g2 = be_bytes_to_g2(self.signature.to_bytes());
        let unblinded_sig_g2 = unblind(blinded_sig_g2, blinding_factor);

        // Convert the unblinded G2 into a Signature
        let unblinded_bytes = g2_to_be_bytes(unblinded_sig_g2);
        let unblinded_sig = Signature::from_bytes(unblinded_bytes)?;

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

    /// sign an Envelope to create a SignedEnvelope
    pub fn sign_envelope(&self, e: Envelope) -> Result<SignedEnvelope> {
        // Note we are signing a G2, not message bytes, so we can't
        // use blsttc:SecretKey.sign(msg);
        let signature = self.sk.sign_g2(e.blinded_msg());

        let signed_envelope = SignedEnvelope {
            envelope: e,
            signature,
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

/// Represents a neutral third party "expert" that can
/// verify a Signature is valid on a Slip or Envelope.
///
/// Any party can take the Slip or Envelope to the
/// SignatureExaminer for verification.
pub struct SignatureExaminer;

impl SignatureExaminer {
    /// Verifies with pk that sig is valid for slip
    #[allow(clippy::ptr_arg)]
    pub fn verify_signature_on_slip(slip: &Slip, sig: &Signature, pk: &PublicKey) -> bool {
        verify_signature_on_slip(slip, sig, pk)
    }

    /// Verifies with pk that sig is valid for envelope
    #[allow(clippy::ptr_arg)]
    pub fn verify_signature_on_envelope(
        envelope: &Envelope,
        sig: &Signature,
        pk: &PublicKey,
    ) -> bool {
        verify_signature_on_envelope(envelope, sig, pk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_signer() -> Result<()> {
        let official = BlindSigner::from(*b"*******************************-");

        let voter = SlipPreparer::from(*b"11111111111111111111111111111110");
        let slip: Slip = b"I vote for mickey mouse".to_vec();
        let envelope = voter.place_slip_in_envelope(&slip);

        // TODO consider implementing Copy for envelope?
        let signed_envelope = official.sign_envelope(envelope.clone())?;

        // check that the envelope returned to us has a valid signature on it
        // ie check the authority signed the blinded message correctly
        let envelope_sig = signed_envelope.signature_on_envelope();
        let env_sig_is_valid = SignatureExaminer::verify_signature_on_envelope(
            &envelope,
            &envelope_sig,
            &official.public_key(),
        );
        assert!(env_sig_is_valid);

        let slip_sig = signed_envelope.signature_on_slip(voter.blinding_factor())?;

        // check the signed envelope is different to the signed message
        // TODO consider if envelope_sig should be a value instead of a reference
        assert!(slip_sig != *envelope_sig);

        // check the slip signature has a valid signature from the official
        // ie check the official signature has been applied the unblinded message correctly
        let slip_sig_is_valid =
            SignatureExaminer::verify_signature_on_slip(&slip, &slip_sig, &official.public_key());
        assert!(slip_sig_is_valid);

        // nobody else can unblind the signature, only the voter
        let other_voter = SlipPreparer::from(*b"22222222222222222222222222222221");
        let bad_slip_sig = signed_envelope.signature_on_slip(other_voter.blinding_factor())?;
        let bad_slip_sig_is_valid = SignatureExaminer::verify_signature_on_slip(
            &slip,
            &bad_slip_sig,
            &official.public_key(),
        );
        assert!(!bad_slip_sig_is_valid);

        Ok(())
    }
}
