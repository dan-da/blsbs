pub use crate::error::{Error, Result};
use crate::utils::*;
use blsttc::pairing::bls12_381::Fr;
use blsttc::{PublicKey, SecretKey, Signature};

pub type Slip = Vec<u8>;

pub struct SlipPreparer {
    blinding_factor: Fr,
}

impl SlipPreparer {
    pub fn new() -> Self {
        let sk = SecretKey::random();

        Self {
            blinding_factor: fr_from_be_bytes(sk.to_bytes()),
        }
    }

    pub fn blinding_factor(&self) -> Fr {
        self.blinding_factor
    }

    #[allow(clippy::ptr_arg)]
    pub fn place_slip_in_envelope(&self, slip: &Slip) -> Envelope {
        let msg_g2 = hash_g2_with_dst(&slip);

        let blinded_msg = blind(msg_g2, self.blinding_factor);

        // blinded_msg_bytes (Envelope aka [u8; 96])
        g2_to_be_bytes(blinded_msg)
    }

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
    fn default() -> Self {
        Self::new()
    }
}

impl From<[u8; 32]> for SlipPreparer {
    fn from(b: [u8; 32]) -> Self {
        Self {
            blinding_factor: fr_from_be_bytes(b),
        }
    }
}

pub type Envelope = [u8; 96];

pub struct SignedEnvelope {
    envelope: Envelope,
    signature: [u8; 96],
}

impl SignedEnvelope {
    pub fn signature_for_envelope(&self) -> Result<Signature> {
        Signature::from_bytes(self.envelope).map_err(Error::from)
    }

    pub fn signature_for_slip(&self, blinding_factor: Fr) -> Result<Signature> {
        // unblind the mint sig
        let blinded_sig_g2 = be_bytes_to_g2(self.signature);
        let unblinded_sig_g2 = unblind(blinded_sig_g2, blinding_factor);

        // Convert the unblinded G2 into a Signature
        let unblinded_bytes = g2_to_be_bytes(unblinded_sig_g2);
        let unblinded_sig = Signature::from_bytes(unblinded_bytes).unwrap();

        println!("Unblinded signature: {:?}", unblinded_bytes);

        Ok(unblinded_sig)
    }
}

#[derive(Default)]
pub struct BlindSigner {
    sk: SecretKey,
}

impl BlindSigner {
    pub fn new() -> Self {
        Self {
            sk: SecretKey::random(),
        }
    }

    pub fn public_key(&self) -> PublicKey {
        self.sk.public_key()
    }

    pub fn sk_bendian(&self) -> Fr {
        fr_from_be_bytes(self.sk.to_bytes())
    }

    pub fn sign_envelope(&self, e: Envelope) -> Result<SignedEnvelope> {
        let blinded_msg_g2 = be_bytes_to_g2(e);

        // Note we are signing a G2, not message bytes, so we can't
        // use blsttc:SecretKey.sign(msg);
        let mint_sig_g2 = sign_g2(blinded_msg_g2, self.sk_bendian());

        // return mint sig on the wire
        let mint_sig_bytes = g2_to_be_bytes(mint_sig_g2);
        println!("Mint signature of blinded message: {:?}", mint_sig_bytes);

        let signed_envelope = SignedEnvelope {
            envelope: e,
            signature: mint_sig_bytes,
        };

        Ok(signed_envelope)
    }
}

impl From<[u8; 32]> for BlindSigner {
    fn from(b: [u8; 32]) -> Self {
        let sk = SecretKey::from_bytes(b).unwrap();
        Self { sk }
    }
}

impl From<SecretKey> for BlindSigner {
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
