use crate::error::Result;
use crate::utils::*;
use crate::Envelope;
use blsttc::pairing::bls12_381::Fr;
use blsttc::{PublicKey, SecretKeyShare, SignatureShare};

/// Represents a single signature on an Envelope
/// that requires muliple signatures by multiple
/// BlindSigner parties.
///
/// These signature shares must be combined together
/// to form a complete Signature on the Envelope
/// as well as on the Slip inside.
pub struct SignedEnvelopeShare {
    pub envelope: Envelope,
    sig_share: SignatureShare,
}

impl SignedEnvelopeShare {
    pub fn signature_share_for_envelope(&self) -> &SignatureShare {
        &self.sig_share
    }

    pub fn signature_share_for_slip(&self, blinding_factor: Fr) -> Result<SignatureShare> {
        // unblind the BlindSigner's sig
        let blinded_sig_g2 = be_bytes_to_g2(self.sig_share.to_bytes());
        let unblinded_sig_g2 = unblind(blinded_sig_g2, blinding_factor);

        // Convert the unblinded G2 into a Signature
        let unblinded_bytes = g2_to_be_bytes(unblinded_sig_g2);
        let unblinded_sig = SignatureShare::from_bytes(unblinded_bytes).unwrap();

        println!("Unblinded signature: {:?}", unblinded_bytes);

        Ok(unblinded_sig)
    }
}

/// Represents a single party that signs the Envelope
/// without seeing the Slip inside.
///
/// Some scenarios require require muliple signatures
/// by multiple BlindSigner parties in order to
/// create an authoritative signature.
pub struct BlindSignerShare {
    sks: SecretKeyShare,
    pk: PublicKey,
}

impl BlindSignerShare {
    pub fn new(sks: SecretKeyShare, pk: PublicKey) -> Self {
        Self { sks, pk }
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.pk
    }

    pub fn sks_bendian(&self) -> Fr {
        fr_from_be_bytes(self.sks.to_bytes())
    }

    pub fn sign_envelope(&self, e: Envelope) -> Result<SignedEnvelopeShare> {
        // Note we are signing a G2, not message bytes, so we can't
        // use blsttc:SecretKey.sign(msg);
        let bs_sig_g2 = sign_g2(e.blinded_msg(), self.sks_bendian());

        // return bs sig on the wire
        let bs_sig_bytes = g2_to_be_bytes(bs_sig_g2);
        println!(
            "BlindSigner's signature of blinded message: {:?}",
            bs_sig_bytes
        );

        let signed_envelope = SignedEnvelopeShare {
            envelope: e,
            sig_share: SignatureShare::from_bytes(bs_sig_bytes)?,
        };

        Ok(signed_envelope)
    }
}

impl From<(SecretKeyShare, PublicKey)> for BlindSignerShare {
    fn from(t: (SecretKeyShare, PublicKey)) -> Self {
        Self { sks: t.0, pk: t.1 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Slip, SlipPreparer};
    use blsttc::SecretKeySet;

    fn mk_secret_key_set(threshold: usize) -> SecretKeySet {
        let mut rng = rand::thread_rng();
        SecretKeySet::random(threshold, &mut rng)
    }

    #[test]
    fn m_of_n_signers() -> Result<()> {
        let num_signers = 3;
        let sks = mk_secret_key_set(num_signers - 1);

        let officials: Vec<BlindSignerShare> = (0..num_signers)
            .into_iter()
            .map(|i| {
                BlindSignerShare::new(sks.secret_key_share(&i), sks.public_keys().public_key())
            })
            .collect();

        let voter = SlipPreparer::from(*b"11111111111111111111111111111111");
        let slip: Slip = b"I vote for mickey mouse".to_vec();
        let envelope = voter.place_slip_in_envelope(&slip);

        let mut shares_owned: Vec<SignatureShare> = Default::default();
        //vec![(0, &slip_sig_share)];

        for o in officials.iter() {
            let signed_envelope_share = o.sign_envelope(envelope.clone())?;
            let slip_sig_share =
                signed_envelope_share.signature_share_for_slip(voter.blinding_factor())?;
            shares_owned.push(slip_sig_share);
        }

        let shares: Vec<(usize, &SignatureShare)> = shares_owned
            .iter()
            .enumerate()
            .map(|(i, s)| (i, s))
            .collect();

        let slip_sig = sks.public_keys().combine_signatures(shares).unwrap();

        let result = voter.verify_slip_signature(&slip, &slip_sig, &sks.public_keys().public_key());

        assert!(result.is_ok());

        Ok(())
    }

    #[test]
    fn m_of_n_signers_below_threshold() -> Result<()> {
        let num_signers = 3;
        let sks = mk_secret_key_set(num_signers - 1);

        // We have one less signer than required
        let officials: Vec<BlindSignerShare> = (0..num_signers - 1)
            .into_iter()
            .map(|i| {
                BlindSignerShare::new(sks.secret_key_share(&i), sks.public_keys().public_key())
            })
            .collect();

        let voter = SlipPreparer::from(*b"11111111111111111111111111111111");
        let slip: Slip = b"I vote for mickey mouse".to_vec();
        let envelope = voter.place_slip_in_envelope(&slip);

        let mut shares_owned: Vec<SignatureShare> = Default::default();

        for o in officials.iter() {
            let signed_envelope_share = o.sign_envelope(envelope.clone())?;
            let slip_sig_share =
                signed_envelope_share.signature_share_for_slip(voter.blinding_factor())?;
            shares_owned.push(slip_sig_share);
        }

        let shares: Vec<(usize, &SignatureShare)> = shares_owned
            .iter()
            .enumerate()
            .map(|(i, s)| (i, s))
            .collect();

        let result = sks.public_keys().combine_signatures(shares);

        assert_eq!(result, Err(blsttc::error::Error::NotEnoughShares));

        Ok(())
    }
}
