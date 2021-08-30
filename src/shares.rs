use crate::error::Result;
use crate::utils::*;
use crate::Envelope;
use blsttc::pairing::bls12_381::Fr;
use blsttc::IntoFr;
use blsttc::{PublicKey, PublicKeySet, SecretKeyShare, SignatureShare};

/// Represents a single signature on an Envelope
/// that requires muliple signatures by multiple
/// BlindSigner parties.
///
/// These signature shares must be combined together
/// to form a complete Signature on the Envelope
/// as well as on the Slip inside.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedEnvelopeShare {
    pub envelope: Envelope,
    sig_share: SignatureShare,
    sig_share_index: Fr,
}

impl SignedEnvelopeShare {
    /// Creates a new SignedEnvelopeShare from a given Envelope, SignatureShare, and Share Index.
    pub fn new<T: IntoFr>(
        envelope: Envelope,
        sig_share: SignatureShare,
        sig_share_index: T,
    ) -> Self {
        Self {
            envelope,
            sig_share,
            sig_share_index: into_fr(sig_share_index),
        }
    }

    /// returns the SignatureShare written on Envelope
    pub fn signature_share_for_envelope(&self) -> &SignatureShare {
        &self.sig_share
    }

    pub fn signature_share_for_envelope_with_index(&self) -> (Fr, &SignatureShare) {
        (self.sig_share_index, &self.sig_share)
    }

    pub fn signature_share_index(&self) -> Fr {
        self.sig_share_index
    }

    /// returns the SignatureShare written on Slip.  requires knowledge of
    /// SlipPreparer's blinding_factor.
    pub fn signature_share_for_slip(&self, blinding_factor: Fr) -> Result<SignatureShare> {
        // unblind the BlindSigner's sig
        let blinded_sig_g2 = be_bytes_to_g2(self.sig_share.to_bytes());
        let unblinded_sig_g2 = unblind(blinded_sig_g2, blinding_factor);

        // Convert the unblinded G2 into a Signature
        let unblinded_bytes = g2_to_be_bytes(unblinded_sig_g2);
        let unblinded_sig = SignatureShare::from_bytes(unblinded_bytes).unwrap();

        Ok(unblinded_sig)
    }
}

/// Represents a single party that signs the Envelope
/// without seeing the Slip inside.
///
/// Some scenarios require require muliple signatures
/// by multiple BlindSigner parties in order to
/// create an authoritative signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlindSignerShare {
    sks: SecretKeyShare,
    sks_index: Fr,
    pks: PublicKeySet,
}

impl BlindSignerShare {
    /// Creates a new BlindSignerShare from a given SecretKeyShare and PublicKeySet
    pub fn new<T: IntoFr>(sks: SecretKeyShare, sks_index: T, pks: PublicKeySet) -> Self {
        Self {
            sks,
            sks_index: into_fr(sks_index),
            pks,
        }
    }

    pub fn secret_key_share(&self) -> &SecretKeyShare {
        &self.sks
    }

    pub fn secret_key_share_index(&self) -> Fr {
        self.sks_index
    }

    pub fn secret_key_share_with_index(&self) -> (Fr, &SecretKeyShare) {
        (self.sks_index, &self.sks)
    }

    /// returns the PublicKeySet
    pub fn public_key_set(&self) -> &PublicKeySet {
        &self.pks
    }

    /// returns the PublicKey
    pub fn public_key(&self) -> PublicKey {
        self.pks.public_key()
    }

    /// converts SecretKey to big-endian bytes.
    fn sks_bendian(&self) -> Fr {
        fr_from_be_bytes(self.sks.to_bytes())
    }

    /// sign an Envelope to create a SignedEnvelopeShare
    pub fn sign_envelope(&self, e: Envelope) -> Result<SignedEnvelopeShare> {
        // Note we are signing a G2, not message bytes, so we can't
        // use blsttc:SecretKey.sign(msg);
        let bs_sig_g2 = sign_g2(e.blinded_msg(), self.sks_bendian());

        // return bs sig on the wire
        let bs_sig_bytes = g2_to_be_bytes(bs_sig_g2);

        let signed_envelope = SignedEnvelopeShare {
            envelope: e,
            sig_share: SignatureShare::from_bytes(bs_sig_bytes)?,
            sig_share_index: self.sks_index,
        };

        Ok(signed_envelope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SignatureExaminer, Slip, SlipPreparer};
    use blsttc::SecretKeySet;

    fn mk_secret_key_set(threshold: usize) -> SecretKeySet {
        let mut rng = rand::thread_rng();
        SecretKeySet::random(threshold, &mut rng)
    }

    #[test]
    fn m_of_n_signers() -> Result<()> {
        let num_signers = 3;
        let sks = mk_secret_key_set(num_signers - 1);

        // note: here are are staring with 1 instead of 0 to verify
        // that share indexes are working properly.
        let officials: Vec<BlindSignerShare> = (1..num_signers + 1)
            .into_iter()
            .map(|i| BlindSignerShare::new(sks.secret_key_share(&i), i, sks.public_keys()))
            .collect();

        let voter = SlipPreparer::from(*b"11111111111111111111111111111111");
        let slip: Slip = b"I vote for mickey mouse".to_vec();
        let envelope = voter.place_slip_in_envelope(&slip);

        let mut shares_owned: Vec<(Fr, SignatureShare)> = Default::default();
        //vec![(0, &slip_sig_share)];

        for o in officials.iter() {
            let signed_envelope_share = o.sign_envelope(envelope.clone())?;
            let slip_sig_share =
                signed_envelope_share.signature_share_for_slip(voter.blinding_factor())?;
            let index = signed_envelope_share.signature_share_index();
            shares_owned.push((index, slip_sig_share));
        }

        let shares: Vec<(Fr, &SignatureShare)> =
            shares_owned.iter().map(|(i, s)| (*i, s)).collect();

        let slip_sig = sks.public_keys().combine_signatures(shares).unwrap();

        let result = SignatureExaminer::verify_signature_on_slip(
            &slip,
            &slip_sig,
            &sks.public_keys().public_key(),
        );

        assert!(result);

        Ok(())
    }

    #[test]
    fn m_of_n_signers_below_threshold() -> Result<()> {
        let num_signers = 3;
        let sks = mk_secret_key_set(num_signers - 1);

        // We have one less signer than required
        let officials: Vec<BlindSignerShare> = (0..num_signers - 1)
            .into_iter()
            .map(|i| BlindSignerShare::new(sks.secret_key_share(&i), i, sks.public_keys()))
            .collect();

        let voter = SlipPreparer::from(*b"11111111111111111111111111111111");
        let slip: Slip = b"I vote for mickey mouse".to_vec();
        let envelope = voter.place_slip_in_envelope(&slip);

        let mut shares_owned: Vec<(Fr, SignatureShare)> = Default::default();

        for o in officials.iter() {
            let signed_envelope_share = o.sign_envelope(envelope.clone())?;
            let slip_sig_share =
                signed_envelope_share.signature_share_for_slip(voter.blinding_factor())?;
            let index = signed_envelope_share.signature_share_index();
            shares_owned.push((index, slip_sig_share));
        }

        let shares: Vec<(Fr, &SignatureShare)> =
            shares_owned.iter().map(|(i, s)| (*i, s)).collect();

        let result = sks.public_keys().combine_signatures(shares);

        assert_eq!(result, Err(blsttc::error::Error::NotEnoughShares));

        Ok(())
    }
}
