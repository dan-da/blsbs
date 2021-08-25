# blsbs
BLS Blind Signatures

## Warning

This crate is very experimental at present, probably has serious bugs, and
should not be used for anything serious. It is unpublished for a reason.

## About

This crate implements a simple API for working with [Chaumian Blind
Signatures](https://en.wikipedia.org/wiki/Blind_signature) using [BLS
cryptography](https://en.wikipedia.org/wiki/BLS_digital_signature).
 
The API supports both single key signatures and multisig. This is based on
`SecretKeyShare` and `SignatureShare` from
[blsttc](https://github.com/maidsafe/blsttc), originally implemented in
[threshold_crypto](https://github.com/poanetwork/threshold_crypto).
 
This API embraces the metaphor of a `Slip` of paper that is enclosed in a
carbon-lined `Envelope`. The carbon lining is important because a `Signature`
written outside the `Envelope` will transfer to the `Slip` inside as well. The
`SlipPreparer` puts a message on the `Slip` and places it in the `Envelope`,
then sends it to another party, the `BlindSigner`.

The `BlindSigner` signs the outside of the `Envelope` without seeing the `Slip`
inside, then returns it to the `SlipPreparer`. The `SlipPreparer` opens the
`Envelope`, removes the `Slip`, and can then verify with the `BlindSigner`'s
public key that both the `Envelope` and the `Slip` have the `BlindSigner`'s
`Signature`. Any party with a copy of the `Slip` and `BlindSigner`'s public key
can perform this verification.
 
See Chaum's [original paper](https://www.chaum.com/publications/Chaum-blind-signatures.PDF) for a fuller discussion.
 
The multisig API extends the above metaphor with the idea that at least m
`BlindSigner` parties must sign the `Envelope` for the combined `Signature` to
be considered valid.

## Example Usage

A basic example with a single blind signer:

```
use blsbs::*;

fn main() {
    let official = BlindSigner::new();
    let voter = SlipPreparer::new();

    let slip: Slip = b"I vote for mickey mouse".to_vec();
    let envelope = voter.place_slip_in_envelope(&slip);

    let signed_envelope = official.sign_envelope(envelope)?;

    let slip_sig = signed_envelope.signature_for_slip(voter.blinding_factor())?;
    let result = voter.verify_slip_signature(&slip, &slip_sig, &official.public_key());

    assert!(result.is_ok());
}
```

see tests in src/shared.rs for examples of m-of-n usage.