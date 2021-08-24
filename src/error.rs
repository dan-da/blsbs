use blst::BLST_ERROR;
use blsttc::error::FromBytesError;
use std::array::TryFromSliceError;
use thiserror::Error;

/// Specialisation of `std::Result`.
pub type Result<T, E = BlindSignatureError> = std::result::Result<T, E>;
pub type Error = BlindSignatureError;

#[derive(Error, Debug)]
/// error variants.
pub enum BlindSignatureError {
    #[error("An error occured when signing {0}")]
    Signing(String),

    #[error("blst error")]
    Blst(BLST_ERROR),

    #[error("deserialization from bytes failed")]
    BlsttcFromBytes(#[from] FromBytesError),

    #[error("deserialization from bytes failed")]
    InvalidBytes(#[from] TryFromSliceError),
}

impl From<BLST_ERROR> for BlindSignatureError {
    fn from(e: BLST_ERROR) -> Self {
        Self::Blst(e)
    }
}
