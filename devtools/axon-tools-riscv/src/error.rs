use alloc::string::{String, ToString};

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub enum Error {
    InvalidProofBlockHash,
    NotEnoughSignatures,
    VerifyMptProof,

    #[cfg(feature = "proof")]
    Bls(blst::BLST_ERROR),
}

#[cfg(feature = "proof")]
impl From<blst::BLST_ERROR> for Error {
    fn from(e: blst::BLST_ERROR) -> Self {
        Self::Bls(e)
    }
}

impl ToString for Error {
    fn to_string(&self) -> String {
        match self {
            Error::InvalidProofBlockHash => "Invalid proof block hash".to_string(),
            Error::NotEnoughSignatures => "Not enough signatures".to_string(),
            Error::VerifyMptProof => "Verify mpt proof".to_string(),
            #[cfg(feature = "proof")]
            Error::Bls(e) => alloc::format!("Bls error: {:?}", e),
        }
    }
}
