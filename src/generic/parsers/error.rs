use crate::generic::claims::PasetoClaimError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GenericParserError {
  #[error(transparent)]
  ClaimError {
    #[from]
    source: PasetoClaimError,
  },
  #[error("A paseto cipher error occurred")]
  CipherError {
    #[from]
    source: crate::core::PasetoError,
  },
  #[error("The payload was unable to be serialized into json")]
  PayloadJsonError {
    #[from]
    source: serde_json::Error,
  },
}
