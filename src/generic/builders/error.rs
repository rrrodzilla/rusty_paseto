use crate::generic::PasetoClaimError;
use thiserror::Error;
/// Errors raised by the generic builder when adding claims or encrypting or signing PASETO tokens.
#[derive(Debug, Error)]
pub enum GenericBuilderError {
  /// A generic claim error
  #[error(transparent)]
  ClaimError {
    #[from]
    source: PasetoClaimError,
  },
  ///An error with a invalid malformed iso8601 email address
  #[error("{0} is an invalid iso8601 (email) string")]
  BadEmailAddress(String),
  ///An error indicating a duplicate top level claim in the token
  #[error("The claim '{0}' appears more than once in the top level payload json")]
  DuplicateTopLevelPayloadClaim(String),
  ///A generic cipher error
  #[error("A paseto cipher error occurred")]
  CipherError {
    #[from]
    source: crate::core::PasetoError,
  },
  ///A JSON serialization error with the token payload
  #[error("The payload was unable to be serialized into json")]
  PayloadJsonError {
    #[from]
    source: serde_json::Error,
  },
}
