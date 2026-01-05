use crate::generic::claims::PasetoClaimError;
use thiserror::Error;

/// Errors raised by the generic parser when validating claims or parsing a PASETO token.
///
/// # Deprecated
///
/// This error type is deprecated. Use [`crate::Error`] instead for new code.
/// It will be removed in a future major version.
#[deprecated(
    since = "0.10.0",
    note = "Use rusty_paseto::Error instead. This type will be removed in a future major version."
)]
#[derive(Debug, Error)]
pub enum GenericParserError {
  /// An error from the existence or non-existence or validation of a claim
  #[error(transparent)]
  ClaimError {
    #[from]
    source: PasetoClaimError,
  },
  /// An error decrypting or validating a token
  #[error("A paseto cipher error occurred")]
  CipherError {
    #[from]
    source: crate::core::PasetoError,
  },
  /// A JSON deserialization error for the token payload
  #[error("The payload was unable to be serialized into json")]
  PayloadJsonError {
    #[from]
    source: serde_json::Error,
  },
}
