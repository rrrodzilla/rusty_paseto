use crate::generic::PasetoClaimError;
use thiserror::Error;
//  /// Certain payload claims require a valid iso8601 datetime string.  This error is raised when
//  /// attempting to parse a string that does not fit the iso8601 format.
//  #[derive(Error, Debug)]
//  #[error("{0} is an invalid iso8601 string")]
//  pub struct Iso8601ParseError(String);
//  impl Iso8601ParseError {
//    pub(crate) fn new(s: &str) -> Self {
//      Self(s.to_string())
//    }
//  }

//  #[derive(Error, Debug)]
//  #[error("{0} is an invalid header for this paseto version and/or purpose")]
//  pub struct HeaderParseError(String);

//  /// Potential errors from attempting to build a token claim
//  #[derive(Debug, Error)]
//  pub enum TokenClaimError {
//    #[error("The key {0} is a reserved for use within PASETO.  To set a reserved claim, use the strong type: e.g - ExpirationClaimClaim")]
//    ReservedClaim(String),
//  }

#[derive(Debug, Error)]
pub enum GenericBuilderError {
  #[error(transparent)]
  ClaimError {
    #[from]
    source: PasetoClaimError,
  },
  #[error("{0} is an invalid iso8601 (email) string")]
  BadEmailAddress(String),
  #[error("The claim '{0}' appears more than once in the top level payload json")]
  DuplicateTopLevelPayloadClaim(String),
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
