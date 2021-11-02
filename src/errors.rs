use thiserror::Error;

/// Certain payload claims require a valid iso8601 datetime string.  This error is raised when
/// attempting to parse a string that does not fit the iso8601 format.
#[derive(Error, Debug)]
#[error("{0} is an invalid iso8601 string")]
pub struct Iso8601ParseError(String);
impl Iso8601ParseError {
  pub(crate) fn new(s: &str) -> Self {
    Self(s.to_string())
  }
}

#[derive(Error, Debug)]
#[error("{0} is an invalid header for this paseto version and/or purpose")]
pub struct HeaderParseError(String);
impl HeaderParseError {
  pub(crate) fn new(s: &str) -> Self {
    Self(s.to_string())
  }
}

/// Potential errors from attempting to build a token claim
#[derive(Debug, Error)]
pub enum TokenClaimError {
  #[error("The key {0} is a reserved for use within PASETO.  To set a reserved claim, use the strong type: e.g - ExpirationClaimClaim")]
  ReservedClaim(String),
}

#[derive(Debug, Error)]
pub enum GenericTokenBuilderError {
  #[error("Use of a reserved PASETO claim key")]
  TokenClaimError {
    #[from]
    source: crate::errors::TokenClaimError,
  },
  #[error("Invalid iso8601 string")]
  Iso8601ParseError {
    #[from]
    source: crate::errors::Iso8601ParseError,
  },
  #[error("The claim '{0}' appears more than once in the top level payload json")]
  DuplicateTopLevelPayloadClaim(String),
  #[error("The payload was unable to be serialized into json")]
  PayloadJsonError {
    #[from]
    source: serde_json::Error,
  },
}

/// Potential errors from attempting to parse a token string
#[derive(Debug, Error)]
pub enum PasetoTokenParseError {
  #[error("The token signature could not be verified")]
  InvalidSignature,
  #[error("The token is not available for use before {0}")]
  UseBeforeAvailable(String),
  #[error("The token has expired")]
  ExpiredToken,
  #[error("The claim {0} was not the expected type")]
  InvalidClaimValueType(String),
  #[error("The claim {0} failed downcasting")]
  DowncastClaim(String),
  #[error("A custom claim validator for claim '{0}' failed for value '{1}'")]
  CustomClaimValidation(String, String),
  #[error("The claim '{0}' failed validation")]
  InvalidClaim(String),
  #[error("This string has an incorrect number of parts and cannot be parsed into a token")]
  IncorrectSize,
  #[error("The token header is invalid")]
  WrongHeader,
  #[error("The provided footer is invalid")]
  FooterInvalid,
  #[error("An invalid date was found during token parsing")]
  InvalidDate,
  #[error("Couldn't deserialize payload into json with serde")]
  PayloadJson {
    #[from]
    source: serde_json::Error,
  },
  #[error("Couldn't decode the payload before encryption")]
  PayloadDecode {
    #[from]
    source: base64::DecodeError,
  },
  #[error("This error can never happen")]
  Infallible {
    #[from]
    source: std::convert::Infallible,
  },
  #[error("Couldn't decrypt payload")]
  Decrypt,
  #[error("Invalid token signature")]
  InvalidSignatureParse {
    #[from]
    source: ed25519_dalek::ed25519::Error,
  },
}
