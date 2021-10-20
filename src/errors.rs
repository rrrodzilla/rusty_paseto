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

/// Potential errors from attempting to build a token claim
#[derive(Debug, Error)]
pub enum TokenClaimError {
  #[error("The key {0} is a reserved for use within PASETO.  To set a reserved claim, use the strong type: e.g - ExpirationClaimClaim")]
  ReservedClaim(String),
}

/// Potential errors from attempting to build a v2 local token
#[derive(Debug, Error)]
pub enum TokenBuilderError {
  #[error("The payload was unable to be serialized into json")]
  PayloadJsonError {
    #[from]
    source: serde_json::Error,
  },
}

/// Potential errors from attempting to parse a token string
#[derive(Debug, Error)]
pub enum PasetoTokenParseError {
  #[error("This string has an incorrect number of parts and cannot be parsed into a token")]
  IncorrectSize,
  #[error("The token header is invalid")]
  WrongHeader,
  #[error("The provided footer is invalid")]
  FooterInvalid,
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
}
