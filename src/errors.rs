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
