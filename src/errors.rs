use thiserror::Error;

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
