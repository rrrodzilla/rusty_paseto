use thiserror::Error;

/// Potential errors from attempting to build a token claim
#[derive(Debug, Error)]
pub enum PasetoError {
  #[error("A cipher error occurred")]
  PasetoCipherError(Box<PasetoError>),
  #[error("An unspecified cryption error occured")]
  Cryption,
  #[error("Could not assemble final signature.")]
  Signature,
  #[error("An unspecified cipher error occurred")]
  Cipher {
    #[from]
    source: ring::error::Unspecified,
  },
  #[error("An unspecified cipher error occurred")]
  RsaCipher {
    #[from]
    source: ed25519_dalek::ed25519::Error,
  },
  #[error("The token signature could not be verified")]
  InvalidSignature,
  #[error("This string has an incorrect number of parts and cannot be parsed into a token")]
  IncorrectSize,
  #[error("The token header is invalid")]
  WrongHeader,
  #[error("The provided footer is invalid")]
  FooterInvalid,
  #[error("A base64 decode error occurred")]
  PayloadBase64Decode {
    #[from]
    source: base64::DecodeError,
  },
  #[error("A Utf8 parsing error occurred")]
  Utf8Error {
    #[from]
    source: std::str::Utf8Error,
  },
  #[error("An unspecified cipher error occurred")]
  ChaChaCipherError,
  #[error("A Utf8 parsing error occurred")]
  Infallibale {
    #[from]
    source: std::convert::Infallible,
  },
  #[error("A Utf8 parsing error occurred")]
  FromUtf8Error {
    #[from]
    source: std::string::FromUtf8Error,
  },
}
