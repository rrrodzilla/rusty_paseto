use std::array::TryFromSliceError;
use thiserror::Error;

/// Potential errors from attempting to build a token claim
#[derive(Debug, Error)]
pub enum PasetoError {
  ///A general, unspecified (for security reasons) cipher error
  #[error("A cipher error occurred")]
  PasetoCipherError(Box<PasetoError>),
  ///A general, unspecified (for security reasons) cipher error
  #[error("An unspecified cryption error occured")]
  Cryption,
  ///A problem generating a signature
  #[error("Key was not in the correct format")]
  InvalidKey,
  ///A problem generating a signature
  #[error("Could not assemble final signature.")]
  Signature,
  /// Occurs when a private RSA key is not in pkcs#8 format
  #[error("A private RSA key was not in the correct format")]
  KeyRejected {
    ///Surfaces key rejection errors from ring
    #[from]
    source: ring::error::KeyRejected,
  },
  ///A general, unspecified (for security reasons) cipher error
  #[error("An unspecified cipher error occurred")]
  Cipher {
    ///Surfaces unspecified errors from ring
    #[from]
    source: ring::error::Unspecified,
  },
  #[cfg(feature = "ed25519-dalek")]
  ///An RSA cipher error
  #[error("An unspecified cipher error occurred")]
  RsaCipher {
    ///An RSA cipher error
    #[from]
    source: ed25519_dalek::ed25519::Error,
  },
  #[cfg(feature = "p384")]
  ///An ECSDA cipher error
  #[error("An unspecified ECSDA error occurred")]
  ECSDAError {
    ///An ECSDA cipher error
    #[from]
    source: p384::ecdsa::Error,
  },
  #[cfg(feature = "blake2")]
  ///An RSA cipher error
  #[error("An unspecified cipher error occurred")]
  InvalidLength {
    ///An RSA cipher error
    #[from]
    source: blake2::digest::InvalidLength,
  },
  ///Occurs when a signature fails verification
  #[error("The token signature could not be verified")]
  InvalidSignature,
  #[error("A slice conversion error occurred")]
  TryFromSlice {
    ///Surfaces errors from slice conversion attempts
    #[from]
    source: TryFromSliceError,
  },
  ///Occurs when an untrusted token string is unable to be parsed into its constituent parts
  #[error("This string has an incorrect number of parts and cannot be parsed into a token")]
  IncorrectSize,
  ///Occurs when an incorrect header is provided on an untrusted token string
  #[error("The token header is invalid")]
  WrongHeader,
  ///Occurs when an incorrect footer was passed in an attempt to parse an untrusted token string
  #[error("The provided footer is invalid")]
  FooterInvalid,
  ///Occurs when a base64 encoded payload cannot be decoded
  #[error("A base64 decode error occurred")]
  PayloadBase64Decode {
    ///Surfaced from the base64 crate
    #[from]
    source: base64::DecodeError,
  },
  ///Occurs when a string fails parsing as Utf8
  #[error("A Utf8 parsing error occurred")]
  Utf8Error {
    ///Surfaced from std::str::Utf8
    #[from]
    source: std::str::Utf8Error,
  },
  ///A cipher error from the ChaCha algorithm
  #[error("An unspecified cipher error occurred")]
  ChaChaCipherError,
  ///An infallible error
  #[error("A Utf8 parsing error occurred")]
  Infallibale {
    ///An infallible error
    #[from]
    source: std::convert::Infallible,
  },
  ///Occurs when a string fails conversion from Utf8
  #[error("A Utf8 parsing error occurred")]
  FromUtf8Error {
    ///Surfaced from std::string::FromUtf8Error
    #[from]
    source: std::string::FromUtf8Error,
  },
}
