use thiserror::Error;

/// Errors from validating claims in a parsed token
#[derive(Debug, Error)]
pub enum GeneralPasetoError {
  ///A general, unspecified paseto error
  #[error("A general paseto error occurred")]
  PasetoError(Box<GeneralPasetoError>),
  #[error("An infallible error occurred")]
  Infallible {
    ///An infallible error
    #[from]
    source: std::convert::Infallible,
  },
  ///An error with the data format
  #[error(transparent)]
  RFC3339Date(#[from] time::error::Format),
}
