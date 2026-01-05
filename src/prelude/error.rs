use thiserror::Error;

/// Errors from validating claims in a parsed token
///
/// # Deprecated
///
/// This error type is deprecated. Use [`rusty_paseto::Error`](crate::Error) instead for new code.
/// It will be removed in a future major version.
#[deprecated(
  since = "0.10.0",
  note = "Use rusty_paseto::Error instead. This type has design issues and will be removed."
)]
#[derive(Debug, Error)]
pub enum GeneralPasetoError {
  /// An infallible error (included for From implementation completeness)
  #[error("An infallible error occurred")]
  Infallible {
    /// An infallible error
    #[from]
    source: std::convert::Infallible,
  },
  /// An error with the data format
  #[error(transparent)]
  RFC3339Date(#[from] time::error::Format),
}
