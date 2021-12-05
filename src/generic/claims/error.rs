use thiserror::Error;

#[derive(Debug, Error)]
pub enum PasetoClaimError {
  #[error("This token is expired")]
  Expired,
  #[error("The token cannot be used before {0}")]
  UseBeforeAvailable(String),
  #[error("The value {0} is a malformed RFC3339 date")]
  RFC3339Date(String),
  #[error("The expected claim '{0}' was not found in the payload")]
  Missing(String),
  #[error("Could not convert claim '{0}' to the expected data type")]
  Unexpected(String),
  #[error("The claim '{0}' failed custom validation")]
  CustomValidation(String),
  #[error("The claim '{0}' failed validation.  Expected '{1}' but received '{2}'")]
  Invalid(String, String, String),
  #[error("The key {0} is a reserved for use within PASETO.  To set a reserved claim, use the strong type: e.g - ExpirationClaimClaim")]
  Reserved(String),
  #[error("{0} is an invalid iso8601 (email) string")]
  BadEmailAddress(String),
  #[error("The claim '{0}' appears more than once in the top level payload json")]
  DuplicateTopLevelPayloadClaim(String),
}
