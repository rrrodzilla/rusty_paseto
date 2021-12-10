use thiserror::Error;

/// Errors from validating claims in a parsed token
#[derive(Debug, Error)]
pub enum PasetoClaimError {
  /// Occurs during an attempt to parse an expired token
  #[error("This token is expired")]
  Expired,
  /// Occurs during an attempt to parse a token before its Not Before claim time
  #[error("The token cannot be used before {0}")]
  UseBeforeAvailable(String),
  /// Occurs if a date time is passed that is not a valid RFC3339 date - "2019-01-01T00:00:00+00:00"
  #[error("The value {0} is a malformed RFC3339 date")]
  RFC3339Date(String),
  /// Occurs if a claim was expected but wasn't found in the payload
  #[error("The expected claim '{0}' was not found in the payload")]
  Missing(String),
  /// Occurs during claim validation if a claim value was unable to be converted to its expected type
  #[error("Could not convert claim '{0}' to the expected data type")]
  Unexpected(String),
  /// Occurs when a custom claim fails validation
  #[error("The claim '{0}' failed custom validation")]
  CustomValidation(String),
  /// Occurs when a claim fails validation
  #[error("The claim '{0}' failed validation.  Expected '{1}' but received '{2}'")]
  Invalid(String, String, String),
  /// Occurs when a user attempts to create a custom claim using a reserved claim key
  #[error("The key {0} is a reserved for use within PASETO.  To set a reserved claim, use the strong type: e.g - ExpirationClaimClaim")]
  Reserved(String),
  /// Occurs when a user attempts to use a top level claim more than once in the payload
  #[error("The claim '{0}' appears more than once in the top level payload json")]
  DuplicateTopLevelPayloadClaim(String),
}
