use serde_json::Value;
use std::collections::HashMap;

mod audience_claim;
mod custom_claim;
mod error;
mod expiration_claim;
mod issued_at_claim;
mod issuer_claim;
mod not_before_claim;
mod subject_claim;
mod token_identifier_claim;
mod traits;

pub use audience_claim::AudienceClaim;
pub use custom_claim::CustomClaim;
pub use error::PasetoClaimError;
pub use expiration_claim::ExpirationClaim;
pub use issued_at_claim::IssuedAtClaim;
pub use issuer_claim::IssuerClaim;
pub use not_before_claim::NotBeforeClaim;
pub use subject_claim::SubjectClaim;
pub use token_identifier_claim::TokenIdentifierClaim;
pub use traits::PasetoClaim;
///A type for creating generic claim validation functions
pub type ValidatorFn = dyn Fn(&str, &Value) -> Result<(), PasetoClaimError>;
///A type for tracking claims in a token
pub type ValidatorMap = HashMap<String, Box<ValidatorFn>>;

#[cfg(test)]
mod unit_tests {
  //TODO: need more comprehensive tests than these to flesh out the additionl error types
  use super::*;
  use anyhow::Result;
  //use chrono::prelude::*;
  use std::convert::TryFrom;
  use time::format_description::well_known::Rfc3339;

  #[test]
  fn test_expiration_claim() -> Result<()> {
    // setup
    // a good time format
    let now = time::OffsetDateTime::now_utc().format(&Rfc3339)?;

    assert!(ExpirationClaim::try_from("hello").is_err());
    let claim = ExpirationClaim::try_from(now);
    assert!(claim.is_ok());
    let claim = claim.unwrap();

    assert_eq!(claim.get_key(), "exp");

    Ok(())
  }

  #[test]
  fn test_not_before_claim() -> Result<()> {
    // setup
    // a good time format
    let now = time::OffsetDateTime::now_utc().format(&Rfc3339)?;

    assert!(NotBeforeClaim::try_from("hello").is_err());
    let claim = NotBeforeClaim::try_from(now);
    assert!(claim.is_ok());
    let claim = claim.unwrap();

    assert_eq!(claim.get_key(), "nbf");

    Ok(())
  }

  #[test]
  fn test_issued_at_claim() -> Result<()> {
    // setup
    // a good time format
    let now = time::OffsetDateTime::now_utc().format(&Rfc3339)?;

    assert!(IssuedAtClaim::try_from("hello").is_err());
    let claim = IssuedAtClaim::try_from(now);
    assert!(claim.is_ok());
    let claim = claim.unwrap();

    assert_eq!(claim.get_key(), "iat");

    Ok(())
  }
  #[test]
  fn test_token_identifier_claim() {
    // setup
    let borrowed_str = String::from("hello world");
    let claim = TokenIdentifierClaim::from(borrowed_str.as_str());

    //verify
    assert_eq!("jti", claim.get_key());
  }

  #[test]
  fn test_audience_claim() {
    // setup
    let borrowed_str = String::from("hello world");
    let claim = AudienceClaim::from(borrowed_str.as_str());

    //verify
    assert_eq!("aud", claim.get_key());
  }

  #[test]
  fn test_subject_claim() {
    // setup
    let borrowed_str = String::from("hello world");
    let claim = SubjectClaim::from(borrowed_str.as_str());

    //verify
    assert_eq!("sub", claim.get_key());
  }

  #[test]
  fn test_iss_claim() {
    // setup
    let borrowed_str = String::from("hello world");
    let claim = IssuerClaim::from(borrowed_str.as_str());

    //verify
    assert_eq!("iss", claim.get_key());
  }

  #[test]
  fn test_basic_custom_claim() -> Result<()> {
    let borrowed_str = String::from("universe");
    let claim = CustomClaim::try_from((borrowed_str.as_str(), 137))?;
    // setup
    //verify

    assert_eq!(claim.get_key(), "universe");
    let (_, v) = claim.as_ref();
    assert_eq!(v, &137);
    Ok(())
  }

  #[test]
  fn test_restricted_custom_claim() {
    // setup
    //verify
    assert!(CustomClaim::try_from(("iss", 137)).is_err());
    assert!(CustomClaim::try_from(("sub", 137)).is_err());
    assert!(CustomClaim::try_from(("aud", 137)).is_err());
    assert!(CustomClaim::try_from(("exp", 137)).is_err());
    assert!(CustomClaim::try_from(("nbf", 137)).is_err());
    assert!(CustomClaim::try_from(("iat", 137)).is_err());
    assert!(CustomClaim::try_from(("jti", 137)).is_err());
    assert!(CustomClaim::try_from(("i'm good tho", true)).is_ok());
  }
}
