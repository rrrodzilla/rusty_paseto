use crate::errors::Iso8601ParseError;
use std::convert::TryFrom;
//what would example code look like?
// let claim = ExpirationClaim::from("out of this world");
pub struct ExpirationClaim<'a>((&'a str, &'a str));

impl<'a> TryFrom<&'a str> for ExpirationClaim<'a> {
  type Error = Iso8601ParseError;

  fn try_from(value: &'a str) -> Result<Self, Self::Error> {
    match iso8601::datetime(value) {
      Ok(_) => Ok(Self(("exp", value))),
      Err(_) => Err(Iso8601ParseError::new(value)),
    }
  }
}

impl<'a> AsRef<(&'a str, &'a str)> for ExpirationClaim<'a> {
  fn as_ref(&self) -> &(&'a str, &'a str) {
    &self.0
  }
}

//what would example code look like?
// let claim = NotBeforeClaim::from("out of this world");
pub struct NotBeforeClaim<'a>((&'a str, &'a str));

impl<'a> TryFrom<&'a str> for NotBeforeClaim<'a> {
  type Error = Iso8601ParseError;

  fn try_from(value: &'a str) -> Result<Self, Self::Error> {
    match iso8601::datetime(value) {
      Ok(_) => Ok(Self(("nbf", value))),
      Err(_) => Err(Iso8601ParseError::new(value)),
    }
  }
}

impl<'a> AsRef<(&'a str, &'a str)> for NotBeforeClaim<'a> {
  fn as_ref(&self) -> &(&'a str, &'a str) {
    &self.0
  }
}

//what would example code look like?
// let claim = IssuedAtClaim::from("out of this world");
pub struct IssuedAtClaim<'a>((&'a str, &'a str));

impl<'a> TryFrom<&'a str> for IssuedAtClaim<'a> {
  type Error = Iso8601ParseError;

  fn try_from(value: &'a str) -> Result<Self, Self::Error> {
    match iso8601::datetime(value) {
      Ok(_) => Ok(Self(("iat", value))),
      Err(_) => Err(Iso8601ParseError::new(value)),
    }
  }
}

impl<'a> AsRef<(&'a str, &'a str)> for IssuedAtClaim<'a> {
  fn as_ref(&self) -> &(&'a str, &'a str) {
    &self.0
  }
}

//what would example code look like?
// let token_identifier_claim = token_identifierClaim::from("out of this world");
pub struct TokenIdentifierClaim<'a>((&'a str, &'a str));

impl<'a> From<&'a str> for TokenIdentifierClaim<'a> {
  fn from(s: &'a str) -> Self {
    Self(("jti", s))
  }
}

impl<'a> AsRef<(&'a str, &'a str)> for TokenIdentifierClaim<'a> {
  fn as_ref(&self) -> &(&'a str, &'a str) {
    &self.0
  }
}

//what would example code look like?
// let audience_claim = audienceClaim::from("out of this world");
pub struct AudienceClaim<'a>((&'a str, &'a str));

impl<'a> From<&'a str> for AudienceClaim<'a> {
  fn from(s: &'a str) -> Self {
    Self(("aud", s))
  }
}

impl<'a> AsRef<(&'a str, &'a str)> for AudienceClaim<'a> {
  fn as_ref(&self) -> &(&'a str, &'a str) {
    &self.0
  }
}

//what would example code look like?
// let claim = ArbitraryClaim::new<u8>("universe", 137);
pub struct ArbitraryClaim<'a, V>((&'a str, V));

impl<'a, V> ArbitraryClaim<'a, V> {
  fn new(name: &'a str, value: V) -> Self {
    Self((name, value))
  }
}

impl<'a, V> AsRef<(&'a str, V)> for ArbitraryClaim<'a, V> {
  fn as_ref(&self) -> &(&'a str, V) {
    &self.0
  }
}

//what would example code look like?
// let subject_claim = SubjectClaim::from("out of this world");
pub struct SubjectClaim<'a>((&'a str, &'a str));

impl<'a> From<&'a str> for SubjectClaim<'a> {
  fn from(s: &'a str) -> Self {
    Self(("sub", s))
  }
}

impl<'a> AsRef<(&'a str, &'a str)> for SubjectClaim<'a> {
  fn as_ref(&self) -> &(&'a str, &'a str) {
    &self.0
  }
}

//what would example code look like?
// let issuer_claim = IssuerClaim::from("something");
pub struct IssuerClaim<'a>((&'a str, &'a str));

impl<'a> From<&'a str> for IssuerClaim<'a> {
  fn from(s: &'a str) -> Self {
    Self(("iss", s))
  }
}

impl<'a> AsRef<(&'a str, &'a str)> for IssuerClaim<'a> {
  fn as_ref(&self) -> &(&'a str, &'a str) {
    &self.0
  }
}

#[cfg(test)]
mod unit_tests {

  use super::*;
  use anyhow::Result;
  use chrono::prelude::*;

  #[test]
  fn test_expiration_claim() -> Result<()> {
    //creating a claim name
    let now = Local::now();
    let s = now.to_rfc3339();

    let claim = ExpirationClaim::try_from(s.as_str())?;
    let (name, value) = claim.as_ref();
    assert_eq!(&"exp", name);
    assert_eq!(&s, value);

    //test a bad time format
    let now = Local::now();
    let bad_date = now.to_string();
    let claim = ExpirationClaim::try_from(bad_date.as_str());
    assert!(claim.is_err());

    Ok(())
  }

  #[test]
  fn test_not_before_claim() -> Result<()> {
    //creating a claim name
    let now = Local::now();
    let s = now.to_rfc3339();

    let claim = NotBeforeClaim::try_from(s.as_str())?;
    let (name, value) = claim.as_ref();
    assert_eq!(&"nbf", name);
    assert_eq!(&s, value);

    //test a bad time format
    let now = Local::now();
    let bad_date = now.to_string();
    let claim = NotBeforeClaim::try_from(bad_date.as_str());
    assert!(claim.is_err());

    Ok(())
  }
  #[test]
  fn test_issued_at_claim() -> Result<()> {
    //creating a claim name
    let now = Local::now();
    let s = now.to_rfc3339();

    let claim = IssuedAtClaim::try_from(s.as_str())?;
    let (name, value) = claim.as_ref();
    assert_eq!(&"iat", name);
    assert_eq!(&s, value);

    //test a bad time format
    let now = Local::now();
    let bad_date = now.to_string();
    let claim = IssuedAtClaim::try_from(bad_date.as_str());
    assert!(claim.is_err());

    Ok(())
  }

  #[test]
  fn test_token_identifier_claim() {
    //creating a claim name
    let claim = TokenIdentifierClaim::from("out of this world");
    let (name, value) = claim.as_ref();
    assert_eq!(&"jti", name);
    assert_eq!(&"out of this world", value);
  }

  #[test]
  fn test_audience_claim() {
    //creating a claim name
    let claim = AudienceClaim::from("out of this world");
    let (name, value) = claim.as_ref();
    assert_eq!(&"aud", name);
    assert_eq!(&"out of this world", value);
  }

  #[test]
  fn test_subject_claim() {
    //creating a claim name
    let claim = SubjectClaim::from("out of this world");
    let (name, value) = claim.as_ref();
    assert_eq!(&"sub", name);
    assert_eq!(&"out of this world", value);
  }

  #[test]
  fn test_iss_claim() {
    //creating a claim name
    let claim = IssuerClaim::from("sanchez");
    let (name, value) = claim.as_ref();
    assert_eq!(&"iss", name);
    assert_eq!(&"sanchez", value);
  }

  #[test]
  fn test_arbitrary_claim() {
    //creating a claim name
    let claim = ArbitraryClaim::new("universe", 137);
    let (name, value) = claim.as_ref();
    assert_eq!(&"universe", name);
    assert_eq!(&137, value);
  }
}
