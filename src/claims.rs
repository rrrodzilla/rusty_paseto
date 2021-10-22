use crate::errors::{Iso8601ParseError, TokenClaimError};
use crate::traits::PasetoClaim;
use serde::ser::SerializeMap;
use std::convert::From;
use std::convert::{AsRef, TryFrom};

#[derive(Clone, Debug)]
pub struct CustomClaim<T>((String, T));

impl<T> PasetoClaim for CustomClaim<T> {
  fn get_key(&self) -> &str {
    &self.0 .0
  }
}

impl TryFrom<&str> for CustomClaim<&str> {
  type Error = TokenClaimError;

  fn try_from(val: &str) -> Result<Self, Self::Error> {
    let key = val;
    match key {
      key if ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"].contains(&key) => {
        Err(TokenClaimError::ReservedClaim(key.into()))
      }
      _ => Ok(Self((String::from(val), ""))),
    }
  }
}

impl<T> TryFrom<(&str, T)> for CustomClaim<T> {
  type Error = TokenClaimError;

  fn try_from(val: (&str, T)) -> Result<Self, Self::Error> {
    let key = val.0;
    match key {
      key if ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"].contains(&key) => {
        Err(TokenClaimError::ReservedClaim(key.into()))
      }
      _ => Ok(Self((String::from(val.0), val.1))),
    }
  }
}

//we want to receive a reference as a tuple
impl<T> AsRef<(String, T)> for CustomClaim<T> {
  fn as_ref(&self) -> &(String, T) {
    &self.0
  }
}

impl<T: serde::Serialize> serde::Serialize for CustomClaim<T> {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: serde::Serializer,
  {
    let mut map = serializer.serialize_map(Some(2))?;
    map.serialize_key(&self.0 .0)?;
    map.serialize_value(&self.0 .1)?;
    map.end()
  }
}

#[derive(Clone)]
pub struct IssuedAtClaim<'a>((&'a str, &'a str));
impl<'a> PasetoClaim for IssuedAtClaim<'a> {
  fn get_key(&self) -> &str {
    self.0 .0
  }
}

impl<'a> Default for IssuedAtClaim<'a> {
  fn default() -> Self {
    Self(("iat", "2019-01-01T00:00:00+00:00"))
  }
}

impl<'a> TryFrom<&'a str> for IssuedAtClaim<'a> {
  type Error = Iso8601ParseError;

  fn try_from(value: &'a str) -> Result<Self, Self::Error> {
    match iso8601::datetime(value) {
      Ok(_) => Ok(Self(("iat", value))),
      Err(_) => Err(Iso8601ParseError::new(value)),
    }
  }
}

//want to receive a reference as a tuple
impl<'a> AsRef<(&'a str, &'a str)> for IssuedAtClaim<'a> {
  fn as_ref(&self) -> &(&'a str, &'a str) {
    &self.0
  }
}

impl<'a> serde::Serialize for IssuedAtClaim<'a> {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: serde::Serializer,
  {
    let mut map = serializer.serialize_map(Some(2))?;
    map.serialize_key(&self.0 .0)?;
    map.serialize_value(&self.0 .1)?;
    map.end()
  }
}

#[derive(Clone)]
pub struct NotBeforeClaim<'a>((&'a str, &'a str));
impl<'a> PasetoClaim for NotBeforeClaim<'a> {
  fn get_key(&self) -> &str {
    self.0 .0
  }
}

impl<'a> Default for NotBeforeClaim<'a> {
  fn default() -> Self {
    Self(("nbf", "2019-01-01T00:00:00+00:00"))
  }
}

impl<'a> TryFrom<&'a str> for NotBeforeClaim<'a> {
  type Error = Iso8601ParseError;

  fn try_from(value: &'a str) -> Result<Self, Self::Error> {
    match iso8601::datetime(value) {
      Ok(_) => Ok(Self(("nbf", value))),
      Err(_) => Err(Iso8601ParseError::new(value)),
    }
  }
}

//want to receive a reference as a tuple
impl<'a> AsRef<(&'a str, &'a str)> for NotBeforeClaim<'a> {
  fn as_ref(&self) -> &(&'a str, &'a str) {
    &self.0
  }
}

impl<'a> serde::Serialize for NotBeforeClaim<'a> {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: serde::Serializer,
  {
    let mut map = serializer.serialize_map(Some(2))?;
    map.serialize_key(&self.0 .0)?;
    map.serialize_value(&self.0 .1)?;
    map.end()
  }
}

#[derive(Clone)]
pub struct ExpirationClaim<'a>((&'a str, &'a str));
impl<'a> PasetoClaim for ExpirationClaim<'a> {
  fn get_key(&self) -> &str {
    self.0 .0
  }
}

impl<'a> Default for ExpirationClaim<'a> {
  fn default() -> Self {
    Self(("exp", "2019-01-01T00:00:00+00:00"))
  }
}

impl<'a> TryFrom<&'a str> for ExpirationClaim<'a> {
  type Error = Iso8601ParseError;

  fn try_from(value: &'a str) -> Result<Self, Self::Error> {
    match iso8601::datetime(value) {
      Ok(_) => Ok(Self(("exp", value))),
      Err(_) => Err(Iso8601ParseError::new(value)),
    }
  }
}

//want to receive a reference as a tuple
impl<'a> AsRef<(&'a str, &'a str)> for ExpirationClaim<'a> {
  fn as_ref(&self) -> &(&'a str, &'a str) {
    &self.0
  }
}

impl<'a> serde::Serialize for ExpirationClaim<'a> {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: serde::Serializer,
  {
    let mut map = serializer.serialize_map(Some(2))?;
    map.serialize_key(&self.0 .0)?;
    map.serialize_value(&self.0 .1)?;
    map.end()
  }
}

#[derive(Clone)]
pub struct TokenIdentifierClaim<'a>((&'a str, &'a str));
impl<'a> PasetoClaim for TokenIdentifierClaim<'a> {
  fn get_key(&self) -> &str {
    self.0 .0
  }
}

impl<'a> Default for TokenIdentifierClaim<'a> {
  fn default() -> Self {
    Self(("jti", ""))
  }
}

//created using the From trait
impl<'a> From<&'a str> for TokenIdentifierClaim<'a> {
  fn from(s: &'a str) -> Self {
    Self(("jti", s))
  }
}

//want to receive a reference as a tuple
impl<'a> AsRef<(&'a str, &'a str)> for TokenIdentifierClaim<'a> {
  fn as_ref(&self) -> &(&'a str, &'a str) {
    &self.0
  }
}

impl<'a> serde::Serialize for TokenIdentifierClaim<'a> {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: serde::Serializer,
  {
    let mut map = serializer.serialize_map(Some(2))?;
    map.serialize_key(&self.0 .0)?;
    map.serialize_value(&self.0 .1)?;
    //map.serialize_entry(self.0 .0, self.0 .1)?;
    map.end()
  }
}

#[derive(Clone)]
pub struct AudienceClaim<'a>((&'a str, &'a str));
impl<'a> PasetoClaim for AudienceClaim<'a> {
  fn get_key(&self) -> &str {
    self.0 .0
  }
}

impl<'a> Default for AudienceClaim<'a> {
  fn default() -> Self {
    Self(("aud", ""))
  }
}

//created using the From trait
impl<'a> From<&'a str> for AudienceClaim<'a> {
  fn from(s: &'a str) -> Self {
    Self(("aud", s))
  }
}

//want to receive a reference as a tuple
impl<'a> AsRef<(&'a str, &'a str)> for AudienceClaim<'a> {
  fn as_ref(&self) -> &(&'a str, &'a str) {
    &self.0
  }
}

impl<'a> serde::Serialize for AudienceClaim<'a> {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: serde::Serializer,
  {
    let mut map = serializer.serialize_map(Some(2))?;
    map.serialize_key(&self.0 .0)?;
    map.serialize_value(&self.0 .1)?;
    //map.serialize_entry(self.0 .0, self.0 .1)?;
    map.end()
  }
}

#[derive(Clone)]
pub struct SubjectClaim<'a>((&'a str, &'a str));

impl<'a> PasetoClaim for SubjectClaim<'a> {
  fn get_key(&self) -> &str {
    self.0 .0
  }
}

impl<'a> Default for SubjectClaim<'a> {
  fn default() -> Self {
    Self(("sub", ""))
  }
}

//created using the From trait
impl<'a> From<&'a str> for SubjectClaim<'a> {
  fn from(s: &'a str) -> Self {
    Self(("sub", s))
  }
}

//want to receive a reference as a tuple
impl<'a> AsRef<(&'a str, &'a str)> for SubjectClaim<'a> {
  fn as_ref(&self) -> &(&'a str, &'a str) {
    &self.0
  }
}

impl<'a> serde::Serialize for SubjectClaim<'a> {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: serde::Serializer,
  {
    let mut map = serializer.serialize_map(Some(2))?;
    map.serialize_entry(self.0 .0, self.0 .1)?;
    map.end()
  }
}

#[derive(Clone)]
pub struct IssuerClaim<'a>((&'a str, &'a str));

impl<'a> PasetoClaim for IssuerClaim<'a> {
  fn get_key(&self) -> &str {
    self.0 .0
  }
}

impl<'a> Default for IssuerClaim<'a> {
  fn default() -> Self {
    Self(("iss", ""))
  }
}

//created using the From trait
impl<'a> From<&'a str> for IssuerClaim<'a> {
  fn from(s: &'a str) -> Self {
    Self(("iss", s))
  }
}

//want to receive a reference as a tuple
impl<'a> AsRef<(&'a str, &'a str)> for IssuerClaim<'a> {
  fn as_ref(&self) -> &(&'a str, &'a str) {
    &self.0
  }
}

impl<'a> serde::Serialize for IssuerClaim<'a> {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: serde::Serializer,
  {
    let mut map = serializer.serialize_map(Some(2))?;
    map.serialize_entry(self.0 .0, self.0 .1)?;
    map.end()
  }
}

#[cfg(test)]
mod unit_tests {

  use super::*;
  use anyhow::Result;
  use chrono::prelude::*;
  use std::convert::TryFrom;

  #[test]
  fn test_expiration_claim() -> Result<()> {
    // setup
    // a good time format
    let now = Local::now();
    let s = now.to_rfc3339();

    assert!(ExpirationClaim::try_from("hello").is_err());
    let claim = ExpirationClaim::try_from(s.as_str());
    assert!(claim.is_ok());
    let claim = claim.unwrap();

    assert_eq!(claim.get_key(), "exp");

    Ok(())
  }

  #[test]
  fn test_not_before_claim() -> Result<()> {
    // setup
    // a good time format
    let now = Local::now();
    let s = now.to_rfc3339();

    assert!(NotBeforeClaim::try_from("hello").is_err());
    let claim = NotBeforeClaim::try_from(s.as_str());
    assert!(claim.is_ok());
    let claim = claim.unwrap();

    assert_eq!(claim.get_key(), "nbf");

    Ok(())
  }

  #[test]
  fn test_issued_at_claim() -> Result<()> {
    // setup
    // a good time format
    let now = Local::now();
    let s = now.to_rfc3339();

    assert!(IssuedAtClaim::try_from("hello").is_err());
    let claim = IssuedAtClaim::try_from(s.as_str());
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
