//  //use crate::common::{PurposeLocal, V2};
use crate::errors::{Iso8601ParseError, TokenClaimError};
//  use crate::traits::Claim;
use serde::ser::SerializeMap;
use std::convert::From;
//  use std::marker::PhantomData;
use std::convert::{AsRef, TryFrom};
//  pub struct Expiration;
//  pub struct NotBefore;
//  pub struct IssuedAt;
//  pub struct TokenIdentifier;

#[derive(Clone, Debug)]
pub struct Arbitrary<T: 'static>((&'static str, T));

impl<T> TryFrom<(&'static str, T)> for Arbitrary<T> {
  type Error = TokenClaimError;

  fn try_from(val: (&'static str, T)) -> Result<Self, Self::Error> {
    let key = val.0;
    match key {
      key if ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"].contains(&key) => {
        Err(TokenClaimError::ReservedClaim(key.into()))
      }
      _ => Ok(Self((key, val.1))),
    }
  }
}

//want to receive a reference as a tuple
impl<T> AsRef<(&'static str, T)> for Arbitrary<T> {
  fn as_ref(&self) -> &(&'static str, T) {
    &(self.0)
  }
}

impl<T: serde::Serialize> serde::Serialize for Arbitrary<T> {
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
pub struct Expiration((&'static str, &'static str));

impl TryFrom<&'static str> for Expiration {
  type Error = Iso8601ParseError;

  fn try_from(value: &'static str) -> Result<Self, Self::Error> {
    match iso8601::datetime(value) {
      Ok(_) => Ok(Self(("exp", value))),
      Err(_) => Err(Iso8601ParseError::new(value)),
    }
  }
}

//  /// parsing a date string and ensuring it's a valid iso8601 formatted string
//  fn verify_iso8601_value<'a, ClaimType>(
//    key: &str,
//    value: &'a str,
//  ) -> Result<PasetoClaim<&'a str, ClaimType>, Iso8601ParseError> {
//    match iso8601::datetime(value) {
//      //Ok(_) => Ok(Self<Expiration>(("exp", value))),
//      Ok(_) => Ok(PasetoClaim {
//        claim_type: PhantomData::<ClaimType>,
//        key: key.to_string(),
//        value,
//      }),
//      Err(_) => Err(Iso8601ParseError::new(value)),
//    }
//  }
//  //created using the From trait
//  impl From<&'static str> for Expiration {
//    fn from(s: &'static str) -> Self {
//      Self(("exp", s))
//    }
//  }

//want to receive a reference as a tuple
impl AsRef<(&'static str, &'static str)> for Expiration {
  fn as_ref(&self) -> &(&'static str, &'static str) {
    &self.0
  }
}

impl serde::Serialize for Expiration {
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
pub struct Audience((&'static str, &'static str));

//created using the From trait
impl From<&'static str> for Audience {
  fn from(s: &'static str) -> Self {
    Self(("aud", s))
  }
}

//want to receive a reference as a tuple
impl AsRef<(&'static str, &'static str)> for Audience {
  fn as_ref(&self) -> &(&'static str, &'static str) {
    &self.0
  }
}

impl serde::Serialize for Audience {
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
pub struct Subject((&'static str, &'static str));

//created using the From trait
impl From<&'static str> for Subject {
  fn from(s: &'static str) -> Self {
    Self(("sub", s))
  }
}

//want to receive a reference as a tuple
impl AsRef<(&'static str, &'static str)> for Subject {
  fn as_ref(&self) -> &(&'static str, &'static str) {
    &self.0
  }
}

impl serde::Serialize for Subject {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: serde::Serializer,
  {
    let mut map = serializer.serialize_map(Some(2))?;
    map.serialize_entry(self.0 .0, self.0 .1)?;
    map.end()
  }
}

//  pub struct Subject;
//  pub struct Arbitrary;
//  pub struct Issuer;

//  #[derive(Serialize, Clone)]
//  pub struct PasetoClaim<T, ClaimType> {
//    claim_type: PhantomData<ClaimType>,
//    key: String,
//    value: T,
//  }

//  //  impl<'a, ClaimType, T: Display> fmt::Display for PasetoClaim<'a, ClaimType, T> {
//  //    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//  //      write!(f, "({}, {})", self.key, self.value)
//  //    }
//  //  }

//  // Claim trait allows access to internal values
//  impl<T, ClaimType> Claim<T> for PasetoClaim<T, ClaimType> {
//    fn get_key(&self) -> &str {
//      &self.key
//    }
//    fn get_value(&self) -> &T {
//      &self.value
//    }
//  }

//  impl TryFrom<&str> for PasetoClaim<&str, IssuedAt> {
//    type Error = Iso8601ParseError;

//    fn try_from(value: &str) -> Result<Self, Self::Error> {
//      verify_iso8601_value("iat", &value.to_owned())
//    }
//  }

//  impl TryFrom<&str> for PasetoClaim<&str, NotBefore> {
//    type Error = Iso8601ParseError;

//    fn try_from(value: &str) -> Result<Self, Self::Error> {
//      verify_iso8601_value("nbf", &value.to_owned())
//    }
//  }

//  impl TryFrom<&str> for PasetoClaim<&str, Expiration> {
//    type Error = Iso8601ParseError;

//    fn try_from(value: &str) -> Result<Self, Self::Error> {
//      verify_iso8601_value("exp", &value.to_owned())
//    }
//  }

//  impl From<&str> for PasetoClaim<&str, TokenIdentifier> {
//    fn from(value: &str) -> Self {
//      Self {
//        claim_type: PhantomData::<TokenIdentifier>,
//        key: "jti".to_string(),
//        value: &value.to_owned(),
//      }
//    }
//  }

//  impl From<&str> for PasetoClaim<&str, Audience> {
//    fn from(value: &str) -> Self {
//      Self {
//        claim_type: PhantomData::<Audience>,
//        key: "aud".to_string(),
//        value: &value.to_owned(),
//      }
//    }
//  }

//  impl From<&str> for PasetoClaim<&str, Subject> {
//    fn from(value: &str) -> Self {
//      Self {
//        claim_type: PhantomData::<Subject>,
//        key: "sub".to_string(),
//        value: &value.to_owned(),
//      }
//    }
//  }

//  impl From<&str> for PasetoClaim<&str, Issuer> {
//    fn from(value: &str) -> Self {
//      Self {
//        claim_type: PhantomData::<Issuer>,
//        key: "iss".to_string(),
//        value: &value.to_owned(),
//      }
//    }
//  }

//  impl<'a, T: Serialize> PasetoClaim<T, Arbitrary> {
//    pub fn try_new(key: &'a str, value: T) -> Result<Self, TokenClaimError> {
//      //ensuring we don't use any of the restricted values
//      match key {
//        key if ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"].contains(&key) => {
//          Err(TokenClaimError::ReservedClaim(key.into()))
//        }
//        _ => Ok(Self {
//          claim_type: PhantomData::<Arbitrary>,
//          key: key.to_string(),
//          value,
//        }),
//      }
//    }
//  }

//  #[cfg(test)]
//  mod unit_tests {

//    use super::*;
//    use crate::traits::Claim;
//    use anyhow::Result;
//    use chrono::prelude::*;
//    use std::convert::TryFrom;

//    #[test]
//    fn test_expiration_claim() -> Result<()> {
//      // setup
//      // a good time format
//      let now = Local::now();
//      let s = now.to_rfc3339();

//      assert!(PasetoClaim::<Expiration>::try_from("hello").is_err());
//      let claim = PasetoClaim::<Expiration>::try_from(s.as_str());
//      assert!(claim.is_ok());
//      let claim = claim.unwrap();

//      assert_eq!(claim.get_key(), "exp");

//      Ok(())
//    }

//    #[test]
//    fn test_not_before_claim() -> Result<()> {
//      //  //creating a claim name
//      let now = Local::now();
//      let s = now.to_rfc3339();

//      assert!(PasetoClaim::<NotBefore>::try_from("hello").is_err());
//      let claim = PasetoClaim::<NotBefore>::try_from(s.as_str());
//      assert!(claim.is_ok());
//      let claim = claim.unwrap();
//      assert_eq!(claim.get_key(), "nbf");

//      Ok(())
//    }

//    #[test]
//    fn test_issued_at_claim() -> Result<()> {
//      //  //creating a claim name
//      let now = Local::now();
//      let s = now.to_rfc3339();

//      assert!(PasetoClaim::<IssuedAt>::try_from("hello").is_err());
//      let claim = PasetoClaim::<IssuedAt>::try_from(s.as_str());
//      assert!(claim.is_ok());
//      let claim = claim.unwrap();
//      assert_eq!(claim.get_key(), "iat");

//      Ok(())
//    }

//    #[test]
//    fn test_token_identifier_claim() {
//      // setup
//      let claim = PasetoClaim::<TokenIdentifier>::from("out of this world");

//      //verify
//      assert_eq!("jti", claim.get_key());
//      //assert_eq!(claim.get_value(), "out of this world");
//    }

//    #[test]
//    fn test_audience_claim() {
//      // setup
//      let claim = PasetoClaim::<Audience>::from("out of this world");

//      //verify
//      assert_eq!("aud", claim.get_key());
//      //assert_eq!("out of this world", claim.get_value());
//    }

//    #[test]
//    fn test_subject_claim() {
//      // setup
//      let claim = PasetoClaim::<Subject>::from("out of this world");

//      //verify
//      assert_eq!("sub", claim.get_key());
//      //assert_eq!("out of this world", claim.get_value());
//    }

//    #[test]
//    fn test_iss_claim() {
//      // setup
//      let claim = PasetoClaim::<Issuer>::from("rick sanchez");

//      //verify
//      assert_eq!("iss", claim.get_key());
//      //assert_eq!("rick sanchez", claim.get_value());
//    }

//    #[test]
//    fn test_basic_arbitrary_claim() -> Result<()> {
//      let claim = PasetoClaim::<Arbitrary, i32>::try_new("universe", 137)?;
//      // setup
//      //verify

//      assert_eq!(claim.key, "universe");
//      assert_eq!(claim.value, 137);
//      Ok(())
//    }

//    #[test]
//    fn test_restricted_arbitrary_claim() {
//      // setup
//      //verify
//      assert!(PasetoClaim::try_new("iss", 137).is_err());
//      assert!(PasetoClaim::try_new("sub", 137).is_err());
//      assert!(PasetoClaim::try_new("aud", 137).is_err());
//      assert!(PasetoClaim::try_new("exp", 137).is_err());
//      assert!(PasetoClaim::try_new("nbf", 137).is_err());
//      assert!(PasetoClaim::try_new("iat", 137).is_err());
//      assert!(PasetoClaim::try_new("jti", 137).is_err());
//      assert!(PasetoClaim::try_new("i'm good tho", true).is_ok());
//    }

//    #[test]
//    fn test_arbitrary_claim() -> Result<()> {
//      //creating a valid arbitrary claim
//      let claim = PasetoClaim::try_new("universe", 137)?;

//      assert_eq!(claim.key, "universe");
//      assert_eq!(claim.value, 137);
//      Ok(())
//    }
//  }
