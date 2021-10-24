use crate::errors::PasetoTokenParseError;
use crate::traits::Base64Encodable;
use serde_json::Value;
use std::collections::HashMap;
use std::fmt;

pub type ValidatorFn = dyn Fn(&str, &Value) -> Result<(), PasetoTokenParseError>;
pub type ValidatorMap = HashMap<String, Box<ValidatorFn>>;

#[derive(Debug)]
pub struct Version2;
#[derive(Debug)]
pub struct PurposeLocal;
#[derive(Debug)]
pub struct PurposePublic;

/// An optional footer for the PASETO token.
///
/// Appended to the end of a token and validated during decryption.
///
///
/// # Examples
///
/// ```
/// # use rusty_paseto::core_tokens::*;
/// # let key = &Key::<Version2, PurposeLocal>::new_random();
/// let footer = Some(Footer::from("wubbulubbadubdub"));
/// # let payload = Payload::from("I'm Pickle Rick!");
///
/// // Use in any token that accepts an optional footer
/// let token = GenericToken::<Version2, PurposeLocal>::new(payload, key, footer);
/// ```
#[derive(Debug, Clone, Copy)]
pub struct Footer<'a>(&'a str);

impl<'a> Base64Encodable<str> for Footer<'a> {}

impl<'a> AsRef<str> for Footer<'a> {
  fn as_ref(&self) -> &str {
    self.0
  }
}
impl<'a> Default for Footer<'a> {
  fn default() -> Self {
    Self("")
  }
}
impl<'a> From<&'a str> for Footer<'a> {
  fn from(s: &'a str) -> Self {
    Self(s)
  }
}
impl<'a> fmt::Display for Footer<'a> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", self.0)
  }
}
impl<'a> PartialEq for Footer<'a> {
  fn eq(&self, other: &Self) -> bool {
    self.0 == other.0
  }
}
impl<'a> Eq for Footer<'a> {}

/// The token payload
#[derive(PartialEq, Debug, Clone, Copy)]
pub struct Payload<'a>(&'a str);
impl Base64Encodable<str> for Payload<'_> {}
impl<'a> AsRef<str> for Payload<'a> {
  fn as_ref(&self) -> &str {
    self.0
  }
}

impl<'a> Default for Payload<'a> {
  fn default() -> Self {
    Self("")
  }
}

impl<'a> From<&'a str> for Payload<'a> {
  fn from(s: &'a str) -> Self {
    Self(s)
  }
}

impl<'a, R> PartialEq<R> for Payload<'a>
where
  R: AsRef<&'a str>,
{
  fn eq(&self, other: &R) -> bool {
    self.as_ref() == *other.as_ref()
  }
}

impl<'a> fmt::Display for Payload<'a> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", self.0)
  }
}

#[derive(Clone)]
pub(crate) struct RawPayload(Vec<u8>);
impl Base64Encodable<Vec<u8>> for RawPayload {}
impl From<Vec<u8>> for RawPayload {
  fn from(s: Vec<u8>) -> Self {
    Self(s)
  }
}
impl AsRef<Vec<u8>> for RawPayload {
  fn as_ref(&self) -> &Vec<u8> {
    &self.0
  }
}
impl fmt::Display for RawPayload {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "{:?}", self.0)
  }
}
#[cfg(test)]
mod unit_tests {

  use super::*;

  #[test]
  fn test_v2_footer() {
    let footer = Footer::default();
    assert_eq!(footer.as_ref(), "");
    assert!(footer.as_ref().is_empty());
  }

  #[test]
  fn test_v2_footer_encoded_equality() {
    //  TODO: revisit after refactor
    //  let this_footer = Base64EncodedString::from(String::default());
    //  let that_footer = Base64EncodedString::from(String::default());
    //  assert!(this_footer == that_footer);
  }

  #[test]
  fn test_set_v2_footer() {
    let footer: Footer = "wubbulubbadubdub".into();
    assert_eq!(footer.as_ref(), "wubbulubbadubdub");
    assert!(!footer.as_ref().is_empty());
  }
}
