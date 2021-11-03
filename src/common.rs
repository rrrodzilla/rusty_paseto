use crate::errors::PasetoTokenParseError;
use crate::traits::Base64Encodable;
use serde_json::Value;
use std::collections::HashMap;
use std::fmt::{self, Display};
use std::marker::PhantomData;

pub type ValidatorFn = dyn Fn(&str, &Value) -> Result<(), PasetoTokenParseError>;
pub type ValidatorMap = HashMap<String, Box<ValidatorFn>>;

#[derive(Debug)]
pub struct Public(&'static str);
impl Default for Public {
  fn default() -> Self {
    Self("public")
  }
}

impl Display for Public {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", self.0)
  }
}

#[derive(Debug)]
pub struct V4(&'static str);
impl Default for V4 {
  fn default() -> Self {
    Self("v4")
  }
}
impl Display for V4 {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", self.0)
  }
}

#[derive(Debug)]
pub struct V2(&'static str);
impl Default for V2 {
  fn default() -> Self {
    Self("v2")
  }
}
impl Display for V2 {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", self.0)
  }
}

#[derive(Debug)]
pub struct Local(&'static str);
impl Default for Local {
  fn default() -> Self {
    Self("local")
  }
}
impl Display for Local {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", self.0)
  }
}

#[derive(PartialEq, Debug)]
pub(crate) struct Header<Version, Purpose>
where
  Version: Default + Display,
  Purpose: Default + Display,
{
  version: PhantomData<Version>,
  purpose: PhantomData<Purpose>,
  header: String,
}

impl<Version, Purpose> AsRef<str> for Header<Version, Purpose>
where
  Version: Default + Display,
  Purpose: Default + Display,
{
  fn as_ref(&self) -> &str {
    self.header.as_ref()
  }
}

impl<Version, Purpose> Default for Header<Version, Purpose>
where
  Version: Default + Display,
  Purpose: Default + Display,
{
  fn default() -> Self {
    Self {
      version: PhantomData,
      purpose: PhantomData,
      header: format!("{}.{}.", Version::default(), Purpose::default()),
    }
  }
}

impl<Version, Purpose> Display for Header<Version, Purpose>
where
  Version: Default + Display,
  Purpose: Default + Display,
{
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", self.header)
  }
}

#[derive(Debug, Clone, Default)]
pub struct ImplicitAssertion(String);

impl Base64Encodable<str> for ImplicitAssertion {}

impl AsRef<str> for ImplicitAssertion {
  fn as_ref(&self) -> &str {
    &self.0
  }
}
impl From<&str> for ImplicitAssertion {
  fn from(s: &str) -> Self {
    Self(s.to_string())
  }
}
impl fmt::Display for ImplicitAssertion {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", self.0)
  }
}
impl PartialEq for ImplicitAssertion {
  fn eq(&self, other: &Self) -> bool {
    self.0 == other.0
  }
}
impl Eq for ImplicitAssertion {}

/// An optional footer for the PASETO token.
///
/// Appended to the end of a token and validated during decryption.
///
///
/// # Examples
///
/// ```
/// # use rusty_paseto::core_tokens::*;
/// # let key = &Key::<V2, Local>::new_random();
/// let footer = Some(Footer::from("wubbulubbadubdub"));
/// # let payload = Payload::from("I'm Pickle Rick!");
///
/// // Use in any token that accepts an optional footer
/// let token = GenericToken::<V2, Local>::new(payload, key, footer);
/// ```
#[derive(Debug, Clone, Default)]
pub struct Footer(String);

impl Base64Encodable<str> for Footer {}

impl AsRef<str> for Footer {
  fn as_ref(&self) -> &str {
    &self.0
  }
}
impl From<&str> for Footer {
  fn from(s: &str) -> Self {
    Self(s.to_string())
  }
}
impl fmt::Display for Footer {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", self.0)
  }
}
impl PartialEq for Footer {
  fn eq(&self, other: &Self) -> bool {
    self.0 == other.0
  }
}
impl Eq for Footer {}

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

  fn test_header_equality<S, H>(valid_value: H, header: S)
  where
    S: AsRef<str>,
    H: AsRef<str>,
  {
    assert_eq!(header.as_ref(), valid_value.as_ref());
  }

  #[test]
  fn test_v4_local_header_equality() {
    test_header_equality(Header::<V4, Local>::default(), "v4.local.");
  }

  #[test]
  fn test_v4_public_header_equality() {
    test_header_equality(Header::<V4, Public>::default(), "v4.public.");
  }

  #[test]
  fn test_v2_public_header_equality() {
    test_header_equality(Header::<V2, Public>::default(), "v2.public.");
  }
  #[test]
  fn test_v2_local_header_equality() {
    test_header_equality(Header::<V2, Local>::default(), "v2.local.");
  }
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
