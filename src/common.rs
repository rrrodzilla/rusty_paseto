use std::fmt;

#[derive(Default)]
pub(crate) struct V2LocalHeader<'a>(&'a str);
impl<'a> AsRef<str> for V2LocalHeader<'a> {
  fn as_ref(&self) -> &str {
    "v2.local."
  }
}

/// An optional footer for the PASETO token.
///
/// Appended to the end of a token and validated during decryption.
///
///
/// # Examples
///
/// ```
/// # use rusty_paseto::v2::local::*;
/// # use rusty_paseto::v2::*;
/// # let key = &V2LocalSharedKey::new_random();
/// let footer = Some(Footer::from("wubbulubbadubdub"));
/// # let payload = Payload::from("I'm Pickle Rick!");
///
/// // Use in any token that accepts an optional footer
/// let token = V2LocalToken::new(payload, key, footer);
/// ```
#[derive(Clone, Copy)]
pub struct Footer<'a>(&'a str);

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

///A v2 local token header as per the paseto specification
#[derive(PartialEq, Debug)]
pub(crate) struct Header<'a>(&'a str);

impl<'a> PartialEq<str> for Header<'a> {
  fn eq(&self, other: &str) -> bool {
    self.as_ref() == other
  }
}
impl<'a> PartialEq<Header<'a>> for str {
  fn eq(&self, other: &Header<'a>) -> bool {
    self == other.as_ref()
  }
}
impl<'a> AsRef<str> for Header<'a> {
  fn as_ref(&self) -> &str {
    self.0
  }
}
impl<'a> Default for Header<'a> {
  fn default() -> Self {
    Self("v2.local.")
  }
}

impl<'a> fmt::Display for Header<'a> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", self.0)
  }
}

/// The token payload
#[derive(PartialEq, Debug, Clone, Copy)]
pub struct Payload<'a>(&'a str);
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

#[cfg(test)]
mod unit_tests {

  use super::*;
  use crate::crypto::Base64EncodedString;

  #[test]
  fn test_v2_local_header_equality() {
    let header = V2LocalHeader::default();
    assert_eq!(header.as_ref(), "v2.local.")
  }

  #[test]
  fn test_v2_header_equality() {
    let header = Header::default();
    assert_eq!(&header, "v2.local.")
  }

  #[test]
  fn test_v2_header_outfix_equality_from_str() {
    assert!("v2.local.".eq(&Header::default()));
  }

  #[test]
  fn test_v2_header_outfix_equality() {
    assert!(Header::default().eq("v2.local."));
  }

  #[test]
  fn test_v2_footer() {
    let footer = Footer::default();
    assert_eq!(footer.as_ref(), "");
    assert!(footer.as_ref().is_empty());
  }

  #[test]
  fn test_v2_footer_encoded_equality() {
    let this_footer = Base64EncodedString::from(String::default());
    let that_footer = Base64EncodedString::from(String::default());
    assert!(this_footer == that_footer);
  }

  #[test]
  fn test_set_v2_footer() {
    let footer: Footer = "wubbulubbadubdub".into();
    assert_eq!(footer.as_ref(), "wubbulubbadubdub");
    assert!(!footer.as_ref().is_empty());
  }
}
