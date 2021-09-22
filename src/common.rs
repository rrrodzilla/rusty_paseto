use std::fmt;

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
