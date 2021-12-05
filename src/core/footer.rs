use super::*;
use std::fmt;
use std::ops::Deref;

#[derive(Default, Debug, Clone, Copy)]
pub struct Footer<'a>(&'a str);

impl<'a> Base64Encodable<str> for Footer<'a> {}

impl<'a> Deref for Footer<'a> {
  type Target = [u8];

  fn deref(&self) -> &'a Self::Target {
    self.0.as_bytes()
  }
}

impl<'a> AsRef<str> for Footer<'a> {
  fn as_ref(&self) -> &str {
    self.0
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
  fn test_set_v2_footer() {
    let footer: Footer = "wubbulubbadubdub".into();
    assert_eq!(footer.as_ref(), "wubbulubbadubdub");
    assert!(!footer.as_ref().is_empty());
  }
}
