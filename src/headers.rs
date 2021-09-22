use std::fmt;

#[derive(Default)]
pub(crate) struct V2LocalHeader<'a>(&'a str);
impl<'a> AsRef<str> for V2LocalHeader<'a> {
  fn as_ref(&self) -> &str {
    "v2.local."
  }
}

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
#[cfg(test)]
mod unit_tests {

  use super::*;

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
}
