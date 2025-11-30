use super::traits::Base64Encodable;
use std::fmt;
use std::ops::Deref;

/// The token payload
#[derive(Default, Debug, Clone, Copy)]
pub struct Payload<'a>(&'a str);
impl Base64Encodable<str> for Payload<'_> {}

impl<'a> Deref for Payload<'a> {
  type Target = [u8];

  fn deref(&self) -> &'a Self::Target {
    self.0.as_bytes()
  }
}

impl AsRef<str> for Payload<'_> {
  fn as_ref(&self) -> &str {
    self.0
  }
}

impl<'a> From<&'a str> for Payload<'a> {
  fn from(s: &'a str) -> Self {
    Self(s)
  }
}

impl<R> PartialEq<R> for Payload<'_>
where
  R: AsRef<str>,
{
  fn eq(&self, other: &R) -> bool {
    self.as_ref() == other.as_ref()
  }
}

impl fmt::Display for Payload<'_> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", self.0)
  }
}
