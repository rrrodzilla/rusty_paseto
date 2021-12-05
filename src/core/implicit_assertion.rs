use std::fmt;
use std::ops::Deref;

#[derive(Default, Debug, Copy, Clone)]
pub struct ImplicitAssertion<'a>(&'a str);

impl<'a> Deref for ImplicitAssertion<'a> {
  type Target = [u8];

  fn deref(&self) -> &'a Self::Target {
    self.0.as_bytes()
  }
}

impl<'a> AsRef<str> for ImplicitAssertion<'a> {
  fn as_ref(&self) -> &str {
    self.0
  }
}
impl<'a> From<&'a str> for ImplicitAssertion<'a> {
  fn from(s: &'a str) -> Self {
    Self(s)
  }
}
impl<'a> fmt::Display for ImplicitAssertion<'a> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", self.0)
  }
}
impl<'a> PartialEq for ImplicitAssertion<'a> {
  fn eq(&self, other: &Self) -> bool {
    self.0 == other.0
  }
}
impl<'a> Eq for ImplicitAssertion<'a> {}
