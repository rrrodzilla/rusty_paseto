use crate::core::traits::*;
use std::fmt;
use std::fmt::Display;

#[derive(Debug, Clone, Copy)]
pub struct V4(&'static str);
impl VersionTrait for V4 {}
impl ImplicitAssertionCapable for V4 {}
impl V2orV4 for V4 {}
impl AsRef<str> for V4 {
  fn as_ref(&self) -> &str {
    self.0
  }
}
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
