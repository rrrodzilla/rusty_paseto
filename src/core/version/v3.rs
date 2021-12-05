use crate::core::traits::*;
use std::fmt;
use std::fmt::Display;

#[derive(Debug, Clone, Copy)]
pub struct V3(&'static str);
impl VersionTrait for V3 {}
impl AsRef<str> for V3 {
  fn as_ref(&self) -> &str {
    self.0
  }
}
impl ImplicitAssertionCapable for V3 {}
impl V1orV3 for V3 {}
impl Default for V3 {
  fn default() -> Self {
    Self("v3")
  }
}
impl Display for V3 {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", self.0)
  }
}
