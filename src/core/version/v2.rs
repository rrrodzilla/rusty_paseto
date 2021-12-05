use crate::core::traits::*;
use std::fmt;
use std::fmt::Display;

#[derive(Debug, Clone, Copy)]
pub struct V2(&'static str);
impl VersionTrait for V2 {}
impl AsRef<str> for V2 {
  fn as_ref(&self) -> &str {
    self.0
  }
}
impl V2orV4 for V2 {}
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
