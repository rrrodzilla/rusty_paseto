use crate::core::traits::*;
use std::fmt;
use std::fmt::Display;

#[derive(Debug, Clone, Copy)]
pub struct V1(&'static str);
impl AsRef<str> for V1 {
  fn as_ref(&self) -> &str {
    self.0
  }
}
impl V1orV3 for V1 {}
impl VersionTrait for V1 {}
impl Default for V1 {
  fn default() -> Self {
    Self("v1")
  }
}
impl Display for V1 {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", self.0)
  }
}
