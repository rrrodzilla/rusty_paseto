use crate::core::traits::*;
use std::fmt;
use std::fmt::Display;

/// Symmetric encryption
#[derive(Debug, Clone, Copy)]
pub struct Local(&'static str);
impl PurposeTrait for Local {}
impl Default for Local {
  fn default() -> Self {
    Self("local")
  }
}
impl AsRef<str> for Local {
  fn as_ref(&self) -> &str {
    self.0
  }
}
impl Display for Local {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", self.0)
  }
}
