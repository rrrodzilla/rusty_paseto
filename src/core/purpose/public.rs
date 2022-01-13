use crate::core::traits::*;
use std::fmt;
use std::fmt::Display;

/// Asymmetric authentication (public-key signatures)
#[derive(Debug, Clone, Copy)]
pub struct Public(&'static str);

impl PurposeTrait for Public {}
impl AsRef<str> for Public {
  fn as_ref(&self) -> &str {
    self.0
  }
}
impl Default for Public {
  fn default() -> Self {
    Self("public")
  }
}

impl Display for Public {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", self.0)
  }
}
