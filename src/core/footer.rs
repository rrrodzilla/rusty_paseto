use super::*;
use std::fmt;
use std::ops::Deref;

/// Unencrypted text, potentially JSON or some other structured format, typically used for key rotation schemes, packed into the
/// payload as part of the cipher scheme.  
///
/// # Usage
/// ```
/// # #[cfg(feature = "default")]
/// # {
/// # use rusty_paseto::prelude::*;
/// # let key = PasetoSymmetricKey::<V4, Local>::from(Key::<32>::from(b"wubbalubbadubdubwubbalubbadubdub"));
/// let token = PasetoBuilder::<V4, Local>::default()
///   // note how we set the footer here
///   .set_footer(Footer::from("Sometimes science is more art than science"))
///   .build(&key)?;
///
///    // the footer same footer should be used to parse the token
/// let json_value = PasetoParser::<V4, Local>::default()
///   .set_footer(Footer::from("Sometimes science is more art than science"))
///   .parse(&token, &key)?;
/// # }
/// # Ok::<(),anyhow::Error>(())
/// ```
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
