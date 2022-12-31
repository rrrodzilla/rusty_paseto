use super::PasetoClaim;
#[cfg(feature = "serde")]
use serde::ser::SerializeMap;

///The reserved ['sub'](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/04-Claims.md) PASETO claim
#[derive(Clone)]
pub struct SubjectClaim<'a>((&'a str, &'a str));

impl<'a> PasetoClaim for SubjectClaim<'a> {
  fn get_key(&self) -> &str {
    self.0 .0
  }
}

impl<'a> Default for SubjectClaim<'a> {
  fn default() -> Self {
    Self(("sub", ""))
  }
}

//created using the From trait
impl<'a> From<&'a str> for SubjectClaim<'a> {
  fn from(s: &'a str) -> Self {
    Self(("sub", s))
  }
}

//want to receive a reference as a tuple
impl<'a> AsRef<(&'a str, &'a str)> for SubjectClaim<'a> {
  fn as_ref(&self) -> &(&'a str, &'a str) {
    &self.0
  }
}

#[cfg(feature = "serde")]
impl<'a> serde::Serialize for SubjectClaim<'a> {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: serde::Serializer,
  {
    let mut map = serializer.serialize_map(Some(2))?;
    map.serialize_entry(self.0 .0, self.0 .1)?;
    map.end()
  }
}
