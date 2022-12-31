use super::{PasetoClaim, PasetoClaimError};
#[cfg(feature = "serde")]
use serde::ser::SerializeMap;

///The reserved ['exp'](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/04-Claims.md) PASETO claim
#[derive(Clone)]
pub struct ExpirationClaim((String, String));
impl PasetoClaim for ExpirationClaim {
  fn get_key(&self) -> &str {
    self.0 .0.as_str()
  }
}

impl Default for ExpirationClaim {
  fn default() -> Self {
    Self(("exp".to_string(), "2019-01-01T00:00:00+00:00".to_string()))
  }
}

impl TryFrom<String> for ExpirationClaim {
  type Error = PasetoClaimError;

  fn try_from(value: String) -> Result<Self, Self::Error> {
    match iso8601::datetime(&value) {
      Ok(_) => Ok(Self(("exp".to_string(), value))),
      Err(_) => Err(PasetoClaimError::RFC3339Date(value.to_string())),
    }
  }
}

impl TryFrom<&str> for ExpirationClaim {
  type Error = PasetoClaimError;

  fn try_from(value: &str) -> Result<Self, Self::Error> {
    match iso8601::datetime(value) {
      Ok(_) => Ok(Self(("exp".to_string(), value.to_string()))),
      Err(_) => Err(PasetoClaimError::RFC3339Date(value.to_string())),
    }
  }
}

//want to receive a reference as a tuple
impl AsRef<(String, String)> for ExpirationClaim {
  fn as_ref(&self) -> &(String, String) {
    &self.0
  }
}

#[cfg(feature = "serde")]
impl serde::Serialize for ExpirationClaim {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: serde::Serializer,
  {
    let mut map = serializer.serialize_map(Some(2))?;
    map.serialize_key(&self.0 .0)?;
    map.serialize_value(&self.0 .1)?;
    map.end()
  }
}
