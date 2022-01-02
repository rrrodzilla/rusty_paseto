use super::{PasetoClaim, PasetoClaimError};
#[cfg(feature = "serde")]
use serde::ser::SerializeMap;

#[derive(Clone, Debug)]
pub struct CustomClaim<T>((String, T));

impl<T> CustomClaim<T> {
  //TODO: this needs to be refactored to be configurable for eventual compressed token
  //implementations
  pub(self) const RESERVED_CLAIMS: [&'static str; 7] = ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"];

  fn check_if_reserved_claim_key(key: &str) -> Result<(), PasetoClaimError> {
    match key {
      key if Self::RESERVED_CLAIMS.contains(&key) => Err(PasetoClaimError::Reserved(key.into())),
      _ => Ok(()),
    }
  }
}

#[cfg(feature = "serde")]
impl<T: serde::Serialize> PasetoClaim for CustomClaim<T> {
  fn get_key(&self) -> &str {
    &self.0 .0
  }
}

impl TryFrom<&str> for CustomClaim<&str> {
  type Error = PasetoClaimError;

  fn try_from(key: &str) -> Result<Self, Self::Error> {
    Self::check_if_reserved_claim_key(key)?;
    Ok(Self((String::from(key), "")))
  }
}

impl<T> TryFrom<(String, T)> for CustomClaim<T> {
  type Error = PasetoClaimError;

  fn try_from(val: (String, T)) -> Result<Self, Self::Error> {
    Self::check_if_reserved_claim_key(val.0.as_str())?;
    Ok(Self((val.0, val.1)))
  }
}

impl<T> TryFrom<(&str, T)> for CustomClaim<T> {
  type Error = PasetoClaimError;

  fn try_from(val: (&str, T)) -> Result<Self, Self::Error> {
    Self::check_if_reserved_claim_key(val.0)?;
    Ok(Self((String::from(val.0), val.1)))
  }
}

//we want to receive a reference as a tuple
impl<T> AsRef<(String, T)> for CustomClaim<T> {
  fn as_ref(&self) -> &(String, T) {
    &self.0
  }
}

#[cfg(feature = "serde")]
impl<T: serde::Serialize> serde::Serialize for CustomClaim<T> {
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
