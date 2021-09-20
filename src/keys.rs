use hex::{FromHex, FromHexError};
use std::convert::{AsRef, From};
use std::default::Default;

pub type Key256BitSize = [u8; 32];
pub type Key192BitSize = [u8; 24];
pub type Key256Bit = Key256BitSize;
pub type Key192Bit = Key192BitSize;

pub struct V2SymmetricKey(Key256Bit);

impl From<Key256Bit> for V2SymmetricKey {
  fn from(key: Key256Bit) -> Self {
    Self(key)
  }
}

impl AsRef<Key256Bit> for V2SymmetricKey {
  fn as_ref(&self) -> &Key256Bit {
    &self.0
  }
}

impl Default for V2SymmetricKey {
  fn default() -> Self {
    Self([0; 32])
  }
}

impl V2SymmetricKey {
  pub(crate) fn parse_from_hex(hex_string: &str) -> Result<Self, FromHexError> {
    let key = get_key_from_hex_string::<Key256BitSize>(hex_string)?;
    Ok(Self(key))
  }
}

pub(crate) struct NonceKey(Key192Bit);

impl Default for NonceKey {
  fn default() -> Self {
    Self([0; 24])
  }
}

impl From<Key192Bit> for NonceKey {
  fn from(key: Key192Bit) -> Self {
    Self(key)
  }
}

impl AsRef<Key192Bit> for NonceKey {
  fn as_ref(&self) -> &Key192Bit {
    &self.0
  }
}
impl NonceKey {
  fn parse_from_hex(hex_string: &str) -> Result<Self, FromHexError> {
    let key = get_key_from_hex_string::<Key192BitSize>(hex_string)?;
    Ok(Self(key))
  }
}

fn get_key_from_hex_string<T: FromHex>(s: &str) -> Result<T, FromHexError>
where
  FromHexError: From<<T as FromHex>::Error>,
{
  Ok(<T>::from_hex(s)?)
}

#[cfg(test)]
mod tests {

  use super::*;
  use crate::util::*;

  //this doesn't compile without a properly sized key
  //which is what we want
  const KEY: Key256Bit = *b"wubbalubbadubdubwubbalubbadubdub";

  #[test]
  fn test_hex_val_for_256_bit_key() {
    let hex_val = "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f";
    let key = V2SymmetricKey::parse_from_hex(hex_val).expect("couldn't convert hex value to key");
    assert_eq!(key.as_ref().len(), 32);
  }

  #[test]
  fn test_bad_hex_val_for_256_bit_key() {
    //that first 'B' should NOT B there :-\
    let hex_val = "B707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f";
    let key = V2SymmetricKey::parse_from_hex(hex_val);
    assert!(key.is_err());
  }

  #[test]
  fn test_hex_val_for_192_bit_key() {
    let key = NonceKey::parse_from_hex("45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b")
      .expect("Could not parse hex value from string");
    assert_eq!(key.as_ref().len(), 24);
  }

  #[test]
  fn test_bad_hex_val_for_192_bit_key() {
    //that first 'B' should NOT B there :-\
    let key = NonceKey::parse_from_hex("B45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b");
    assert!(key.is_err());
  }

  #[test]
  fn test_implied_bit_key() {
    let symmetric_key: V2SymmetricKey = KEY.into();
    assert_eq!(symmetric_key.as_ref(), &KEY)
  }

  #[test]
  fn test_nonce_key_random() {
    let random_buf = get_random_192_bit_buf();
    let nonce_key = NonceKey::from(random_buf);
    assert_eq!(&nonce_key.as_ref().len(), &24);
  }
  #[test]
  fn test_explicit_convert() {
    let symmetric_key = V2SymmetricKey::from(KEY);
    assert_eq!(symmetric_key.as_ref(), &KEY)
  }

  #[test]
  fn test_random_key() {
    let key = get_random_256_bit_buf();

    let symmetric_key = V2SymmetricKey::from(key);
    assert_eq!(symmetric_key.as_ref(), &key)
  }
}
