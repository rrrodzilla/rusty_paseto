use hex::{FromHex, FromHexError};
use std::convert::{AsRef, From};
use std::default::Default;

pub type Key256BitSize = [u8; 32];
pub type Key192BitSize = [u8; 24];
pub type Key256Bit<'a> = &'a Key256BitSize;
pub type Key192Bit<'a> = &'a Key192BitSize;

pub struct V2SymmetricKey<'a>(Key256Bit<'a>);

impl<'a> From<Key256Bit<'a>> for V2SymmetricKey<'a> {
  fn from(key: Key256Bit<'a>) -> Self {
    Self(key)
  }
}

impl<'a> AsRef<Key256Bit<'a>> for V2SymmetricKey<'a> {
  fn as_ref(&self) -> &Key256Bit<'a> {
    &self.0
  }
}

impl<'a> Default for V2SymmetricKey<'a> {
  fn default() -> Self {
    Self(&[0; 32])
  }
}
pub(crate) struct NonceKey<'a>(Key192Bit<'a>);

impl<'a> Default for NonceKey<'a> {
  fn default() -> Self {
    Self(&[0; 24])
  }
}

impl<'a> From<Key192Bit<'a>> for NonceKey<'a> {
  fn from(key: Key192Bit<'a>) -> Self {
    Self(key)
  }
}

impl<'a> AsRef<Key192Bit<'a>> for NonceKey<'a> {
  fn as_ref(&self) -> &Key192Bit<'a> {
    &self.0
  }
}

pub fn get_key_from_hex_string<T: FromHex>(s: &str) -> Result<T, FromHexError>
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
  const KEY: Key256Bit = b"wubbalubbadubdubwubbalubbadubdub";

  #[test]
  fn test_hex_val_for_256_bit_key() {
    let hex_val = "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f";
    let key: Key256Bit = &get_key_from_hex_string::<Key256BitSize>(hex_val).expect("couldn't convert hex value to key");
    assert_eq!(key.as_ref().len(), 32);
  }

  #[test]
  fn test_hex_val_for_192_bit_key() {
    let hex_val = "45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b";
    let key: Key192Bit = &get_key_from_hex_string::<Key192BitSize>(hex_val).expect("couldn't convert hex value to key");
    assert_eq!(key.as_ref().len(), 24);
  }

  #[test]
  fn test_implied_bit_key() {
    let symmetric_key: V2SymmetricKey = KEY.into();
    assert_eq!(symmetric_key.as_ref(), &KEY)
  }

  #[test]
  fn test_nonce_key_random() {
    let random_buf = get_random_192_bit_buf();
    let nonce_key = NonceKey::from(&random_buf);
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

    let symmetric_key = V2SymmetricKey::from(&key);
    assert_eq!(symmetric_key.as_ref(), &&key)
  }
}
