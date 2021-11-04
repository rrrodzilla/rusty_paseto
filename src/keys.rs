use crate::common::{Local, Public, V2, V4};
use crate::traits::{AsymmetricKey, Sodium, SymmetricKey};
use ed25519_dalek::{Keypair, SignatureError};
use hex::{FromHex, FromHexError};
use ring::rand::{SecureRandom, SystemRandom};
use std::any::Any;
use std::convert::{AsRef, From, TryFrom};
use std::default::Default;
use std::marker::PhantomData;
use std::str::FromStr;

/// A type to ensure u8 arrays with exactly 32 elements
/// to allow for the creation of 256 bit keys
pub type Key256Bit = [u8; 32];
pub type Key512Bit = [u8; 64];
/// A type to ensure u8 arrays with exactly 24 elements
/// to allow for the creation of 192 bit keys
pub type Key192Bit = [u8; 24];

/// A structure for parsing strings which might be hex keys of a particular size
pub struct HexKey<T>(T);
impl From<&Key192Bit> for HexKey<Key192Bit> {
  /// Only allows hex keys of the correct size
  fn from(key: &Key192Bit) -> Self {
    Self(*key)
  }
}

///Allows any string to attempt to be parsed into a HexKey
impl<T: FromHex> FromStr for HexKey<T>
where
  FromHexError: std::convert::From<<T as FromHex>::Error>,
{
  type Err = FromHexError;

  /// allows any arbitrary string that may or may not
  /// be a hex value to be parsed into a hex value of a
  /// given typed KeyBit size (Key256Bit or Key192Bit)
  fn from_str(s: &str) -> Result<Self, Self::Err> {
    let key = <T>::from_hex(s)?;
    Ok(Self(key))
  }
}

///Allows access to the internal hex key
impl<T> AsRef<T> for HexKey<T> {
  fn as_ref(&self) -> &T {
    &self.0
  }
}

pub struct Key<Version, Purpose> {
  version: PhantomData<Version>,
  purpose: PhantomData<Purpose>,
  key: Box<dyn Any>,
}

impl TryFrom<&Key512Bit> for Key<V2, Public> {
  type Error = SignatureError;
  fn try_from(k: &Key512Bit) -> Result<Self, Self::Error> {
    let key = Keypair::from_bytes(k)?;
    Ok(Self {
      version: PhantomData,
      purpose: PhantomData,
      key: Box::new(key),
    })
  }
}

impl TryFrom<&Key512Bit> for Key<V4, Public> {
  type Error = SignatureError;
  fn try_from(k: &Key512Bit) -> Result<Self, Self::Error> {
    let key = Keypair::from_bytes(k)?;
    Ok(Self {
      version: PhantomData,
      purpose: PhantomData,
      key: Box::new(key),
    })
  }
}

impl From<&Key256Bit> for Key<V2, Local> {
  /// Creates a V2LocalSharedKey from a Key256Bit structure
  fn from(key: &Key256Bit) -> Self {
    Self {
      version: PhantomData,
      purpose: PhantomData,
      key: Box::new(*key),
    }
  }
}

impl From<Key256Bit> for Key<V2, Local> {
  /// Creates a V2LocalSharedKey from a Key256Bit structure
  fn from(key: Key256Bit) -> Self {
    Self {
      version: PhantomData,
      purpose: PhantomData,
      key: Box::new(key),
    }
  }
}

impl AsymmetricKey for Key<V4, Public> {}
impl AsRef<Keypair> for Key<V4, Public> {
  fn as_ref(&self) -> &Keypair {
    self.key.as_ref().downcast_ref().unwrap()
  }
}

impl AsymmetricKey for Key<V2, Public> {}
impl AsRef<Keypair> for Key<V2, Public> {
  fn as_ref(&self) -> &Keypair {
    self.key.as_ref().downcast_ref().unwrap()
  }
}

impl SymmetricKey for Key<V2, Local> {}
impl AsRef<Key256Bit> for Key<V2, Local> {
  fn as_ref(&self) -> &Key256Bit {
    self.key.as_ref().downcast_ref().unwrap()
  }
}

impl Default for Key<V2, Local> {
  fn default() -> Self {
    Self {
      version: PhantomData,
      purpose: PhantomData,
      key: Box::new([0; 32]),
    }
  }
}

impl<Version> Key<Version, Local>
where
  Version: Sodium,
{
  ///Returns a new valid random V2LocalSharedKey
  pub fn new_random() -> Self {
    let rng = SystemRandom::new();
    let mut buf = [0u8; 32];
    rng.fill(&mut buf).unwrap();
    Self {
      version: PhantomData,
      purpose: PhantomData,
      key: Box::new(buf),
    }
  }
}

impl From<HexKey<Key256Bit>> for Key<V2, Local> {
  /// Only allows hex keys of the correct size
  fn from(key: HexKey<Key256Bit>) -> Self {
    Self {
      version: PhantomData,
      purpose: PhantomData,
      key: Box::new(*key.as_ref()),
    }
  }
}
#[derive(Debug, PartialEq)]
pub(crate) struct NonceKey(Key192Bit);

impl Default for NonceKey {
  fn default() -> Self {
    Self([0; 24])
  }
}

/// Only allows hex keys of the correct size
impl From<HexKey<Key192Bit>> for NonceKey {
  fn from(key: HexKey<Key192Bit>) -> Self {
    Self(*key.as_ref())
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
  pub fn new_random() -> Self {
    let rng = SystemRandom::new();
    let mut buf = [0u8; 24];
    rng.fill(&mut buf).unwrap();
    Self(buf)
  }
}

#[cfg(test)]
mod unit_tests {

  use super::*;
  use anyhow::Result;
  use std::convert::{AsRef, From};

  //this doesn't compile without a properly sized key
  //which is what we want
  const KEY: Key256Bit = *b"wubbalubbadubdubwubbalubbadubdub";

  #[test]
  fn test_key_pair() -> Result<()> {
    let pk = "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2"
        .parse::<HexKey<Key512Bit>>()?;
    let keypair = Key::<V2, Public>::try_from(pk.as_ref())?;
    let key = keypair.as_ref();
    let secret = &key.secret;
    assert_eq!(secret.as_bytes().len(), 32);
    Ok(())
  }

  #[test]
  fn test_new_random_key() {
    let key = Key::<V2, Local>::new_random();
    assert_eq!(key.as_ref().len(), 32);
  }

  #[test]
  fn test_hex_val_for_256_bit_key() {
    let hex_val = "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f"
      .parse::<HexKey<Key256Bit>>()
      .expect("oops!");
    let key = Key::<V2, Local>::from(hex_val);
    assert_eq!(key.as_ref().len(), 32);
  }

  #[test]
  fn test_bad_hex_val_for_256_bit_key() {
    //that first 'B' should NOT B there :-\
    let bad_hex = "B707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f".parse::<HexKey<Key256Bit>>();
    assert!(bad_hex.is_err());
    //another try
    let another_bad_hex = "probably not".parse::<HexKey<Key256Bit>>();
    assert!(another_bad_hex.is_err());
  }

  #[test]
  fn test_hex_val_for_192_bit_key() {
    let key = "45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b"
      .parse::<HexKey<Key192Bit>>()
      .expect("Could not parse hex value from string");
    assert_eq!(key.as_ref().len(), 24);
  }

  #[test]
  fn test_bad_hex_val_for_192_bit_key() {
    let bad_hex = "B707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f".parse::<HexKey<Key192Bit>>();
    //that first 'B' should NOT B there :-\
    assert!(bad_hex.is_err());
  }

  #[test]
  fn test_implied_bit_key() {
    let symmetric_key: Key<V2, Local> = KEY.into();
    assert_eq!(symmetric_key.as_ref(), &KEY)
  }

  #[test]
  fn test_nonce_key_random() {
    let nonce_key = NonceKey::new_random();
    assert_eq!(&nonce_key.as_ref().len(), &24);
  }
  #[test]
  fn test_explicit_convert() {
    let symmetric_key = Key::<V2, Local>::from(KEY);
    assert_eq!(symmetric_key.as_ref(), &KEY)
  }
}
