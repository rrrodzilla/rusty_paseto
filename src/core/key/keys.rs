use crate::core::PasetoError;
use ring::rand::{SecureRandom, SystemRandom};
use std::convert::{From, TryFrom};
use std::ops::Deref;
use zeroize::Zeroize;

#[derive(Zeroize)]
#[zeroize(drop)]
#[derive(Clone, Debug)]
pub struct Key<const KEYSIZE: usize>([u8; KEYSIZE]);

impl<const KEYSIZE: usize> Default for Key<KEYSIZE> {
  fn default() -> Self {
    Self([0u8; KEYSIZE])
  }
}

impl<const KEYSIZE: usize> AsRef<[u8]> for Key<KEYSIZE> {
  fn as_ref(&self) -> &[u8] {
    &self.0
  }
}

impl<const KEYSIZE: usize> Deref for Key<KEYSIZE> {
  type Target = [u8; KEYSIZE];
  fn deref(&self) -> &Self::Target {
    &self.0
  }
}

impl<const KEYSIZE: usize> From<&[u8]> for Key<KEYSIZE> {
  fn from(key: &[u8]) -> Self {
    let mut me = Key::<KEYSIZE>::default();
    me.0.copy_from_slice(key);
    me
  }
}

impl<const KEYSIZE: usize> From<&[u8; KEYSIZE]> for Key<KEYSIZE> {
  fn from(key: &[u8; KEYSIZE]) -> Self {
    Self(*key)
  }
}

impl<const KEYSIZE: usize> From<[u8; KEYSIZE]> for Key<KEYSIZE> {
  fn from(key: [u8; KEYSIZE]) -> Self {
    Self(key)
  }
}

impl<const KEYSIZE: usize> TryFrom<&str> for Key<KEYSIZE> {
  type Error = hex::FromHexError;
  fn try_from(value: &str) -> Result<Self, Self::Error> {
    let key = hex::decode(value)?;
    let mut me = Key::<KEYSIZE>::default();
    me.0.copy_from_slice(&key);
    Ok(me)
  }
}

//  impl<T: FromHex, const KEYSIZE: usize> FromStr for Key<KEYSIZE>
//  where
//    FromHexError: std::convert::From<<T as FromHex>::Error>,
//    T: impl Into<str>,
//  {
//    type Err = FromHexError;

//    /// allows any arbitrary string that may or may not
//    /// be a hex value to be parsed into a hex value of a
//    /// given typed KeyBit size (Key256Bit or Key192Bit)
//    fn from_str(s: &str) -> Result<Self, Self::Err> {
//      let key = <T>::from_hex(s)?;
//      Ok(Self(key))
//    }
//  }

impl<const KEYSIZE: usize> Key<KEYSIZE> {
  pub fn try_new_random() -> Result<Self, PasetoError> {
    let rng = SystemRandom::new();
    let mut buf = [0u8; KEYSIZE];
    rng.fill(&mut buf)?;
    Ok(Self(buf))
  }
}
