use crate::core::PasetoError;
use ring::rand::{SecureRandom, SystemRandom};
use std::convert::{From, TryFrom};
use std::fmt::Debug;
use std::ops::Deref;
use zeroize::Zeroize;

/// A wrapper for a slice of bytes that constitute a key of a specific size
#[derive(Zeroize)]
#[zeroize(drop)]
#[derive(Clone)]
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

impl<const KEYSIZE: usize> Key<KEYSIZE> {
  /// Uses the system's RNG to create a random slice of bytes of a specific size
  pub fn try_new_random() -> Result<Self, PasetoError> {
    let rng = SystemRandom::new();
    let mut buf = [0u8; KEYSIZE];
    rng.fill(&mut buf)?;
    Ok(Self(buf))
  }
}

impl<const KEYSIZE: usize> Debug for Key<KEYSIZE> {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "!!! KEY IS PRIVATE !!!")
  }
}
