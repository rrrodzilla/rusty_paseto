use super::*;
use crate::core::*;
use std::convert::{AsRef, From};
use std::marker::PhantomData;

/// A wrapper for the private half of an asymmetric key pair
///
/// [V2] and [V4] keys are created from [Key] of size 64, [V1] keys are of an arbitrary size
pub struct PasetoAsymmetricPrivateKey<'a, Version, Purpose> {
  version: PhantomData<Version>,
  purpose: PhantomData<Purpose>,
  key: &'a [u8],
}

impl<'a, Version> From<&'a [u8]> for PasetoAsymmetricPrivateKey<'a, Version, Public>
where
  Version: V2orV4,
{
  fn from(key: &'a [u8]) -> Self {
    Self {
      version: PhantomData,
      purpose: PhantomData,
      key,
    }
  }
}

impl<'a, Version, Purpose> AsRef<[u8]> for PasetoAsymmetricPrivateKey<'a, Version, Purpose> {
  fn as_ref(&self) -> &[u8] {
    self.key
  }
}

#[cfg(feature = "v1_public")]
impl<'a> From<&'a [u8]> for PasetoAsymmetricPrivateKey<'a, V1, Public> {
  fn from(key: &'a [u8]) -> Self {
    Self {
      version: PhantomData,
      purpose: PhantomData,
      key,
    }
  }
}

impl<'a, Version> From<&'a Key<64>> for PasetoAsymmetricPrivateKey<'a, Version, Public>
where
  Version: V2orV4,
{
  fn from(key: &'a Key<64>) -> Self {
    Self {
      version: PhantomData,
      purpose: PhantomData,
      key: key.as_ref(),
    }
  }
}

#[cfg(feature = "v3_public")]
impl<'a> From<&'a Key<48>> for PasetoAsymmetricPrivateKey<'a, V3, Public> {
  fn from(key: &'a Key<48>) -> Self {
    Self {
      version: PhantomData,
      purpose: PhantomData,
      key: key.as_ref(),
    }
  }
}


