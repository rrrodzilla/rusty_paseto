use super::Key;
use crate::core::Public;
use crate::core::{V2orV4, V1};
use std::convert::{AsRef, From};
use std::marker::PhantomData;

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
