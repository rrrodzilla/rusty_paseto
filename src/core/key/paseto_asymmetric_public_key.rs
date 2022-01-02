use super::Key;
use crate::core::*;
use std::convert::{AsRef, From};
use std::marker::PhantomData;

pub struct PasetoAsymmetricPublicKey<'a, Version, Purpose> {
  version: PhantomData<Version>,
  purpose: PhantomData<Purpose>,
  key: &'a [u8],
}

impl<'a, Version, Purpose> AsRef<[u8]> for PasetoAsymmetricPublicKey<'a, Version, Purpose> {
  fn as_ref(&self) -> &[u8] {
    self.key
  }
}

#[cfg(feature = "v1_public")]
impl<'a> From<&'a [u8]> for PasetoAsymmetricPublicKey<'a, V1, Public> {
  fn from(key: &'a [u8]) -> Self {
    Self {
      version: PhantomData,
      purpose: PhantomData,
      key,
    }
  }
}

impl<'a, Version> From<&'a Key<32>> for PasetoAsymmetricPublicKey<'a, Version, Public>
where
  Version: V2orV4,
{
  fn from(key: &'a Key<32>) -> Self {
    Self {
      version: PhantomData,
      purpose: PhantomData,
      key: key.as_ref(),
    }
  }
}
