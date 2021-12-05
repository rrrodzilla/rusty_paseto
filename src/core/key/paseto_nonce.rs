use super::Key;
use crate::core::{Local, Public};
use crate::core::{V1, V2, V3, V4};
use std::convert::{AsRef, From};
use std::marker::PhantomData;
use std::ops::Deref;

pub struct PasetoNonce<'a, Version, Purpose> {
  version: PhantomData<Version>,
  purpose: PhantomData<Purpose>,
  key: &'a [u8],
}

impl<'a, Version, Purpose> Deref for PasetoNonce<'a, Version, Purpose> {
  type Target = [u8];
  fn deref(&self) -> &Self::Target {
    self.key
  }
}

impl<'a, Version, Purpose> AsRef<[u8]> for PasetoNonce<'a, Version, Purpose> {
  fn as_ref(&self) -> &[u8] {
    self.key
  }
}

impl<'a> From<&'a Key<32>> for PasetoNonce<'a, V1, Local> {
  fn from(key: &'a Key<32>) -> Self {
    Self {
      version: PhantomData,
      purpose: PhantomData,
      key: key.as_ref(),
    }
  }
}

impl<'a> From<&'a Key<24>> for PasetoNonce<'a, V2, Local> {
  fn from(key: &'a Key<24>) -> Self {
    Self {
      version: PhantomData,
      purpose: PhantomData,
      key: key.as_ref(),
    }
  }
}

impl<'a> From<&'a Key<32>> for PasetoNonce<'a, V2, Local> {
  fn from(key: &'a Key<32>) -> Self {
    Self {
      version: PhantomData,
      purpose: PhantomData,
      key: key.as_ref(),
    }
  }
}

impl<'a> From<&'a Key<32>> for PasetoNonce<'a, V3, Local> {
  fn from(key: &'a Key<32>) -> Self {
    Self {
      version: PhantomData,
      purpose: PhantomData,
      key: key.as_ref(),
    }
  }
}

impl<'a> From<&'a Key<32>> for PasetoNonce<'a, V4, Local> {
  fn from(key: &'a Key<32>) -> Self {
    Self {
      version: PhantomData,
      purpose: PhantomData,
      key: key.as_ref(),
    }
  }
}

impl<'a, T> From<&'a T> for PasetoNonce<'a, V2, Public>
where
  T: Into<&'a [u8]>,
  &'a [u8]: From<&'a T>,
{
  fn from(key: &'a T) -> Self {
    Self {
      version: PhantomData,
      purpose: PhantomData,
      key: key.into(),
    }
  }
}

#[cfg(test)]
mod builders {
  use std::convert::From;

  use crate::core::*;
  use anyhow::Result;

  use super::PasetoNonce;

  #[test]
  fn v2_local_key_test() -> Result<()> {
    let key = Key::<32>::from(b"wubbalubbadubdubwubbalubbadubdub");
    let paseto_key = PasetoNonce::<V2, Local>::from(&key);
    assert_eq!(paseto_key.as_ref().len(), key.as_ref().len());
    Ok(())
  }
}
