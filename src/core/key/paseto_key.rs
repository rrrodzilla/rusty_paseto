use super::Key;
use crate::core::{Local, Public};
use crate::core::{V1, V2, V3, V4};
use std::convert::{AsRef, From};
use std::marker::PhantomData;

pub struct PasetoKey<'a, Version, Purpose> {
  version: PhantomData<Version>,
  purpose: PhantomData<Purpose>,
  key: &'a [u8],
}

impl<'a, Version, Purpose> AsRef<[u8]> for PasetoKey<'a, Version, Purpose> {
  fn as_ref(&self) -> &[u8] {
    self.key
  }
}

impl<'a> From<&'a Key<32>> for PasetoKey<'a, V1, Local> {
  fn from(key: &'a Key<32>) -> Self {
    Self {
      version: PhantomData,
      purpose: PhantomData,
      key: key.as_ref(),
    }
  }
}

impl<'a> From<&'a [u8]> for PasetoKey<'a, V1, Public> {
  fn from(key: &'a [u8]) -> Self {
    Self {
      version: PhantomData,
      purpose: PhantomData,
      key,
    }
  }
}

impl<'a> From<&'a Key<32>> for PasetoKey<'a, V2, Local> {
  fn from(key: &'a Key<32>) -> Self {
    Self {
      version: PhantomData,
      purpose: PhantomData,
      key: key.as_ref(),
    }
  }
}

impl<'a> From<&'a Key<64>> for PasetoKey<'a, V2, Public> {
  fn from(key: &'a Key<64>) -> Self {
    Self {
      version: PhantomData,
      purpose: PhantomData,
      key: key.as_ref(),
    }
  }
}

impl<'a> From<&'a Key<32>> for PasetoKey<'a, V3, Local> {
  fn from(key: &'a Key<32>) -> Self {
    Self {
      version: PhantomData,
      purpose: PhantomData,
      key: key.as_ref(),
    }
  }
}

impl<'a> From<&'a [u8]> for PasetoKey<'a, V4, Public> {
  fn from(key: &'a [u8]) -> Self {
    Self {
      version: PhantomData,
      purpose: PhantomData,
      key,
    }
  }
}

impl<'a> From<&'a Key<64>> for PasetoKey<'a, V4, Public> {
  fn from(key: &'a Key<64>) -> Self {
    Self {
      version: PhantomData,
      purpose: PhantomData,
      key: key.as_ref(),
    }
  }
}

impl<'a> From<&'a Key<32>> for PasetoKey<'a, V4, Public> {
  fn from(key: &'a Key<32>) -> Self {
    Self {
      version: PhantomData,
      purpose: PhantomData,
      key: key.as_ref(),
    }
  }
}

impl<'a> From<&'a Key<32>> for PasetoKey<'a, V4, Local> {
  fn from(key: &'a Key<32>) -> Self {
    Self {
      version: PhantomData,
      purpose: PhantomData,
      key: key.as_ref(),
    }
  }
}

impl<'a> From<&'a Key<32>> for PasetoKey<'a, V2, Public> {
  fn from(key: &'a Key<32>) -> Self {
    Self {
      version: PhantomData,
      purpose: PhantomData,
      key: key.as_ref(),
    }
  }
}

#[cfg(test)]
mod builders {
  use std::convert::From;

  use crate::core::*;
  use anyhow::Result;

  use super::PasetoKey;

  #[test]
  fn v2_local_key_test() -> Result<()> {
    let key = Key::<32>::from(b"wubbalubbadubdubwubbalubbadubdub");
    let paseto_key = PasetoKey::<V2, Local>::from(&key);
    assert_eq!(paseto_key.as_ref().len(), key.as_ref().len());
    Ok(())
  }
}
