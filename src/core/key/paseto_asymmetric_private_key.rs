use super::Key;
#[cfg(feature = "v1_public_insecure")]
use crate::core::V1;
#[cfg(feature = "v3_public")]
use crate::core::V3;
use crate::core::{Public, V2orV4};
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

impl<Version, Purpose> AsRef<[u8]> for PasetoAsymmetricPrivateKey<'_, Version, Purpose> {
  fn as_ref(&self) -> &[u8] {
    self.key
  }
}

#[cfg(feature = "v1_public_insecure")]
impl<'a> From<&'a [u8]> for PasetoAsymmetricPrivateKey<'a, V1, Public> {
  /// Creates a V1 private key from a byte slice.
  ///
  /// # Security Warning
  ///
  /// V1 public tokens use RSA which is vulnerable to RUSTSEC-2023-0071 (Marvin Attack).
  /// Use V4 instead for new implementations.
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


