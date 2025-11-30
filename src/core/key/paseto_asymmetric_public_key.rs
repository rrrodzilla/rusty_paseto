use super::Key;
#[cfg(feature = "v1_public_insecure")]
use crate::core::V1;
#[cfg(feature = "v3_public")]
use crate::core::{PasetoError, V3};
use crate::core::{Public, V2orV4};
use std::convert::{AsRef, From};
use std::marker::PhantomData;

/// A wrapper for the public half of an asymmetric key pair
///
/// [V2] and [V4] keys are created from [Key] of size 32, [V1] keys are of an arbitrary size
pub struct PasetoAsymmetricPublicKey<'a, Version, Purpose> {
  version: PhantomData<Version>,
  purpose: PhantomData<Purpose>,
  key: &'a [u8],
}

impl<Version, Purpose> AsRef<[u8]> for PasetoAsymmetricPublicKey<'_, Version, Purpose> {
  fn as_ref(&self) -> &[u8] {
    self.key
  }
}

#[cfg(feature = "v1_public_insecure")]
impl<'a> From<&'a [u8]> for PasetoAsymmetricPublicKey<'a, V1, Public> {
  /// Creates a V1 public key from a byte slice.
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

#[cfg(feature = "v3_public")]
impl<'a> TryFrom<&'a Key<49>> for PasetoAsymmetricPublicKey<'a, V3, Public> {
  type Error = PasetoError;
  fn try_from(key: &'a Key<49>) -> Result<Self, Self::Error> {
    if key[0] != 2 && key[0] != 3 {
      return Err(PasetoError::InvalidKey);
    }
    //if this is successful, we can be sure our key is in a valid format
    Ok(Self {
      version: PhantomData,
      purpose: PhantomData,
      key: key.as_ref(),
    })
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
