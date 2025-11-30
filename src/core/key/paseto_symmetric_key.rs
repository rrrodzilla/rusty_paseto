use super::Key;
use crate::core::Local;
use std::convert::{AsRef, From};
use std::marker::PhantomData;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A wrapper for a symmetric key
///
/// Keys are created from [Key] of size 32
///
/// This type implements [Zeroize] and [ZeroizeOnDrop] to ensure the key material
/// is securely cleared from memory when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PasetoSymmetricKey<Version, Purpose> {
  #[zeroize(skip)]
  version: PhantomData<Version>,
  #[zeroize(skip)]
  purpose: PhantomData<Purpose>,
  key: Key<32>,
}

impl<Version> From<Key<32>> for PasetoSymmetricKey<Version, Local> {
  fn from(key: Key<32>) -> Self {
    Self {
      version: PhantomData,
      purpose: PhantomData,
      key,
    }
  }
}

impl<Version, Purpose> AsRef<[u8]> for PasetoSymmetricKey<Version, Purpose> {
  fn as_ref(&self) -> &[u8] {
    self.key.as_ref()
  }
}
