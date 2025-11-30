use super::Key;
#[cfg(feature = "v1_public_insecure")]
use crate::core::V1;
#[cfg(feature = "v3_public")]
use crate::core::V3;
use crate::core::{Public, V2orV4};
use std::convert::{AsRef, From};
use std::marker::PhantomData;
#[cfg(any(
  feature = "v1_public_insecure",
  feature = "v2_public",
  feature = "v3_public",
  feature = "v4_public"
))]
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A wrapper for the private half of an asymmetric key pair (borrowed reference).
///
/// [V2] and [V4] keys are created from [Key] of size 64, [V1] keys are of an arbitrary size.
///
/// # Memory Safety Warning
///
/// ⚠️ **This struct holds a borrowed reference to key material and does NOT zeroize memory when dropped.**
///
/// The key material referenced by this struct:
/// - Is **not** cleared from memory when this struct is dropped
/// - Remains in memory until the original owner (e.g., [`Key<64>`]) is dropped and zeroized
/// - May persist in memory if the source is a raw `&[u8]` slice
///
/// ## Recommendations
///
/// 1. **Use [`Key<64>`] as the source** - The [`Key`] type implements [`Zeroize`] and clears memory on drop
/// 2. **Consider [`PasetoAsymmetricPrivateKeyOwned`]** - An owned variant that zeroizes on drop
/// 3. **Minimize lifetime** - Keep instances of this struct short-lived
/// 4. **Clear source data** - Ensure the underlying key material is zeroized after use
///
/// ## Example: Secure Usage Pattern
///
/// ```rust,ignore
/// // Good: Key<64> zeroizes on drop
/// let key_bytes = Key::<64>::try_new_random()?;
/// let private_key = PasetoAsymmetricPrivateKey::<V4, Public>::from(&key_bytes);
/// // ... use private_key ...
/// // key_bytes will be zeroized when dropped
/// ```
///
/// ## Why This Design?
///
/// This borrowed-reference design enables zero-copy operations and flexibility in key
/// management, but places the responsibility for secure memory handling on the caller.
/// For automatic zeroization, use [`PasetoAsymmetricPrivateKeyOwned`] instead.
pub struct PasetoAsymmetricPrivateKey<'a, Version, Purpose> {
  version: PhantomData<Version>,
  purpose: PhantomData<Purpose>,
  key: &'a [u8],
}

/// An owned wrapper for the private half of an asymmetric key pair with automatic zeroization.
///
/// Unlike [`PasetoAsymmetricPrivateKey`], this struct **owns** the key material and implements
/// [`Zeroize`] and [`ZeroizeOnDrop`] to securely clear the key from memory when dropped.
///
/// # Security
///
/// ✅ Key material is automatically zeroed when this struct is dropped, preventing sensitive
/// data from lingering in memory.
///
/// # Usage
///
/// ```rust,ignore
/// use rusty_paseto::core::*;
///
/// // Create from a Key<64>
/// let key = Key::<64>::try_new_random()?;
/// let private_key = PasetoAsymmetricPrivateKeyOwned::<V4, Public>::from(key);
///
/// // Use for signing
/// let token = Paseto::<V4, Public>::builder()
///     .set_payload(payload)
///     .try_sign(&private_key.as_borrowed())?;
///
/// // Key material is automatically zeroized when private_key is dropped
/// ```
// This struct is part of the public API for library consumers who want
// automatic zeroization of key material. It may not be used internally.
#[cfg(any(
  feature = "v1_public_insecure",
  feature = "v2_public",
  feature = "v3_public",
  feature = "v4_public"
))]
#[allow(dead_code)]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PasetoAsymmetricPrivateKeyOwned<Version, Purpose> {
  #[zeroize(skip)]
  version: PhantomData<Version>,
  #[zeroize(skip)]
  purpose: PhantomData<Purpose>,
  key: Vec<u8>,
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

// ============================================================================
// PasetoAsymmetricPrivateKeyOwned implementations
// ============================================================================

#[cfg(any(feature = "v2_public", feature = "v4_public"))]
impl<Version> From<Key<64>> for PasetoAsymmetricPrivateKeyOwned<Version, Public>
where
  Version: V2orV4,
{
  fn from(key: Key<64>) -> Self {
    Self {
      version: PhantomData,
      purpose: PhantomData,
      key: key.as_ref().to_vec(),
    }
  }
}

#[cfg(any(feature = "v2_public", feature = "v4_public"))]
impl<Version> From<Vec<u8>> for PasetoAsymmetricPrivateKeyOwned<Version, Public>
where
  Version: V2orV4,
{
  fn from(key: Vec<u8>) -> Self {
    Self {
      version: PhantomData,
      purpose: PhantomData,
      key,
    }
  }
}

#[cfg(any(
  feature = "v1_public_insecure",
  feature = "v2_public",
  feature = "v3_public",
  feature = "v4_public"
))]
impl<Version, Purpose> AsRef<[u8]> for PasetoAsymmetricPrivateKeyOwned<Version, Purpose> {
  fn as_ref(&self) -> &[u8] {
    &self.key
  }
}

#[cfg(any(
  feature = "v1_public_insecure",
  feature = "v2_public",
  feature = "v3_public",
  feature = "v4_public"
))]
impl<Version, Purpose> PasetoAsymmetricPrivateKeyOwned<Version, Purpose> {
  /// Returns a borrowed [`PasetoAsymmetricPrivateKey`] reference.
  ///
  /// This allows using the owned key with APIs that expect a borrowed key reference.
  #[allow(dead_code)]
  pub fn as_borrowed(&self) -> PasetoAsymmetricPrivateKey<'_, Version, Purpose> {
    PasetoAsymmetricPrivateKey {
      version: PhantomData,
      purpose: PhantomData,
      key: &self.key,
    }
  }
}

#[cfg(feature = "v3_public")]
impl From<Key<48>> for PasetoAsymmetricPrivateKeyOwned<V3, Public> {
  fn from(key: Key<48>) -> Self {
    Self {
      version: PhantomData,
      purpose: PhantomData,
      key: key.as_ref().to_vec(),
    }
  }
}

#[cfg(feature = "v1_public_insecure")]
impl From<Vec<u8>> for PasetoAsymmetricPrivateKeyOwned<V1, Public> {
  /// Creates a V1 owned private key from a Vec<u8>.
  ///
  /// # Security Warning
  ///
  /// V1 public tokens use RSA which is vulnerable to RUSTSEC-2023-0071 (Marvin Attack).
  /// Use V4 instead for new implementations.
  fn from(key: Vec<u8>) -> Self {
    Self {
      version: PhantomData,
      purpose: PhantomData,
      key,
    }
  }
}
