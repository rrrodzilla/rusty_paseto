#[cfg(feature = "local")]
use super::Key;
#[cfg(all(
  feature = "core",
  any(feature = "v2_public", feature = "v3_public", feature = "local")
))]
use crate::core::*;
use std::convert::AsRef;
#[cfg(all(feature = "core", any(feature = "v2_public", feature = "v3_public")))]
use std::convert::From;
use std::marker::PhantomData;
use std::ops::Deref;

/// A nonce key for use in PASETO algorithms
///
/// Key sizes for nonces are either 32 or 24 bytes in size
///
/// Nonces can be specified directly for testing or randomly in production
/// # Example usage
/// ```
/// # use serde_json::json;
/// # use rusty_paseto::core::*;
///
/// let key = PasetoSymmetricKey::<V4, Local>::from(Key::<32>::try_from("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")?);
/// // generate a random nonce with
/// let nonce = Key::<32>::try_new_random()?;
/// let nonce = PasetoNonce::<V4, Local>::from(&nonce);
///
/// let payload = json!({"data": "this is a secret message", "exp":"2022-01-01T00:00:00+00:00"}).to_string();
/// let payload = payload.as_str();
/// let payload = Payload::from(payload);
///
/// //create a public v4 token
/// let token = Paseto::<V4, Local>::builder()
///   .set_payload(payload)
///   .try_encrypt(&key, &nonce)?;
///
/// # Ok::<(),anyhow::Error>(())
/// ```

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

#[cfg(feature = "v1_local")]
impl<'a> From<&'a Key<32>> for PasetoNonce<'a, V1, Local> {
  fn from(key: &'a Key<32>) -> Self {
    Self {
      version: PhantomData,
      purpose: PhantomData,
      key: key.as_ref(),
    }
  }
}

#[cfg(feature = "v2_local")]
impl<'a> From<&'a Key<24>> for PasetoNonce<'a, V2, Local> {
  fn from(key: &'a Key<24>) -> Self {
    Self {
      version: PhantomData,
      purpose: PhantomData,
      key: key.as_ref(),
    }
  }
}

#[cfg(feature = "v2_local")]
impl<'a> From<&'a Key<32>> for PasetoNonce<'a, V2, Local> {
  fn from(key: &'a Key<32>) -> Self {
    Self {
      version: PhantomData,
      purpose: PhantomData,
      key: key.as_ref(),
    }
  }
}

#[cfg(feature = "v3_local")]
impl<'a> From<&'a Key<32>> for PasetoNonce<'a, V3, Local> {
  fn from(key: &'a Key<32>) -> Self {
    Self {
      version: PhantomData,
      purpose: PhantomData,
      key: key.as_ref(),
    }
  }
}

#[cfg(feature = "v4_local")]
impl<'a> From<&'a Key<32>> for PasetoNonce<'a, V4, Local> {
  fn from(key: &'a Key<32>) -> Self {
    Self {
      version: PhantomData,
      purpose: PhantomData,
      key: key.as_ref(),
    }
  }
}

#[cfg(feature = "v2_public")]
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

#[cfg(all(test, feature = "v2_local"))]
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
