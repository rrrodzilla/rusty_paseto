use std::convert::AsRef;
use std::marker::PhantomData;
use std::ops::Deref;

/// A nonce key for use in PASETO algorithms
///
/// Key sizes for nonces are either 32 or 24 bytes in size
///
/// Nonces can be specified directly for testing or randomly in production
/// # Example usage
/// ```
/// # #[cfg(feature = "v4_local")]
/// # {
/// use serde_json::json;
/// use rusty_paseto::core::*;
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
/// # }
/// # Ok::<(),anyhow::Error>(())
/// ```


pub struct PasetoNonce<'a, Version, Purpose> {
  pub(crate) version: PhantomData<Version>,
  pub(crate) purpose: PhantomData<Purpose>,
  pub(crate) key: &'a [u8],
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









