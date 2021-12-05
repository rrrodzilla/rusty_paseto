use base64::{decode_config, encode_config, DecodeError, URL_SAFE_NO_PAD};
use ring::constant_time::verify_slices_are_equal as ConstantTimeEquals;
use std::fmt::Display;

//marker traits
pub trait VersionTrait: Display + Default + AsRef<str> {}
pub trait PurposeTrait: Display + Default + AsRef<str> {}
pub trait V1orV3: VersionTrait {}
pub trait ImplicitAssertionCapable: VersionTrait {}
pub trait V2orV4: VersionTrait {}

/// Enable a type to encode/decode to/from base64 and compare itself to another implementer using
/// constant time comparision
pub(crate) trait Base64Encodable<T: ?Sized + AsRef<[u8]>>: Display + AsRef<T> {
  fn encode(&self) -> String {
    encode_config(self.as_ref(), URL_SAFE_NO_PAD)
  }
  fn decode(&self) -> Result<Vec<u8>, DecodeError> {
    decode_config(self.as_ref(), URL_SAFE_NO_PAD)
  }
  fn constant_time_equals<B>(&self, other: B) -> bool
  where
    B: AsRef<str>,
  {
    ConstantTimeEquals(self.encode().as_ref(), other.as_ref().as_bytes()).is_ok()
  }
}
