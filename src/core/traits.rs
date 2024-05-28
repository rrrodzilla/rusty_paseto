use base64::DecodeError;
use base64::prelude::*;
use ring::constant_time::verify_slices_are_equal as ConstantTimeEquals;
use std::fmt::Display;

//marker traits
/// Used by marker traits to determine at compile time which PASETO version the user is attempting to use
pub trait VersionTrait: Display + Default + AsRef<str> {}
/// Used by marker traits to determine at compile time which PASETO purpose the user is attempting to use
pub trait PurposeTrait: Display + Default + AsRef<str> {}
pub trait V1orV3: VersionTrait {}
/// A marker trait used to determine if the PASETO token version is capable of using an implicit
/// assertion. Currently this applies only to V3/V4 PASETO tokens
pub trait ImplicitAssertionCapable: VersionTrait {}
pub trait V2orV4: VersionTrait {}

/// Enable a type to encode/decode to/from base64 and compare itself to another implementer using
/// constant time comparision
pub(crate) trait Base64Encodable<T: ?Sized + AsRef<[u8]>>: Display + AsRef<T> {
  fn encode(&self) -> String {
    BASE64_URL_SAFE_NO_PAD.encode(self.as_ref())
  }
  fn decode(&self) -> Result<Vec<u8>, DecodeError> {
    BASE64_URL_SAFE_NO_PAD.decode(self.as_ref())
  }
  fn constant_time_equals<B>(&self, other: B) -> bool
  where
    B: AsRef<str>,
  {
    ConstantTimeEquals(self.encode().as_ref(), other.as_ref().as_bytes()).is_ok()
  }
}
