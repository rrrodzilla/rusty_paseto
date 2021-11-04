use base64::{decode_config, encode_config, DecodeError, URL_SAFE_NO_PAD};
use ring::constant_time::verify_slices_are_equal as ConstantTimeEquals;
//use serde::{Serialize, Serializer};
use crate::keys::Key256Bit;
use ed25519_dalek::*;
use std::{convert::AsRef, fmt::Display};

/// Handles encoding, decoding and comparing Base64Encoded strings
///
/// Encoded strings are compared in constant time.
/// ...
///
pub(crate) trait Base64Encodable<T: ?Sized + std::convert::AsRef<[u8]>>: Display + AsRef<T> {
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

/// a simple marker trait to identify claims
pub trait PasetoClaim: erased_serde::Serialize {
  fn get_key(&self) -> &str;
}

pub trait Sodium: Display + Default {}
pub trait Nist: Display + Default {}
pub trait SymmetricKey: AsRef<Key256Bit> {}
pub trait AsymmetricKey: AsRef<Keypair> {}
