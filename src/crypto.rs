use crate::common::RawPayload;
use crate::errors::PasetoTokenParseError;
use crate::keys::{Key192Bit, Key256Bit};
use crate::traits::Base64Encodable;
use blake2::digest::{Update, VariableOutput};
use blake2::VarBlake2b;
use chacha20poly1305::{
  aead::{Aead, NewAead, Payload as AeadPayload},
  XChaCha20Poly1305, XNonce,
};
use std::convert::{AsMut, AsRef, From};

pub(crate) fn try_decrypt_payload<P, H, F, K>(
  payload: &P,
  header: &H,
  footer: &F,
  key: &K,
) -> Result<String, PasetoTokenParseError>
where
  P: AsRef<str> + Base64Encodable<str>,
  H: AsRef<str>,
  F: AsRef<str>,
  K: AsRef<Key256Bit>,
{
  let mut payload = payload.decode()?;
  let (nonce, ciphertext) = payload.split_at_mut(24);

  let pae = PreAuthenticationEncoding::parse(&[header.as_ref().as_bytes(), nonce, footer.as_ref().as_bytes()]);
  let xnonce = Nonce::from(nonce);
  let aead = XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| PasetoTokenParseError::Decrypt)?;
  match aead.decrypt(
    xnonce.as_ref(),
    AeadPayload {
      msg: ciphertext,
      aad: pae.as_ref(),
    },
  ) {
    Ok(decrypted) => String::from_utf8(decrypted).map_err(|_| PasetoTokenParseError::Decrypt),
    Err(_) => Err(PasetoTokenParseError::Decrypt),
  }
}

pub(crate) fn get_encrypted_raw_payload<P, H, F, K, NK>(
  message: &P,
  header: &H,
  footer: &F,
  key: &K,
  nonce_key: &NK,
) -> RawPayload
where
  P: AsRef<str>,
  H: AsRef<str>,
  F: AsRef<str>,
  K: AsRef<Key256Bit>,
  NK: AsRef<Key192Bit>,
{
  let (nonce, pre_auth, blake2_finalized) = get_aead_encrypt_prerequisites(message, header, footer, nonce_key);
  let aead = XChaCha20Poly1305::new_from_slice(key.as_ref());

  assert!(aead.is_ok());

  let crypted = aead
    .unwrap()
    .encrypt(
      nonce.as_ref(),
      AeadPayload {
        msg: message.as_ref().as_bytes(),
        aad: pre_auth.as_ref(),
      },
    )
    .unwrap();

  let mut raw_payload = Vec::new();
  raw_payload.extend_from_slice(blake2_finalized.as_ref());
  raw_payload.extend_from_slice(crypted.as_ref());

  RawPayload::from(raw_payload)
}

pub(crate) fn get_blake2_finalized<P, NK>(message: &P, nonce_key: &NK) -> Blake2Finalized
where
  P: AsRef<str>,
  NK: AsRef<Key192Bit>,
{
  let mut hash_context = Blake2HashContext::from(nonce_key);
  hash_context.as_mut().update(message.as_ref().as_bytes());
  Blake2Finalized::from(hash_context)
}

pub(crate) fn get_aead_encrypt_prerequisites<P, H, F, NK>(
  message: &P,
  header: &H,
  footer: &F,
  nonce_key: &NK,
) -> (Nonce, PreAuthenticationEncoding, Blake2Finalized)
where
  P: AsRef<str>,
  H: AsRef<str>,
  F: AsRef<str>,
  NK: AsRef<Key192Bit>,
{
  let finalized = get_blake2_finalized(message, nonce_key);

  let pae = PreAuthenticationEncoding::parse(&[
    header.as_ref().as_bytes(),
    finalized.as_ref(),
    footer.as_ref().as_bytes(),
  ]);

  (Nonce::from(&finalized), pae, finalized)
}

pub struct PreAuthenticationEncoding(Vec<u8>);

/// Performs Pre-Authentication Encoding (or PAE) as described in the
/// Paseto Specification v2.
///
impl PreAuthenticationEncoding {
  /// * `pieces` - The Pieces to concatenate, and encode together.
  /// Refactored from original code found at
  /// https://github.com/instructure/paseto/blob/trunk/src/pae.rs
  pub fn parse<'a>(pieces: &'a [&'a [u8]]) -> Self {
    let the_vec = PreAuthenticationEncoding::le64(pieces.len() as u64);

    Self(pieces.iter().fold(the_vec, |mut acc, piece| {
      acc.extend(PreAuthenticationEncoding::le64(piece.len() as u64));
      acc.extend(piece.iter());
      acc
    }))
  }
  /// Encodes a u64-bit unsigned integer into a little-endian binary string.
  ///
  /// * `to_encode` - The u8 to encode.
  /// Copied and gently refactored from https://github.com/instructure/paseto/blob/trunk/src/pae.rs
  pub(crate) fn le64(mut to_encode: u64) -> Vec<u8> {
    let mut the_vec = Vec::with_capacity(8);

    for _idx in 0..8 {
      the_vec.push((to_encode & 255) as u8);
      to_encode >>= 8;
    }

    the_vec
  }
}
impl AsRef<Vec<u8>> for PreAuthenticationEncoding {
  fn as_ref(&self) -> &Vec<u8> {
    &self.0
  }
}

pub struct Blake2HashContext(VarBlake2b);

impl<R> From<R> for Blake2HashContext
where
  R: AsRef<Key192Bit>,
{
  fn from(nonce: R) -> Self {
    Self(VarBlake2b::new_keyed(nonce.as_ref(), nonce.as_ref().len()))
  }
}
impl AsRef<VarBlake2b> for Blake2HashContext {
  fn as_ref(&self) -> &VarBlake2b {
    &self.0
  }
}
impl AsMut<VarBlake2b> for Blake2HashContext {
  fn as_mut(&mut self) -> &mut VarBlake2b {
    &mut self.0
  }
}

pub struct Blake2Finalized(Box<[u8]>);

impl AsRef<Box<[u8]>> for Blake2Finalized {
  fn as_ref(&self) -> &Box<[u8]> {
    &self.0
  }
}
impl From<Blake2HashContext> for Blake2Finalized {
  fn from(mut hash_context: Blake2HashContext) -> Self {
    let swapped = std::mem::take(hash_context.as_mut());
    Self(swapped.finalize_boxed())
  }
}

pub struct Nonce(XNonce);
impl AsRef<XNonce> for Nonce {
  fn as_ref(&self) -> &XNonce {
    &self.0
  }
}
impl From<&Blake2Finalized> for Nonce {
  fn from(finalized_hash: &Blake2Finalized) -> Self {
    Self(*XNonce::from_slice(&*finalized_hash.as_ref()))
  }
}

impl From<&mut [u8]> for Nonce {
  fn from(nonce_slice: &mut [u8]) -> Self {
    Self(*XNonce::from_slice(nonce_slice))
  }
}

pub(crate) fn validate_footer_against_hex_encoded_footer_in_constant_time<F>(
  footer: Option<F>,
  encoded_footer_string: &Option<String>,
) -> Result<(), PasetoTokenParseError>
where
  F: AsRef<str> + Base64Encodable<str>,
{
  if let Some(encoded_footer_string) = encoded_footer_string {
    //this means we found a footer in the provided token string
    //so that means we should also have a provided footer when this method was called
    if let Some(footer) = footer {
      //test for non equality using ConstantTimeEquals
      if footer.constant_time_equals(encoded_footer_string) {
        Ok(())
      } else {
        Err(PasetoTokenParseError::FooterInvalid)
      }
    } else {
      //this means we found a footer in the provided string but there
      //wasn't one provided in the method call
      Err(PasetoTokenParseError::FooterInvalid)
    }
  } else {
    //this means there was no footer found in the provided token string
    if footer.is_some() {
      //if one was provided anyway, we should err
      Err(PasetoTokenParseError::FooterInvalid)
    } else {
      Ok(())
    }
  }
}
#[cfg(test)]
mod unit_tests {
  use blake2::digest::Update;
  use chacha20poly1305::{
    aead::{Aead, NewAead, Payload as AeadPayload},
    XChaCha20Poly1305,
  };

  use crate::headers::Header;
  use crate::keys::*;
  use crate::{common::Footer, traits::Base64Encodable};
  use crate::{
    common::{Payload, PurposeLocal, Version2},
    crypto::{PreAuthenticationEncoding, RawPayload},
  };

  use super::{get_aead_encrypt_prerequisites, get_blake2_finalized, Blake2Finalized, Blake2HashContext, Nonce};

  #[test]
  fn test_le64() {
    assert_eq!(vec![0, 0, 0, 0, 0, 0, 0, 0], PreAuthenticationEncoding::le64(0));
    assert_eq!(vec![10, 0, 0, 0, 0, 0, 0, 0], PreAuthenticationEncoding::le64(10));
  }

  #[test]
  fn test_pae() {
    // Constants taken from paseto source.
    assert_eq!(
      "0000000000000000",
      hex::encode(PreAuthenticationEncoding::parse(&[]).as_ref())
    );
    assert_eq!(
      "01000000000000000000000000000000",
      hex::encode(&PreAuthenticationEncoding::parse(&[&[]]).as_ref())
    );
    assert_eq!(
      "020000000000000000000000000000000000000000000000",
      hex::encode(&PreAuthenticationEncoding::parse(&[&[], &[]]).as_ref())
    );
    assert_eq!(
      "0100000000000000070000000000000050617261676f6e",
      hex::encode(&PreAuthenticationEncoding::parse(&["Paragon".as_bytes()]).as_ref())
    );
    assert_eq!(
      "0200000000000000070000000000000050617261676f6e0a00000000000000496e6974696174697665",
      hex::encode(&PreAuthenticationEncoding::parse(&["Paragon".as_bytes(), "Initiative".as_bytes(),]).as_ref())
    );
  }
  #[test]
  fn test_preauthentication_encoding() {
    let nonce_key = NonceKey::new_random();

    let finalized = get_blake2_finalized(&Payload::default(), &nonce_key);

    let pae = PreAuthenticationEncoding::parse(&[
      Header::<Version2, PurposeLocal>::default().as_ref().as_bytes(),
      finalized.as_ref(),
      Footer::default().as_ref().as_bytes(),
    ]);
    assert!(pae.as_ref().len() > 0);
  }

  #[test]
  fn test_aead_encrypt() {
    let nonce_key = NonceKey::new_random();

    let (nonce, pae, blake2_finalized) = get_aead_encrypt_prerequisites(
      &Payload::from(""),
      &Header::<Version2, PurposeLocal>::default(),
      &Footer::default(),
      &nonce_key,
    );
    let key = Key::<Version2, PurposeLocal>::new_random();
    let aead = XChaCha20Poly1305::new_from_slice(key.as_ref());
    assert!(aead.is_ok());

    let crypted = aead.unwrap().encrypt(
      nonce.as_ref(),
      AeadPayload {
        msg: "some message".as_bytes(),
        aad: pae.as_ref(),
      },
    );
    assert!(crypted.is_ok());
    let mut raw_payload = Vec::new();
    raw_payload.extend_from_slice(blake2_finalized.as_ref());
    raw_payload.extend_from_slice(crypted.unwrap().as_ref());
    let payload = RawPayload::from(raw_payload);
    let encoded = payload.encode();
    assert!(encoded.len() > 0);
  }

  #[test]
  fn test_aead() {
    let key = Key::<Version2, PurposeLocal>::new_random();
    let aead = XChaCha20Poly1305::new_from_slice(key.as_ref());
    assert!(aead.is_ok());
  }

  #[test]
  fn test_mutable_hash_context_into_finalized() {
    let nonce_key = NonceKey::new_random();

    let mut hash_context = Blake2HashContext::from(&nonce_key);
    hash_context.as_mut().update(b"wubbulubbadubdub");

    let finalized: Blake2Finalized = hash_context.into();

    assert_eq!(finalized.as_ref().len(), nonce_key.as_ref().len());
  }

  #[test]
  fn test_finalized_into_nonce() {
    let nonce_key = NonceKey::default();

    let mut hash_context = Blake2HashContext::from(&nonce_key);
    hash_context.as_mut().update(b"");

    let finalized: Blake2Finalized = hash_context.into();
    let nonce = Nonce::from(&finalized);

    assert_eq!(nonce.as_ref().len(), nonce_key.as_ref().len());
    assert!(nonce.as_ref().len() > 0);
  }
}
