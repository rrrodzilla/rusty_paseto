use crate::keys::{Key192Bit, Key256Bit};
use crate::v2::V2LocalTokenParseError;
use base64::{decode_config, encode_config, DecodeError, URL_SAFE_NO_PAD};
use blake2::digest::{Update, VariableOutput};
use blake2::VarBlake2b;
use chacha20poly1305::{
  aead::{Aead, NewAead, Payload as AeadPayload},
  XChaCha20Poly1305, XNonce,
};
use ring::constant_time::verify_slices_are_equal as ConstantTimeEquals;
use std::convert::{AsMut, AsRef, From};
use std::str::FromStr;

pub(crate) fn try_decrypt_payload<H, F, K>(
  payload: &str,
  header: &H,
  footer: &F,
  key: &K,
) -> Result<String, V2LocalTokenParseError>
where
  H: AsRef<str>,
  F: AsRef<str>,
  K: AsRef<Key256Bit>,
{
  let payload_encoded = payload.parse::<Base64EncodedString>()?;
  let mut payload_decoded = payload_encoded.decode()?;
  let (nonce, ciphertext) = payload_decoded.split_at_mut(24);

  let pae = PreAuthenticationEncoding::parse(&[header.as_ref().as_bytes(), nonce, footer.as_ref().as_bytes()]);
  let xnonce = Nonce::from(nonce);
  let aead = XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| V2LocalTokenParseError::Decrypt)?;
  match aead.decrypt(
    xnonce.as_ref(),
    AeadPayload {
      msg: ciphertext,
      aad: pae.as_ref(),
    },
  ) {
    Ok(decrypted) => String::from_utf8(decrypted).map_err(|_| V2LocalTokenParseError::Decrypt),
    Err(_) => Err(V2LocalTokenParseError::Decrypt),
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

#[derive(Clone)]
pub(crate) struct RawPayload(Vec<u8>);
impl From<Vec<u8>> for RawPayload {
  fn from(s: Vec<u8>) -> Self {
    Self(s)
  }
}
impl AsRef<Vec<u8>> for RawPayload {
  fn as_ref(&self) -> &Vec<u8> {
    &self.0
  }
}

#[derive(Clone, Debug)]
pub struct Base64EncodedString(String);

impl Base64EncodedString {
  pub fn decode(&self) -> Result<Vec<u8>, DecodeError> {
    decode_config(&self.0, URL_SAFE_NO_PAD)
  }
}

impl AsRef<str> for Base64EncodedString {
  fn as_ref(&self) -> &str {
    &self.0
  }
}
impl From<String> for Base64EncodedString {
  fn from(s: String) -> Self {
    Self(encode_config(s, URL_SAFE_NO_PAD))
  }
}
impl From<RawPayload> for Base64EncodedString {
  fn from(s: RawPayload) -> Self {
    Self(encode_config(s.as_ref(), URL_SAFE_NO_PAD))
  }
}

impl PartialEq for Base64EncodedString {
  fn eq(&self, other: &Self) -> bool {
    ConstantTimeEquals(self.as_ref().as_bytes(), other.as_ref().as_bytes()).is_ok()
  }
}

impl FromStr for Base64EncodedString {
  type Err = std::convert::Infallible;
  fn from_str(s: &str) -> Result<Self, Self::Err> {
    Ok(Self(s.to_string()))
  }
}

impl Eq for Base64EncodedString {}

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
#[cfg(test)]
mod tests {
  use blake2::digest::Update;
  use chacha20poly1305::{
    aead::{Aead, NewAead, Payload as AeadPayload},
    XChaCha20Poly1305,
  };

  use crate::crypto::{Base64EncodedString, PreAuthenticationEncoding, RawPayload};
  use crate::v2::Footer;
  use crate::v2::Header;
  use crate::{keys::*, v2::Payload};

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
      Header::default().as_ref().as_bytes(),
      finalized.as_ref(),
      Footer::default().as_ref().as_bytes(),
    ]);
    assert!(pae.as_ref().len() > 0);
  }

  #[test]
  fn test_aead_encrypt() {
    let nonce_key = NonceKey::new_random();

    let (nonce, pae, blake2_finalized) =
      get_aead_encrypt_prerequisites(&Payload::from(""), &Header::default(), &Footer::default(), &nonce_key);
    let key = V2LocalSharedKey::new_random();
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
    let encoded = Base64EncodedString::from(payload);
    assert!(encoded.as_ref().len() > 0);
  }

  #[test]
  fn test_aead() {
    let key = V2LocalSharedKey::new_random();
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
