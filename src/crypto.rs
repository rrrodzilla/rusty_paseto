use crate::keys::NonceKey;
use crate::v2::{Footer, Header, Message, RawPayload};
use crate::{get_key_from_hex_string, Key192BitSize, V2SymmetricKey};
use blake2::digest::{Update, VariableOutput};
use blake2::VarBlake2b;
use chacha20poly1305::{
  aead::{Aead, NewAead, Payload},
  XChaCha20Poly1305, XNonce,
};
use std::convert::{AsMut, AsRef, From};

pub(crate) fn get_encrypted_raw_payload(
  message: &Message,
  header: &Header,
  footer: &Footer,
  key: V2SymmetricKey,
  nonce_key: &NonceKey,
) -> RawPayload {
  let (nonce, pre_auth, blake2_finalized) = get_aead_encrypt_prerequisites(message, header, footer, nonce_key);
  let aead = XChaCha20Poly1305::new_from_slice(*key.as_ref());
  //let temp_key = &[0; 32];
  //let aead = XChaCha20Poly1305::new_from_slice(temp_key);

  assert!(aead.is_ok());

  let crypted = aead
    .unwrap()
    .encrypt(
      nonce.as_ref(),
      Payload {
        msg: message.as_ref().as_bytes(),
        aad: pre_auth.as_ref(),
      },
    )
    .unwrap();
  //  eprintln!("PAYLOAD MSG: {}", &message.as_ref());
  let mut raw_payload = Vec::new();
  raw_payload.extend_from_slice(blake2_finalized.as_ref());
  raw_payload.extend_from_slice(crypted.as_ref());

  let payload = RawPayload::from(raw_payload);
  // eprintln!("RAW PAYLOAD: {}", &payload.clone().encode());
  payload
}

pub(crate) fn get_blake2_finalized(message: &Message, nonce_key: &NonceKey) -> Blake2Finalized {
  let mut hash_context = Blake2HashContext::from(nonce_key);
  hash_context.as_mut().update(message.as_ref().as_bytes());
  Blake2Finalized::from(hash_context)
}

pub(crate) fn get_aead_encrypt_prerequisites(
  message: &Message,
  header: &Header,
  footer: &Footer,
  nonce_key: &NonceKey,
) -> (Nonce, PreAuthenticationEncoding, Blake2Finalized) {
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

impl From<&NonceKey<'_>> for Blake2HashContext {
  fn from(nonce: &NonceKey) -> Self {
    Self(VarBlake2b::new_keyed(*nonce.as_ref(), nonce.as_ref().len()))
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

#[cfg(test)]
mod tests {
  use blake2::digest::Update;
  use chacha20poly1305::{
    aead::{Aead, NewAead, Payload},
    XChaCha20Poly1305,
  };

  use crate::util::*;
  use crate::v2::Footer;
  use crate::v2::Header;
  use crate::{crypto::PreAuthenticationEncoding, v2::RawPayload};
  use crate::{keys::*, v2::Message};

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
    let random_buf = get_random_192_bit_buf();
    let nonce_key = NonceKey::from(&random_buf);

    let finalized = get_blake2_finalized(&Message::default(), &nonce_key);

    let pae = PreAuthenticationEncoding::parse(&[
      Header::default().as_ref().as_bytes(),
      finalized.as_ref(),
      Footer::default().as_ref().as_bytes(),
    ]);
    assert!(pae.as_ref().len() > 0);
  }

  #[test]
  fn test_aead_encrypt() {
    let random_buf = get_random_192_bit_buf();
    let nonce_key = NonceKey::from(&random_buf);

    let (nonce, pae, blake2_finalized) =
      get_aead_encrypt_prerequisites(&Message::from(""), &Header::default(), &Footer::default(), &nonce_key);
    let random_buf = get_random_256_bit_buf();
    let key = V2SymmetricKey::from(&random_buf);
    let aead = XChaCha20Poly1305::new_from_slice(*key.as_ref());
    assert!(aead.is_ok());

    let crypted = aead.unwrap().encrypt(
      nonce.as_ref(),
      Payload {
        msg: "some message".as_bytes(),
        aad: pae.as_ref(),
      },
    );
    assert!(crypted.is_ok());
    let mut raw_payload = Vec::new();
    raw_payload.extend_from_slice(blake2_finalized.as_ref());
    raw_payload.extend_from_slice(crypted.unwrap().as_ref());
    let payload = RawPayload::from(raw_payload);
    //      let token = V2LocalToken::parse_from_parts(Header::default(), payload, Some(footer));
    assert!(payload.encode().len() > 0);
  }

  #[test]
  fn test_aead() {
    let random_buf = get_random_256_bit_buf();
    let key = V2SymmetricKey::from(&random_buf);
    let aead = XChaCha20Poly1305::new_from_slice(*key.as_ref());
    assert!(aead.is_ok());
  }

  #[test]
  fn test_mutable_hash_context_into_finalized() {
    let random_buf = get_random_192_bit_buf();
    let nonce_key = NonceKey::from(&random_buf);

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
