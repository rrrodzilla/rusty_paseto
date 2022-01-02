use super::*;
#[cfg(feature = "aes")]
use aes::{cipher::generic_array::GenericArray, Aes256Ctr};
use base64::{encode_config, URL_SAFE_NO_PAD};
#[cfg(feature = "blake2")]
use blake2::{
  digest::{Update, VariableOutput},
  VarBlake2b,
};
#[cfg(feature = "chacha20")]
use chacha20::cipher::{NewCipher, StreamCipher};
#[cfg(all(feature = "chacha20", any(feature = "v2_local", feature = "v4_local")))]
use chacha20::{Key as ChaChaKey, XNonce as ChaChaNonce};
#[cfg(feature = "chacha20poly1305")]
use chacha20poly1305::{
  aead::{Aead, NewAead, Payload as AeadPayload},
  XChaCha20Poly1305, XNonce,
};

#[cfg(feature = "ed25519-dalek")]
use ed25519_dalek::*;
#[cfg(feature = "hmac")]
use hmac::{Hmac, Mac, NewMac};

#[cfg(any(feature = "v1_local", feature = "v3_local", feature = "v4_local"))]
use ring::constant_time::verify_slices_are_equal as ConstantTimeEquals;
use ring::hkdf;
#[cfg(feature = "v1_public")]
use ring::{
  rand::SystemRandom,
  signature::{RsaKeyPair, UnparsedPublicKey, RSA_PSS_2048_8192_SHA384, RSA_PSS_SHA384},
};
#[cfg(feature = "sha2")]
use sha2::Sha384;
use std::{
  convert::{AsRef, TryFrom},
  fmt,
  fmt::Display,
  marker::PhantomData,
  ops::{Add, Deref},
  str, usize,
};

#[derive(Default, Copy, Clone)]
pub struct Paseto<'a, Version, Purpose>
where
  Version: VersionTrait,
  Purpose: PurposeTrait,
{
  header: Header<Version, Purpose>,
  payload: Payload<'a>,
  footer: Option<Footer<'a>>,
  implicit_assertion: Option<ImplicitAssertion<'a>>,
}

impl<'a, Version: VersionTrait, Purpose: PurposeTrait> Paseto<'a, Version, Purpose> {
  pub fn builder() -> Paseto<'a, Version, Purpose> {
    Self { ..Default::default() }
  }

  pub fn set_payload(&mut self, payload: Payload<'a>) -> &mut Self {
    self.payload = payload;
    self
  }

  pub fn set_footer(&mut self, footer: Footer<'a>) -> &mut Self {
    self.footer = Some(footer);
    self
  }

  /* BEGIN PRIVATE FUNCTIONS */
  fn format_token(&self, encrypted_payload: &str) -> String {
    let footer = self.footer.map(|f| f.encode());
    match footer {
      Some(f) => format!("{}{}.{}", self.header, encrypted_payload, f),
      None => format!("{}{}", self.header, encrypted_payload),
    }
  }

  fn parse_raw_token(
    raw_token: &'a str,
    footer: (impl Into<Option<Footer<'a>>> + Copy),
    v: &Version,
    p: &Purpose,
  ) -> Result<Vec<u8>, PasetoError> {
    //split the raw token into parts
    let potential_parts = raw_token.split('.').collect::<Vec<_>>();
    //inspect the parts
    match potential_parts.len() {
      length if !(3..=4).contains(&length) => {
        return Err(PasetoError::IncorrectSize);
      }
      4 => {
        //verify expected footer
        let footer = footer.into().unwrap_or_default();
        let found_footer = Footer::from(potential_parts[3]);
        if !footer.constant_time_equals(found_footer) {
          return Err(PasetoError::FooterInvalid);
        }
      }
      _ => {}
    }

    //grab the header
    let potential_header = format!("{}.{}.", potential_parts[0], potential_parts[1]);
    //we should be able to verify the header using the passed in Version and Purpose
    let expected_header = format!("{}.{}.", v, p);

    //verify the header
    if potential_header.ne(&expected_header) {
      return Err(PasetoError::WrongHeader);
    };

    let encrypted_payload = Payload::from(potential_parts[2]);
    Ok(encrypted_payload.decode()?)
  }
  /* END PRIVATE FUNCTIONS */
}

impl<'a, Version, Purpose> Paseto<'a, Version, Purpose>
where
  Purpose: PurposeTrait,
  Version: ImplicitAssertionCapable,
{
  /// Note: Only for V3, V4 tokens
  pub fn set_implicit_assertion(&mut self, implicit_assertion: ImplicitAssertion<'a>) -> &mut Self {
    self.implicit_assertion = Some(implicit_assertion);
    self
  }
}

#[cfg(feature = "v1_public")]
impl<'a> Paseto<'a, V1, Public> {
  /// Verifies a signed V1 Public Paseto
  pub fn try_verify(
    signature: &'a str,
    public_key: &PasetoAsymmetricPublicKey<V1, Public>,
    footer: (impl Into<Option<Footer<'a>>> + Copy),
  ) -> Result<String, PasetoError> {
    let decoded_payload = Self::parse_raw_token(signature, footer, &V1::default(), &Public::default())?;

    let ciphertext =
      CipherText::<V1, Public>::try_verify(&decoded_payload, public_key, &footer.into().unwrap_or_default())?
        .ciphertext;

    Ok(String::from_utf8(ciphertext)?)
  }

  /// Attempts to sign a V1 Public Paseto
  /// Fails with a PasetoError if the token is malformed or the private key isn't in a valid pkcs#8
  /// format
  pub fn try_sign(&mut self, key: &PasetoAsymmetricPrivateKey<V1, Public>) -> Result<String, PasetoError> {
    let footer = self.footer.unwrap_or_default();

    let key_pair = RsaKeyPair::from_pkcs8(key.as_ref())?;

    let pae = PreAuthenticationEncoding::parse(&[&self.header, &self.payload, &footer]);
    let random = SystemRandom::new();

    let mut signature = [0; 256];

    key_pair
      .sign(&RSA_PSS_SHA384, &random, &pae, &mut signature)
      .map_err(|_| PasetoError::InvalidSignature)?;

    let raw_payload = RawPayload::<V1, Public>::from(&self.payload, &signature);

    Ok(self.format_token(&raw_payload))
  }
}

#[cfg(feature = "v2_public")]
impl<'a> Paseto<'a, V2, Public> {
  /// Attempts to verify a signed V2 Public Paseto
  /// Fails with a PasetoError if the token is malformed or the token cannot be verified with the
  /// passed public key
  pub fn try_verify(
    signature: &'a str,
    public_key: &PasetoAsymmetricPublicKey<V2, Public>,
    footer: (impl Into<Option<Footer<'a>>> + Copy),
  ) -> Result<String, PasetoError> {
    let decoded_payload = Self::parse_raw_token(signature, footer, &V2::default(), &Public::default())?;

    let public_key = PublicKey::from_bytes(public_key.as_ref()).map_err(|_| PasetoError::InvalidSignature)?;
    let msg = decoded_payload[..(decoded_payload.len() - ed25519_dalek::SIGNATURE_LENGTH)].as_ref();
    let sig = decoded_payload[msg.len()..msg.len() + ed25519_dalek::SIGNATURE_LENGTH].as_ref();

    let signature = Signature::try_from(sig).map_err(|_| PasetoError::InvalidSignature)?;
    let pae = PreAuthenticationEncoding::parse(&[
      &Header::<V2, Public>::default(),
      msg,
      &footer.into().unwrap_or_default(),
    ]);

    public_key
      .verify(&pae, &signature)
      .map_err(|_| PasetoError::InvalidSignature)?;

    Ok(String::from_utf8(Vec::from(msg))?)
  }

  /// Attempts to sign a V2 Public Paseto
  /// Fails with a PasetoError if the token is malformed or the private key can't be parsed
  pub fn try_sign(&mut self, key: &PasetoAsymmetricPrivateKey<V2, Public>) -> Result<String, PasetoError> {
    let footer = self.footer.unwrap_or_default();

    let keypair = Keypair::from_bytes(key.as_ref())?;

    let pae = PreAuthenticationEncoding::parse(&[&self.header, &self.payload, &footer]);

    let signature = keypair.sign(&pae);

    let raw_payload = RawPayload::<V2, Public>::from(&self.payload, &signature);

    Ok(self.format_token(&raw_payload))
  }
}

#[cfg(feature = "v1_local")]
impl<'a> Paseto<'a, V1, Local> {
  /// Attempt to parse an untrusted token string to validate and decrypt into a plaintext payload
  /// Fails with a PasetoError if the token is malformed or can't be decrypted
  pub fn try_decrypt(
    token: &'a str,
    key: &PasetoSymmetricKey<V1, Local>,
    footer: (impl Into<Option<Footer<'a>>> + Copy),
  ) -> Result<String, PasetoError> {
    let decoded_payload = Self::parse_raw_token(token, footer, &V1::default(), &Local::default())?;
    let nonce = Key::from(&decoded_payload[..32]);
    let nonce = PasetoNonce::<V1, Local>::from(&nonce);

    let aks: &[u8] = &AuthenticationKeySeparator::default();
    let authentication_key = AuthenticationKey::<V1, Local>::try_from(&Key::from(aks), key, &nonce)?;
    let eks: &[u8] = &EncryptionKeySeparator::default();
    let encryption_key = EncryptionKey::<V1, Local>::try_from(&Key::from(eks), key, &nonce)?;

    let ciphertext = &decoded_payload[32..(decoded_payload.len() - 48)];

    //pack preauth
    let pae = PreAuthenticationEncoding::parse(&[
      &Header::<V1, Local>::default(),
      nonce.as_ref(),
      ciphertext,
      &footer.into().unwrap_or_default(),
    ]);

    //generate tags
    let tag = &decoded_payload[(nonce.len() + ciphertext.len())..];
    let tag2 = &Tag::<V1, Local>::from(&authentication_key, &pae);
    //compare tags
    ConstantTimeEquals(tag, tag2)?;

    //decrypt payload
    let ciphertext = CipherText::<V1, Local>::from(ciphertext, &encryption_key);

    let decoded_str = str::from_utf8(&ciphertext)?;

    //return decrypted payload
    Ok(decoded_str.to_owned())
  }

  /// Attempt to encrypt a V1, Local Paseto token
  /// Fails with a PasetoError if the token is malformed or can't be encrypted
  pub fn try_encrypt(
    &mut self,
    key: &PasetoSymmetricKey<V1, Local>,
    nonce: &PasetoNonce<V1, Local>,
  ) -> Result<String, PasetoError> {
    //setup
    let footer = self.footer.unwrap_or_default();

    //calculate nonce
    type HmacSha384 = Hmac<Sha384>;
    let mut mac = HmacSha384::new_from_slice(nonce.as_ref()).expect("HMAC can take key of any size");
    mac.update(&self.payload);
    let out = mac.finalize();
    let nonce = Key::from(&out.into_bytes()[..32]);
    let nonce = PasetoNonce::<V1, Local>::from(&nonce);

    //split key
    let aks: &[u8] = &AuthenticationKeySeparator::default();
    let authentication_key = AuthenticationKey::<V1, Local>::try_from(&Key::from(aks), key, &nonce)?;
    let eks: &[u8] = &EncryptionKeySeparator::default();
    let encryption_key = EncryptionKey::<V1, Local>::try_from(&Key::from(eks), key, &nonce)?;

    //encrypt payload
    let ciphertext = CipherText::<V1, Local>::from(&self.payload, &encryption_key);

    //pack preauth
    let pae = PreAuthenticationEncoding::parse(&[&self.header, nonce.as_ref(), &ciphertext, &footer]);

    //      //generate tag
    let tag = Tag::<V1, Local>::from(&authentication_key, &pae);

    //      //generate appended and base64 encoded payload
    let raw_payload = RawPayload::<V1, Local>::from(&nonce, &ciphertext, &tag)?;

    //format as paseto with header and optional footer
    Ok(self.format_token(&raw_payload))
  }
}

#[cfg(feature = "v2_local")]
impl<'a> Paseto<'a, V2, Local> {
  pub fn try_decrypt(
    token: &'a str,
    key: &PasetoSymmetricKey<V2, Local>,
    footer: (impl Into<Option<Footer<'a>>> + Copy),
  ) -> Result<String, PasetoError> {
    //get footer

    let decoded_payload = Self::parse_raw_token(token, footer, &V2::default(), &Local::default())?;
    let (nonce, ciphertext) = decoded_payload.split_at(24);

    //pack preauth
    let pae = &PreAuthenticationEncoding::parse(&[
      &Header::<V2, Local>::default(),
      nonce,
      &footer.into().unwrap_or_default(),
    ]);

    //create the nonce
    let nonce = XNonce::from_slice(nonce);

    //encrypt payload
    let ciphertext = CipherText::<V2, Local>::try_decrypt_from(key, nonce, ciphertext, pae)?;

    //generate appended and base64 encoded payload
    let decoded_str = str::from_utf8(&ciphertext)?;

    //return decrypted payload
    Ok(decoded_str.to_owned())
  }

  pub fn try_encrypt(
    &self,
    key: &PasetoSymmetricKey<V2, Local>,
    nonce: &PasetoNonce<V2, Local>,
  ) -> Result<String, PasetoError> {
    //setup
    let footer = self.footer.unwrap_or_default();

    //create the blake2 context to generate the nonce
    let mut blake2 = VarBlake2b::new_keyed(nonce.as_ref(), 24);
    blake2.update(&*self.payload);
    let context = blake2.finalize_boxed();

    //create the nonce
    let nonce = XNonce::from_slice(&context);

    //pack preauth
    let pae = PreAuthenticationEncoding::parse(&[&self.header, nonce, &footer]);

    //encrypt payload
    let ciphertext = CipherText::<V2, Local>::try_from(key, nonce, &self.payload, &pae)?;

    //generate appended and base64 encoded payload
    let raw_payload = RawPayload::<V2, Local>::from(&context, &ciphertext);

    //format as paseto with header and optional footer
    Ok(self.format_token(&raw_payload))
  }
}

#[cfg(feature = "v3_local")]
impl<'a> Paseto<'a, V3, Local> {
  /// Parse an untrusted token string to validate and decrypt into a plaintext payload
  pub fn try_decrypt(
    token: &'a str,
    key: &PasetoSymmetricKey<V3, Local>,
    footer: (impl Into<Option<Footer<'a>>> + Copy),
    implicit_assertion: (impl Into<Option<ImplicitAssertion<'a>>> + Copy),
  ) -> Result<String, PasetoError> {
    //get footer

    let decoded_payload = Self::parse_raw_token(token, footer, &V3::default(), &Local::default())?;
    let nonce = Key::from(&decoded_payload[..32]);
    let nonce = PasetoNonce::<V3, Local>::from(&nonce);

    let authentication_key =
      AuthenticationKey::<V3, Local>::try_from(&(AuthenticationKeySeparator::default() + &nonce), key)?;
    let encryption_key = EncryptionKey::<V3, Local>::try_from(&(EncryptionKeySeparator::default() + &nonce), key)?;

    let ciphertext = &decoded_payload[32..(decoded_payload.len() - 48)];

    //pack preauth
    let pae = PreAuthenticationEncoding::parse(&[
      &Header::<V3, Local>::default(),
      nonce.as_ref(),
      ciphertext,
      &footer.into().unwrap_or_default(),
      &implicit_assertion.into().unwrap_or_default(),
    ]);

    //generate tags
    let tag = &decoded_payload[(nonce.len() + ciphertext.len())..];
    let tag2 = &Tag::<V3, Local>::from(&authentication_key, &pae);
    //compare tags
    ConstantTimeEquals(tag, tag2)?;

    //decrypt payload
    let ciphertext = CipherText::<V3, Local>::from(ciphertext, &encryption_key);

    let decoded_str = str::from_utf8(&ciphertext)?;

    //return decrypted payload
    Ok(decoded_str.to_owned())
  }

  pub fn try_encrypt(
    &mut self,
    key: &PasetoSymmetricKey<V3, Local>,
    nonce: &PasetoNonce<V3, Local>,
  ) -> Result<String, PasetoError> {
    //setup
    let footer = self.footer.unwrap_or_default();
    let implicit_assertion = self.implicit_assertion.unwrap_or_default();

    //split key
    let authentication_key =
      AuthenticationKey::<V3, Local>::try_from(&(AuthenticationKeySeparator::default() + nonce), key)?;
    let encryption_key = EncryptionKey::<V3, Local>::try_from(&(EncryptionKeySeparator::default() + nonce), key)?;

    //encrypt payload
    let ciphertext = CipherText::<V3, Local>::from(&self.payload, &encryption_key);

    //pack preauth
    let pae =
      PreAuthenticationEncoding::parse(&[&self.header, nonce.as_ref(), &ciphertext, &footer, &implicit_assertion]);

    //      //generate tag
    let tag = Tag::<V3, Local>::from(&authentication_key, &pae);

    //      //generate appended and base64 encoded payload
    let raw_payload = RawPayload::<V3, Local>::from(nonce, &ciphertext, &tag)?;

    //format as paseto with header and optional footer
    Ok(self.format_token(&raw_payload))
  }
}

#[cfg(feature = "v4_local")]
impl<'a> Paseto<'a, V4, Local> {
  pub fn try_decrypt(
    token: &'a str,
    key: &PasetoSymmetricKey<V4, Local>,
    footer: (impl Into<Option<Footer<'a>>> + Copy),
    implicit_assertion: (impl Into<Option<ImplicitAssertion<'a>>> + Copy),
  ) -> Result<String, PasetoError> {
    //get footer

    let decoded_payload = Self::parse_raw_token(token, footer, &V4::default(), &Local::default())?;
    let nonce = Key::from(&decoded_payload[..32]);
    let nonce = PasetoNonce::<V4, Local>::from(&nonce);

    let authentication_key =
      AuthenticationKey::<V4, Local>::from(&(AuthenticationKeySeparator::default() + &nonce), key);
    let encryption_key = EncryptionKey::<V4, Local>::from(&(EncryptionKeySeparator::default() + &nonce), key);

    let ciphertext = &decoded_payload[32..(decoded_payload.len() - 32)];

    //pack preauth
    let pae = PreAuthenticationEncoding::parse(&[
      &Header::<V4, Local>::default(),
      nonce.as_ref(),
      ciphertext,
      &footer.into().unwrap_or_default(),
      &implicit_assertion.into().unwrap_or_default(),
    ]);

    //generate tags
    let tag = &decoded_payload[(nonce.len() + ciphertext.len())..];
    let tag2 = &Tag::<V4, Local>::from(&authentication_key, &pae);
    //compare tags
    ConstantTimeEquals(tag, tag2)?;

    //decrypt payload
    let ciphertext = CipherText::<V4, Local>::from(ciphertext, &encryption_key);

    let decoded_str = str::from_utf8(&ciphertext)?;

    //return decrypted payload
    Ok(decoded_str.to_owned())
  }

  pub fn try_encrypt(
    &mut self,
    key: &PasetoSymmetricKey<V4, Local>,
    nonce: &PasetoNonce<V4, Local>,
  ) -> Result<String, PasetoError> {
    //setup
    let footer = self.footer.unwrap_or_default();
    let implicit_assertion = self.implicit_assertion.unwrap_or_default();

    //split key
    let authentication_key =
      AuthenticationKey::<V4, Local>::from(&(AuthenticationKeySeparator::default() + nonce), key);
    let encryption_key = EncryptionKey::<V4, Local>::from(&(EncryptionKeySeparator::default() + nonce), key);

    //encrypt payload
    let ciphertext = CipherText::<V4, Local>::from(&self.payload, &encryption_key);

    //pack preauth
    let pae =
      PreAuthenticationEncoding::parse(&[&self.header, nonce.as_ref(), &ciphertext, &footer, &implicit_assertion]);

    //generate tag
    let tag = Tag::<V4, Local>::from(&authentication_key, &pae);

    //generate appended and base64 encoded payload
    let raw_payload = RawPayload::<V4, Local>::try_from(nonce, &ciphertext, &tag)?;

    //format as paseto with header and optional footer
    Ok(self.format_token(&raw_payload))
  }
}

#[cfg(feature = "v4_public")]
impl<'a> Paseto<'a, V4, Public> {
  pub fn try_verify(
    signature: &'a str,
    public_key: &PasetoAsymmetricPublicKey<V4, Public>,
    footer: (impl Into<Option<Footer<'a>>> + Copy),
    implicit_assertion: (impl Into<Option<ImplicitAssertion<'a>>> + Copy),
  ) -> Result<String, PasetoError> {
    let decoded_payload = Self::parse_raw_token(signature, footer, &V4::default(), &Public::default())?;

    let public_key = PublicKey::from_bytes(public_key.as_ref())?;
    let msg = decoded_payload[..(decoded_payload.len() - ed25519_dalek::SIGNATURE_LENGTH)].as_ref();
    let sig = decoded_payload[msg.len()..msg.len() + ed25519_dalek::SIGNATURE_LENGTH].as_ref();

    let signature = Signature::try_from(sig)?;
    let pae = PreAuthenticationEncoding::parse(&[
      &Header::<V4, Public>::default(),
      msg,
      &footer.into().unwrap_or_default(),
      &implicit_assertion.into().unwrap_or_default(),
    ]);

    public_key.verify(&pae, &signature)?;

    Ok(String::from_utf8(Vec::from(msg))?)
  }

  pub fn try_sign(&mut self, key: &PasetoAsymmetricPrivateKey<V4, Public>) -> Result<String, PasetoError> {
    let footer = self.footer.unwrap_or_default();
    let assertion = self.implicit_assertion.unwrap_or_default();
    let keypair = Keypair::from_bytes(key.as_ref())?;

    let pae = PreAuthenticationEncoding::parse(&[&self.header, &self.payload, &footer, &assertion]);

    let signature = keypair.sign(&pae);

    let raw_payload = RawPayload::<V4, Public>::from(&self.payload, &signature);

    Ok(self.format_token(&raw_payload))
  }
}

struct CipherText<Version, Purpose> {
  ciphertext: Vec<u8>,
  version: PhantomData<Version>,
  purpose: PhantomData<Purpose>,
}

#[cfg(feature = "v1_public")]
impl CipherText<V1, Public> {
  fn try_verify(decoded_payload: &[u8], public_key: &impl AsRef<[u8]>, footer: &Footer) -> Result<Self, PasetoError> {
    let signature = decoded_payload[(decoded_payload.len() - 256)..].as_ref();
    let public_key = UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA384, public_key);
    let msg = decoded_payload[..(decoded_payload.len() - 256)].as_ref();

    let pae = PreAuthenticationEncoding::parse(&[&Header::<V1, Public>::default(), msg, footer]);

    public_key.verify(&pae, signature)?;

    let ciphertext = Vec::from(msg);

    Ok(CipherText {
      ciphertext,
      version: PhantomData,
      purpose: PhantomData,
    })
  }
}

#[cfg(feature = "v1_local")]
impl CipherText<V1, Local> {
  fn from(payload: &[u8], encryption_key: &EncryptionKey<V1, Local>) -> Self {
    let key = GenericArray::from_slice(encryption_key.as_ref());
    let nonce = GenericArray::from_slice(encryption_key.counter_nonce());
    let mut cipher = Aes256Ctr::new(key, nonce);
    let mut ciphertext = vec![0u8; payload.as_ref().len()];

    ciphertext.copy_from_slice(payload);

    cipher.apply_keystream(&mut ciphertext);

    CipherText {
      ciphertext,
      version: PhantomData,
      purpose: PhantomData,
    }
  }
}

#[cfg(feature = "v2_local")]
impl CipherText<V2, Local> {
  fn try_decrypt_from(
    key: &PasetoSymmetricKey<V2, Local>,
    nonce: &XNonce,
    payload: &[u8],
    pre_auth: &PreAuthenticationEncoding,
  ) -> Result<Self, PasetoError> {
    //let ciphertext = CipherText::try_from(&key, &nonce, &payload, &pae)?;

    let aead = XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| PasetoError::Cryption)?;
    //encrypt cipher_text
    let ciphertext = aead
      .decrypt(
        nonce,
        AeadPayload {
          msg: payload,
          aad: pre_auth.as_ref(),
        },
      )
      .map_err(|_| PasetoError::ChaChaCipherError)?;

    Ok(CipherText {
      ciphertext,
      version: PhantomData,
      purpose: PhantomData,
    })
  }

  fn try_from(
    key: &PasetoSymmetricKey<V2, Local>,
    nonce: &XNonce,
    payload: &[u8],
    pre_auth: &PreAuthenticationEncoding,
  ) -> Result<Self, PasetoError> {
    let aead = XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| PasetoError::Cryption)?;
    //encrypt cipher_text
    let ciphertext = aead
      .encrypt(
        nonce,
        AeadPayload {
          msg: payload,
          aad: pre_auth.as_ref(),
        },
      )
      .map_err(|_| PasetoError::ChaChaCipherError)?;

    Ok(CipherText {
      ciphertext,
      version: PhantomData,
      purpose: PhantomData,
    })
  }
}

#[cfg(feature = "v3_local")]
impl CipherText<V3, Local> {
  fn from(payload: &[u8], encryption_key: &EncryptionKey<V3, Local>) -> Self {
    let key = GenericArray::from_slice(encryption_key.as_ref());
    let nonce = GenericArray::from_slice(encryption_key.counter_nonce());
    let mut cipher = Aes256Ctr::new(key, nonce);
    let mut ciphertext = vec![0u8; payload.len()];

    ciphertext.copy_from_slice(payload);

    cipher.apply_keystream(&mut ciphertext);

    CipherText {
      ciphertext,
      version: PhantomData,
      purpose: PhantomData,
    }
  }
}

#[cfg(feature = "v4_local")]
impl CipherText<V4, Local> {
  fn from(payload: &[u8], encryption_key: &EncryptionKey<V4, Local>) -> Self {
    let mut ciphertext = vec![0u8; payload.len()];
    ciphertext.copy_from_slice(payload);

    let n2 = encryption_key.counter_nonce();
    let mut cipher = chacha20::XChaCha20::new(encryption_key.as_ref(), n2);
    cipher.apply_keystream(&mut ciphertext);

    CipherText {
      ciphertext,
      version: PhantomData,
      purpose: PhantomData,
    }
  }
}

impl<Version, Purpose> AsRef<Vec<u8>> for CipherText<Version, Purpose> {
  fn as_ref(&self) -> &Vec<u8> {
    &self.ciphertext
  }
}

impl<Version, Purpose> std::ops::Deref for CipherText<Version, Purpose> {
  type Target = Vec<u8>;
  fn deref(&self) -> &Self::Target {
    &self.ciphertext
  }
}

#[cfg(feature = "chacha20poly1305")]
struct EncryptionNonce(XNonce);

#[cfg(feature = "chacha20poly1305")]
impl AsRef<XNonce> for EncryptionNonce {
  fn as_ref(&self) -> &XNonce {
    &self.0
  }
}

struct Tag<Version, Purpose> {
  version: PhantomData<Version>,
  purpose: PhantomData<Purpose>,
  tag: Vec<u8>,
}

#[cfg(feature = "v4_local")]
impl Tag<V4, Local> {
  fn from(authentication_key: impl AsRef<[u8]>, pae: &PreAuthenticationEncoding) -> Self {
    let mut tag_context = VarBlake2b::new_keyed(authentication_key.as_ref(), 32);
    tag_context.update(pae.as_ref());
    Self {
      tag: tag_context.finalize_boxed().as_ref().to_vec(),
      version: PhantomData,
      purpose: PhantomData,
    }
  }
}

#[cfg(any(feature = "v1_local", feature = "v3_local"))]
impl<Version> Tag<Version, Local>
where
  Version: V1orV3,
{
  fn from(authentication_key: impl AsRef<[u8]>, pae: &PreAuthenticationEncoding) -> Self {
    type HmacSha384 = Hmac<Sha384>;

    let mut mac = HmacSha384::new_from_slice(authentication_key.as_ref()).expect("HMAC can take key of any size");
    mac.update(pae.as_ref());

    let out = mac.finalize();

    Self {
      tag: out.into_bytes().to_vec(),
      version: PhantomData,
      purpose: PhantomData,
    }
  }
}
impl<Version, Purpose> AsRef<[u8]> for Tag<Version, Purpose> {
  fn as_ref(&self) -> &[u8] {
    &self.tag
  }
}

impl<Version, Purpose> Deref for Tag<Version, Purpose> {
  type Target = [u8];
  fn deref(&self) -> &Self::Target {
    &self.tag
  }
}

pub struct RawPayload<Version, Purpose> {
  version: PhantomData<Version>,
  purpose: PhantomData<Purpose>,
}

#[cfg(feature = "public")]
impl<Version> RawPayload<Version, Public> {
  fn from(payload: &[u8], signature: &impl AsRef<[u8]>) -> String {
    let mut raw_token = Vec::from(payload);
    raw_token.extend_from_slice(signature.as_ref());

    encode_config(&raw_token, URL_SAFE_NO_PAD)
  }
}

#[cfg(feature = "v2_local")]
impl RawPayload<V2, Local> {
  fn from(blake2_hash: &[u8], ciphertext: &[u8]) -> String {
    let mut raw_token = Vec::new();
    raw_token.extend_from_slice(blake2_hash);
    raw_token.extend_from_slice(ciphertext);

    encode_config(&raw_token, URL_SAFE_NO_PAD)
  }
}

#[cfg(any(feature = "v1_local", feature = "v3_local"))]
impl<Version> RawPayload<Version, Local>
where
  Version: V1orV3,
{
  fn from(
    nonce: &PasetoNonce<Version, Local>,
    ciphertext: &impl AsRef<Vec<u8>>,
    tag: &impl AsRef<[u8]>,
  ) -> Result<String, PasetoError> {
    let tag_len = tag.as_ref().len();
    let concat_len: usize = match (nonce.len() + tag_len).checked_add(ciphertext.as_ref().len()) {
      Some(len) => len,
      None => return Err(PasetoError::Signature),
    };

    let mut raw_token = vec![0u8; concat_len];
    raw_token[..nonce.as_ref().len()].copy_from_slice(nonce.as_ref());
    raw_token[nonce.as_ref().len()..nonce.as_ref().len() + ciphertext.as_ref().len()]
      .copy_from_slice(ciphertext.as_ref());
    raw_token[concat_len - tag_len..].copy_from_slice(tag.as_ref());

    Ok(encode_config(&raw_token, URL_SAFE_NO_PAD))
  }
}

#[cfg(feature = "v4_local")]
impl RawPayload<V4, Local> {
  fn try_from(
    nonce: &PasetoNonce<V4, Local>,
    ciphertext: &impl AsRef<Vec<u8>>,
    tag: &impl AsRef<[u8]>,
  ) -> Result<String, PasetoError> {
    let tag_len = tag.as_ref().len();
    let concat_len: usize = match (nonce.len() + tag_len).checked_add(ciphertext.as_ref().len()) {
      Some(len) => len,
      None => return Err(PasetoError::Cryption),
    };

    let mut raw_token = vec![0u8; concat_len];
    raw_token[..nonce.as_ref().len()].copy_from_slice(nonce.as_ref());
    raw_token[nonce.as_ref().len()..nonce.as_ref().len() + ciphertext.as_ref().len()]
      .copy_from_slice(ciphertext.as_ref());
    raw_token[concat_len - tag_len..].copy_from_slice(tag.as_ref());

    Ok(encode_config(&raw_token, URL_SAFE_NO_PAD))
  }
}

#[derive(Default)]
struct EncryptionKey<Version, Purpose> {
  version: PhantomData<Version>,
  purpose: PhantomData<Purpose>,
  key: Vec<u8>,
  #[cfg(any(feature = "v1_local", feature = "v3_local", feature = "v4_local"))]
  nonce: Vec<u8>,
}

#[cfg(feature = "v1_local")]
impl EncryptionKey<V1, Local> {
  fn try_from(
    message: &Key<21>,
    key: &PasetoSymmetricKey<V1, Local>,
    nonce: &PasetoNonce<V1, Local>,
  ) -> Result<Self, PasetoError> {
    let info = message.as_ref();
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA384, &nonce[..16]);
    let HkdfKey(out) = salt.extract(key.as_ref()).expand(&[info], HkdfKey(32))?.try_into()?;

    Ok(Self {
      version: PhantomData,
      purpose: PhantomData,
      key: out.to_vec(),
      nonce: nonce[16..].to_vec(),
    })
  }

  fn counter_nonce(&self) -> &Vec<u8> {
    &self.nonce
  }
}

#[cfg(feature = "v3_local")]
impl EncryptionKey<V3, Local> {
  fn try_from(message: &Key<53>, key: &PasetoSymmetricKey<V3, Local>) -> Result<Self, PasetoError> {
    let info = message.as_ref();
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA384, &[]);

    let HkdfKey(out) = salt.extract(key.as_ref()).expand(&[info], HkdfKey(48))?.try_into()?;

    Ok(Self {
      version: PhantomData,
      purpose: PhantomData,
      key: out[..32].to_vec(),
      nonce: out[32..].to_vec(),
    })
  }

  fn counter_nonce(&self) -> &Vec<u8> {
    &self.nonce
  }
}

#[cfg(feature = "v4_local")]
impl EncryptionKey<V4, Local> {
  fn from(message: &Key<53>, key: &PasetoSymmetricKey<V4, Local>) -> Self {
    //let mut context = Blake2b::new_keyed(key.as_ref(), 56);
    let mut context = VarBlake2b::new_keyed(key.as_ref(), 56);
    context.update(message.as_ref());
    let context = context.finalize_boxed();
    let key = context.as_ref()[..32].to_vec();
    let nonce = context.as_ref()[32..].to_vec();
    assert_eq!(key.len(), 32);
    assert_eq!(nonce.len(), 24);
    Self {
      key,
      nonce,
      version: PhantomData,
      purpose: PhantomData,
    }
  }
  fn counter_nonce(&self) -> &ChaChaNonce {
    ChaChaNonce::from_slice(&self.nonce)
  }
}

impl<Version> AsRef<Vec<u8>> for EncryptionKey<Version, Local>
where
  Version: V1orV3,
{
  fn as_ref(&self) -> &Vec<u8> {
    &self.key
  }
}

impl<Version> Deref for EncryptionKey<Version, Local>
where
  Version: V1orV3,
{
  type Target = [u8];

  fn deref(&self) -> &Self::Target {
    &self.key
  }
}

#[cfg(feature = "v4_local")]
impl AsRef<ChaChaKey> for EncryptionKey<V4, Local> {
  fn as_ref(&self) -> &ChaChaKey {
    ChaChaKey::from_slice(&self.key)
  }
}

#[cfg(feature = "v4_local")]
impl Deref for EncryptionKey<V4, Local> {
  type Target = [u8];

  fn deref(&self) -> &Self::Target {
    ChaChaKey::from_slice(&self.key)
  }
}

#[derive(Debug, PartialEq)]
struct HkdfKey<T: core::fmt::Debug + PartialEq>(T);

impl hkdf::KeyType for HkdfKey<usize> {
  fn len(&self) -> usize {
    self.0
  }
}

impl TryFrom<hkdf::Okm<'_, HkdfKey<usize>>> for HkdfKey<Vec<u8>> {
  type Error = PasetoError;
  fn try_from(okm: hkdf::Okm<HkdfKey<usize>>) -> Result<Self, Self::Error> {
    let mut r = vec![0u8; okm.len().0];
    okm.fill(&mut r)?;
    Ok(Self(r))
  }
}

struct AuthenticationKey<Version, Purpose> {
  version: PhantomData<Version>,
  purpose: PhantomData<Purpose>,
  key: Vec<u8>,
}

#[cfg(feature = "v1_local")]
impl AuthenticationKey<V1, Local> {
  fn try_from(
    message: &[u8; 24],
    key: &PasetoSymmetricKey<V1, Local>,
    nonce: &PasetoNonce<V1, Local>,
  ) -> Result<Self, PasetoError> {
    let info = message.as_ref();
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA384, &nonce[..16]);
    let HkdfKey(out) = salt.extract(key.as_ref()).expand(&[info], HkdfKey(32))?.try_into()?;

    Ok(Self {
      version: PhantomData,
      purpose: PhantomData,
      key: out,
    })
  }
}

#[cfg(feature = "v3_local")]
impl AuthenticationKey<V3, Local> {
  fn try_from(message: &Key<56>, key: &PasetoSymmetricKey<V3, Local>) -> Result<Self, PasetoError> {
    let info = message.as_ref();
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA384, &[]);
    let HkdfKey(out) = salt.extract(key.as_ref()).expand(&[info], HkdfKey(48))?.try_into()?;

    Ok(Self {
      version: PhantomData,
      purpose: PhantomData,
      key: out,
    })
  }
}

#[cfg(feature = "v4_local")]
impl AuthenticationKey<V4, Local> {
  fn from(message: &Key<56>, key: &PasetoSymmetricKey<V4, Local>) -> Self {
    let mut context = VarBlake2b::new_keyed(key.as_ref(), 32);
    context.update(message.as_ref());
    Self {
      version: PhantomData,
      purpose: PhantomData,
      key: context.finalize_boxed().as_ref().to_vec(),
    }
  }
}

impl<Version, Purpose> AsRef<[u8]> for AuthenticationKey<Version, Purpose> {
  fn as_ref(&self) -> &[u8] {
    &self.key
  }
}

impl<Version, Purpose> Deref for AuthenticationKey<Version, Purpose> {
  type Target = [u8];

  fn deref(&self) -> &Self::Target {
    &self.key
  }
}

#[derive(Debug)]
pub struct AuthenticationKeySeparator(&'static str);

impl Display for AuthenticationKeySeparator {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", &self.0)
  }
}

impl Default for AuthenticationKeySeparator {
  fn default() -> Self {
    Self("paseto-auth-key-for-aead")
  }
}

impl Deref for AuthenticationKeySeparator {
  type Target = [u8];

  fn deref(&self) -> &Self::Target {
    self.0.as_bytes()
  }
}

impl AsRef<str> for AuthenticationKeySeparator {
  fn as_ref(&self) -> &str {
    self.0
  }
}

impl<'a, Version> Add<&PasetoNonce<'a, Version, Local>> for AuthenticationKeySeparator {
  type Output = Key<56>;

  fn add(self, rhs: &PasetoNonce<Version, Local>) -> Self::Output {
    let mut output = [0u8; 56];
    output[..24].copy_from_slice(self.0.as_bytes());
    output[24..].copy_from_slice(rhs.as_ref());
    Key::<56>::from(output)
  }
}

#[derive(Debug)]
pub struct EncryptionKeySeparator(&'static str);

impl Display for EncryptionKeySeparator {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", &self.0)
  }
}

impl Default for EncryptionKeySeparator {
  fn default() -> Self {
    Self("paseto-encryption-key")
  }
}

impl Deref for EncryptionKeySeparator {
  type Target = [u8];

  fn deref(&self) -> &Self::Target {
    self.0.as_bytes()
  }
}

impl AsRef<str> for EncryptionKeySeparator {
  fn as_ref(&self) -> &str {
    self.0
  }
}

impl<'a, Version> Add<&PasetoNonce<'a, Version, Local>> for EncryptionKeySeparator {
  type Output = Key<53>;

  fn add(self, rhs: &PasetoNonce<Version, Local>) -> Self::Output {
    let mut output = [0u8; 53];
    output[..21].copy_from_slice(self.0.as_bytes());
    output[21..].copy_from_slice(rhs.as_ref());
    Key::<53>::from(output)
  }
}

pub struct PreAuthenticationEncoding(Vec<u8>);

/// Performs Pre-Authentication Encoding (or PAE) as described in the
/// Paseto Specification v2.
///
impl PreAuthenticationEncoding {
  /// * `pieces` - The Pieces to concatenate, and encode together.
  /// Refactored from original code found at
  /// <https://github.com/instructure/paseto/blob/trunk/src/pae.rs>
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
  /// Copied and gently refactored from <https://github.com/instructure/paseto/blob/trunk/src/pae.rs>
  pub(crate) fn le64(mut to_encode: u64) -> Vec<u8> {
    let mut the_vec = Vec::with_capacity(8);

    for _idx in 0..8 {
      the_vec.push((to_encode & 255) as u8);
      to_encode >>= 8;
    }

    the_vec
  }
}

impl Deref for PreAuthenticationEncoding {
  type Target = [u8];

  fn deref(&self) -> &Self::Target {
    self.0.deref()
  }
}

impl AsRef<Vec<u8>> for PreAuthenticationEncoding {
  fn as_ref(&self) -> &Vec<u8> {
    &self.0
  }
}
