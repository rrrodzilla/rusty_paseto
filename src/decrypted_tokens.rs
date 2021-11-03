use crate::common::Payload;
use crate::common::{Footer, Header, Local, Public, V2};
use crate::crypto::{
  try_decrypt_payload, try_verify_signed_payload, validate_footer_against_hex_encoded_footer_in_constant_time,
};
use crate::errors::PasetoTokenParseError;
use crate::keys::Key;
use crate::untrusted_tokens::UntrustedEncryptedToken;
//use ed25519_dalek::{Keypair, SignatureError};
use std::cmp::PartialEq;
use std::convert::AsRef;
use std::default::Default;
use std::fmt;
use std::marker::PhantomData;

#[derive(Debug, PartialEq)]
pub struct GenericTokenDecrypted<Version, Purpose> {
  version: PhantomData<Version>,
  purpose: PhantomData<Purpose>,
  token: String,
}

impl<R, Version, Purpose> PartialEq<R> for GenericTokenDecrypted<Version, Purpose>
where
  R: AsRef<str>,
{
  fn eq(&self, other: &R) -> bool {
    self.as_ref() == other.as_ref()
  }
}
impl<Version, Purpose> fmt::Display for GenericTokenDecrypted<Version, Purpose> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", self.token)
  }
}

impl<Version, Purpose> AsRef<String> for GenericTokenDecrypted<Version, Purpose> {
  fn as_ref(&self) -> &String {
    &self.token
  }
}
impl<Version, Purpose> GenericTokenDecrypted<Version, Purpose>
where
  Version: fmt::Display + Default,
  Purpose: fmt::Display + Default,
{
  pub fn get_raw_payload<T>(
    potential_token: &T,
    potential_footer: Option<Footer>,
  ) -> Result<String, PasetoTokenParseError>
  where
    T: AsRef<str> + ?Sized,
  {
    //an initial parse of the incoming string to see what we find and validate its structure
    //can raise exceptions
    let parsed_values = potential_token.as_ref().parse::<UntrustedEncryptedToken>()?;
    //if all went well, we can extract the values
    let (parsed_payload, potential_header, found_footer) = parsed_values.as_ref(); //  verify the header

    let header = Header::<Version, Purpose>::default();
    if potential_header.ne(header.as_ref()) {
      return Err(PasetoTokenParseError::WrongHeader);
    }

    //verify any provided and/or discovered footers are valid
    //can raise exceptions
    validate_footer_against_hex_encoded_footer_in_constant_time(potential_footer, found_footer)?;

    Ok(parsed_payload.clone())

    //decrypt the payload
    //can raise exceptions
  }
}

impl GenericTokenDecrypted<V2, Local> {
  // Given an arbitrary string, an encryption key and an optional footer,
  // validate and decrypt this token raising errors as needed
  pub fn parse<T>(
    potential_token: &T,
    potential_footer: Option<Footer>,
    key: &Key<V2, Local>,
  ) -> Result<GenericTokenDecrypted<V2, Local>, PasetoTokenParseError>
  where
    T: AsRef<str> + ?Sized,
  {
    let header = Header::<V2, Local>::default();
    let raw = Self::get_raw_payload(potential_token, potential_footer.clone())?;
    let raw_payload = Payload::from(raw.as_ref());
    //decrypt the payload
    let payload = try_decrypt_payload(
      &raw_payload,
      &header.as_ref(),
      &potential_footer.unwrap_or_default(),
      key,
    )?;
    //can raise exceptions
    Ok(Self {
      version: PhantomData,
      purpose: PhantomData,
      token: payload,
    })
  }
}

impl GenericTokenDecrypted<V2, Public> {
  // Given an arbitrary string, an encryption key and an optional footer,
  // validate and decrypt this token raising errors as needed
  pub fn parse<T>(
    potential_token: &T,
    potential_footer: Option<Footer>,
    key: &Key<V2, Public>,
  ) -> Result<GenericTokenDecrypted<V2, Public>, PasetoTokenParseError>
  where
    T: AsRef<str> + ?Sized,
  {
    let header = Header::<V2, Public>::default();
    let raw = Self::get_raw_payload(potential_token, potential_footer.clone())?;
    let raw_payload = Payload::from(raw.as_ref());
    //decrypt the payload
    //can raise exceptions
    let payload = try_verify_signed_payload(
      &raw_payload,
      &header.as_ref(),
      &potential_footer.unwrap_or_default(),
      key,
    )?;
    Ok(Self {
      version: PhantomData,
      purpose: PhantomData,
      token: payload,
    })
  }
}
