use crate::common::Payload;
use crate::common::{Footer, PurposeLocal, PurposePublic, Version2};
use crate::crypto::{
  try_decrypt_payload, try_verify_signed_payload, validate_footer_against_hex_encoded_footer_in_constant_time,
};
use crate::errors::PasetoTokenParseError;
use crate::headers::Header;
use crate::keys::Key;
use crate::untrusted_tokens::UntrustedEncryptedToken;
use ed25519_dalek::{Keypair, SignatureError};
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
impl GenericTokenDecrypted<Version2, PurposeLocal> {
  // Given an arbitrary string, an encryption key and an optional footer,
  // validate and decrypt this token raising errors as needed
  pub fn parse<T>(
    potential_token: &T,
    potential_footer: Option<Footer>,
    key: &Key<Version2, PurposeLocal>,
  ) -> Result<GenericTokenDecrypted<Version2, PurposeLocal>, PasetoTokenParseError>
  where
    T: AsRef<str> + ?Sized,
  {
    //an initial parse of the incoming string to see what we find and validate its structure
    //can raise exceptions
    let parsed_values = potential_token.as_ref().parse::<UntrustedEncryptedToken>()?;
    //if all went well, we can extract the values
    let (parsed_payload, potential_header, found_footer) = parsed_values.as_ref(); //  verify the header

    if potential_header.ne(Header::<Version2, PurposeLocal>::default().as_ref()) {
      return Err(PasetoTokenParseError::WrongHeader);
    }

    //verify any provided and/or discovered footers are valid
    //can raise exceptions
    validate_footer_against_hex_encoded_footer_in_constant_time(potential_footer, found_footer)?;

    let raw_payload = Payload::from(parsed_payload.as_str());

    //decrypt the payload
    //can raise exceptions
    let payload = try_decrypt_payload(
      &raw_payload,
      &Header::<Version2, PurposeLocal>::default(),
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
impl GenericTokenDecrypted<Version2, PurposePublic> {
  // Given an arbitrary string, an encryption key and an optional footer,
  // validate and decrypt this token raising errors as needed
  pub fn parse<T>(
    potential_token: &T,
    potential_footer: Option<Footer>,
    key: &Key<Version2, PurposePublic>,
  ) -> Result<GenericTokenDecrypted<Version2, PurposePublic>, PasetoTokenParseError>
  where
    T: AsRef<str> + ?Sized,
  {
    //an initial parse of the incoming string to see what we find and validate its structure
    //can raise exceptions
    let parsed_values = potential_token.as_ref().parse::<UntrustedEncryptedToken>()?;
    //if all went well, we can extract the values
    let (parsed_payload, potential_header, found_footer) = parsed_values.as_ref(); //  verify the header

    if potential_header.ne(Header::<Version2, PurposePublic>::default().as_ref()) {
      return Err(PasetoTokenParseError::WrongHeader);
    }

    //verify any provided and/or discovered footers are valid
    //can raise exceptions
    validate_footer_against_hex_encoded_footer_in_constant_time(potential_footer, found_footer)?;

    let raw_payload = Payload::from(parsed_payload.as_str());

    //decrypt the payload
    //can raise exceptions
    let payload = try_verify_signed_payload(
      &raw_payload,
      &Header::<Version2, PurposePublic>::default(),
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
