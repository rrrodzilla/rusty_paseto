use crate::{
  common::{Footer, Header, ImplicitAssertion, Payload, Public, V2, V4},
  crypto::{try_verify_signed_payload, validate_footer_against_hex_encoded_footer_in_constant_time},
  errors::PasetoTokenParseError,
  keys::Key,
  untrusted_tokens::UntrustedEncryptedToken,
};
use std::{cmp::PartialEq, convert::AsRef, default::Default, fmt, marker::PhantomData};

#[derive(Debug, PartialEq)]
pub struct BasicTokenVerified<Version, Purpose> {
  version: PhantomData<Version>,
  purpose: PhantomData<Purpose>,
  token: String,
}

impl<R, Version, Purpose> PartialEq<R> for BasicTokenVerified<Version, Purpose>
where
  R: AsRef<str>,
{
  fn eq(&self, other: &R) -> bool {
    self.as_ref() == other.as_ref()
  }
}
impl<Version, Purpose> fmt::Display for BasicTokenVerified<Version, Purpose> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", self.token)
  }
}

impl<Version, Purpose> AsRef<String> for BasicTokenVerified<Version, Purpose> {
  fn as_ref(&self) -> &String {
    &self.token
  }
}

impl<Version, Purpose> BasicTokenVerified<Version, Purpose>
where
  Version: fmt::Display + Default,
  Purpose: fmt::Display + Default,
{
  pub fn get_raw_data<T>(
    potential_token: &T,
    potential_footer: Option<Footer>,
    header: &Header<Version, Purpose>,
  ) -> Result<String, PasetoTokenParseError>
  where
    T: AsRef<str> + ?Sized,
  {
    //an initial parse of the incoming string to see what we find and validate its structure
    //can raise exceptions
    let parsed_values = potential_token.as_ref().parse::<UntrustedEncryptedToken>()?;
    //if all went well, we can extract the values
    let (parsed_payload, potential_header, found_footer) = parsed_values.as_ref(); //  verify the header

    //    let header = Header::<Version, Purpose>::default();
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
impl BasicTokenVerified<V4, Public> {
  // Given an arbitrary string, an encryption key and an optional footer,
  // validate and decrypt this token raising errors as needed
  pub fn parse<T>(
    potential_token: &T,
    potential_footer: Option<Footer>,
    potential_assertion: Option<ImplicitAssertion>,
    key: &Key<V4, Public>,
  ) -> Result<BasicTokenVerified<V4, Public>, PasetoTokenParseError>
  where
    T: AsRef<str> + ?Sized,
  {
    let header = Header::<V4, Public>::default();
    let raw_data = Self::get_raw_data(potential_token, potential_footer.clone(), &header)?;
    let raw_payload = Payload::from(raw_data.as_ref());

    //decrypt the payload
    //can raise exceptions
    let payload = try_verify_signed_payload(
      &raw_payload,
      &header.as_ref(),
      &potential_footer.unwrap_or_default(),
      &potential_assertion,
      key,
    )?;

    Ok(Self {
      version: PhantomData,
      purpose: PhantomData,
      token: payload,
    })
  }
}
impl BasicTokenVerified<V2, Public> {
  // Given an arbitrary string, an encryption key and an optional footer,
  // validate and decrypt this token raising errors as needed
  pub fn parse<T>(
    potential_token: &T,
    potential_footer: Option<Footer>,
    key: &Key<V2, Public>,
  ) -> Result<BasicTokenVerified<V2, Public>, PasetoTokenParseError>
  where
    T: AsRef<str> + ?Sized,
  {
    let header = Header::<V2, Public>::default();
    let raw_data = Self::get_raw_data(potential_token, potential_footer.clone(), &header)?;
    let raw_payload = Payload::from(raw_data.as_ref());

    //decrypt the payload
    //can raise exceptions
    let payload = try_verify_signed_payload(
      &raw_payload,
      &header.as_ref(),
      &potential_footer.unwrap_or_default(),
      &None::<&str>,
      key,
    )?;

    Ok(Self {
      version: PhantomData,
      purpose: PhantomData,
      token: payload,
    })
  }
}
