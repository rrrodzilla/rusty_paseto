use crate::common::{Footer, PurposeLocal, Version2};
use crate::crypto::{try_decrypt_payload, validate_footer_against_hex_encoded_footer_in_constant_time};
use crate::errors::PasetoTokenParseError;
use crate::headers::v2::*;
use crate::keys::Key;
use crate::untrusted_tokens::UntrustedEncryptedToken;
use crate::v2::Payload;
use std::cmp::PartialEq;
use std::convert::AsRef;
use std::default::Default;
use std::fmt;
use std::marker::PhantomData;
use std::str::FromStr;

/// Parses a V2 Local paseto token string and provides the decrypted payload string
#[derive(Debug, PartialEq)]
pub struct DecryptedToken<Version, Purpose> {
  version: PhantomData<Version>,
  purpose: PhantomData<Purpose>,
  token: String,
}

impl<R, Version, Purpose> PartialEq<R> for DecryptedToken<Version, Purpose>
where
  R: AsRef<str>,
{
  fn eq(&self, other: &R) -> bool {
    self.as_ref() == other.as_ref()
  }
}
impl<Version, Purpose> fmt::Display for DecryptedToken<Version, Purpose> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", self.token)
  }
}

impl<Version, Purpose> AsRef<String> for DecryptedToken<Version, Purpose> {
  fn as_ref(&self) -> &String {
    &self.token
  }
}

impl DecryptedToken<Version2, PurposeLocal> {
  // Given an arbitrary string, an encryption key and an optional footer,
  // validate and decrypt this token raising errors as needed
  pub fn parse<T>(
    potential_token: &T,
    potential_footer: Option<Footer>,
    key: &Key<Version2, PurposeLocal>,
  ) -> Result<DecryptedToken<Version2, PurposeLocal>, PasetoTokenParseError>
  where
    T: AsRef<str> + ?Sized,
  {
    //an initial parse of the incoming string to see what we find and validate its structure
    //can raise exceptions
    let parsed_values = UntrustedEncryptedToken::<Version2, PurposeLocal>::from_str(potential_token.as_ref())?;
    //if all went well, we can extract the values
    let (parsed_payload, found_footer) = parsed_values.as_ref();

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
