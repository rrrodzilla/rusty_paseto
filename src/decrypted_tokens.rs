use crate::common::Footer;
use crate::crypto::{try_decrypt_payload, validate_footer_against_hex_encoded_footer_in_constant_time};
use crate::errors::PasetoTokenParseError;
use crate::headers::Header;
use crate::untrusted_tokens::V2LocalUntrustedEncryptedToken;
use crate::v2::local::V2LocalSharedKey;
use std::cmp::PartialEq;
use std::convert::AsRef;
use std::default::Default;
use std::fmt;
use std::str::FromStr;

/// Parses a V2 Local paseto token string and provides the decrypted payload string
#[derive(Debug, PartialEq)]
pub struct V2LocalDecryptedString(String);

impl<R> PartialEq<R> for V2LocalDecryptedString
where
  R: AsRef<str>,
{
  fn eq(&self, other: &R) -> bool {
    self.as_ref() == other.as_ref()
  }
}
impl fmt::Display for V2LocalDecryptedString {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", self.0)
  }
}

impl AsRef<String> for V2LocalDecryptedString {
  fn as_ref(&self) -> &String {
    &self.0
  }
}

impl V2LocalDecryptedString {
  /// Given an arbitrary string, an encryption key and an optional footer,
  /// validate and decrypt this token raising errors as needed
  pub fn parse<T>(
    potential_token: &T,
    potential_footer: Option<Footer>,
    key: &V2LocalSharedKey,
  ) -> Result<V2LocalDecryptedString, PasetoTokenParseError>
  where
    T: AsRef<str> + ?Sized,
  {
    //an initial parse of the incoming string to see what we find and validate it's structure
    let parsed_values = V2LocalUntrustedEncryptedToken::from_str(potential_token.as_ref())?;
    //if all went well, we can extract the values
    let (raw_payload, found_footer) = parsed_values.as_ref();

    //verify any provided and/or discovered footers are valid
    validate_footer_against_hex_encoded_footer_in_constant_time(potential_footer, found_footer)?;

    //decrypt the payload
    let payload = try_decrypt_payload(
      raw_payload,
      &Header::default(),
      &potential_footer.unwrap_or_default(),
      key,
    )?;
    Ok(Self(payload))
  }
}
