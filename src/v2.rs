//use serde_json;
use crate::crypto::{get_encrypted_raw_payload, try_decrypt_payload, Base64EncodedString};
use crate::keys::NonceKey;
use crate::V2LocalSharedKey;
use std::cmp::PartialEq;
use std::convert::{AsRef, From};
use std::default::Default;
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

/// The token payload
#[derive(PartialEq, Debug, Clone, Copy)]
pub struct Payload<'a>(&'a str);
impl<'a> AsRef<str> for Payload<'a> {
  fn as_ref(&self) -> &str {
    self.0
  }
}
impl<'a> Default for Payload<'a> {
  fn default() -> Self {
    Self("")
  }
}
impl<'a> From<&'a str> for Payload<'a> {
  fn from(s: &'a str) -> Self {
    Self(s)
  }
}
impl<'a, R> PartialEq<R> for Payload<'a>
where
  R: AsRef<&'a str>,
{
  fn eq(&self, other: &R) -> bool {
    self.as_ref() == *other.as_ref()
  }
}
impl<'a> fmt::Display for Payload<'a> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", self.0)
  }
}

#[derive(PartialEq, Debug)]
pub struct Header<'a>(&'a str);

impl<'a> PartialEq<str> for Header<'a> {
  fn eq(&self, other: &str) -> bool {
    self.as_ref() == other
  }
}
impl<'a> PartialEq<Header<'a>> for str {
  fn eq(&self, other: &Header<'a>) -> bool {
    self == other.as_ref()
  }
}
impl<'a> AsRef<str> for Header<'a> {
  fn as_ref(&self) -> &str {
    self.0
  }
}
impl<'a> Default for Header<'a> {
  fn default() -> Self {
    Self("v2.local.")
  }
}

impl<'a> fmt::Display for Header<'a> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", self.0)
  }
}

/// An optional footer for paseto tokens
#[derive(Clone, Copy)]
pub struct Footer<'a>(&'a str);

impl<'a> AsRef<str> for Footer<'a> {
  fn as_ref(&self) -> &str {
    self.0
  }
}
impl<'a> Default for Footer<'a> {
  fn default() -> Self {
    Self("")
  }
}
impl<'a> From<&'a str> for Footer<'a> {
  fn from(s: &'a str) -> Self {
    Self(s)
  }
}
impl<'a> fmt::Display for Footer<'a> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", self.0)
  }
}
impl<'a> PartialEq for Footer<'a> {
  fn eq(&self, other: &Self) -> bool {
    self.0 == other.0
  }
}

impl<'a> Eq for Footer<'a> {}

/// Potential errors from attempting to parse a token string
#[derive(Debug, Error)]
pub enum V2LocalTokenParseError {
  #[error("This string has an incorrect number of parts and cannot be parsed into a token")]
  IncorrectSize,
  #[error("The token header is invalid")]
  WrongHeader,
  #[error("The provided footer is invalid")]
  FooterInvalid,
  #[error("Couldn't decode the payload before encryption")]
  PayloadDecode {
    #[from]
    source: base64::DecodeError,
  },
  #[error("This error can never happen")]
  Infallible {
    #[from]
    source: std::convert::Infallible,
  },
  #[error("Couldn't decrypt payload")]
  Decrypt,
}
/// Parses a V2 Local paseto token string and provides the decrypted payload string
#[derive(Debug, PartialEq)]
pub struct V2LocalDecryptedString(String);

impl PartialEq<Payload<'_>> for V2LocalDecryptedString {
  fn eq(&self, other: &Payload) -> bool {
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
  pub fn parse(
    potential_token: &str,
    potential_footer: Option<Footer>,
    key: &V2LocalSharedKey,
  ) -> Result<V2LocalDecryptedString, V2LocalTokenParseError> {
    //an initial parse of the incoming string to see what we find and validate it's structure
    let parsed_values = potential_token.parse::<V2LocalUntrustedEncryptedToken>()?;
    //if all went well, we can extract the values
    let (raw_payload, found_footer) = parsed_values.as_ref();

    //verify any provided and/or discovered footers are valid
    Self::validate_footer_against_hex_encoded_footer_in_constant_time(potential_footer, found_footer)?;

    //decrypt the payload
    let payload = try_decrypt_payload(
      raw_payload,
      &Header::default(),
      &potential_footer.unwrap_or_default(),
      key,
    )?;
    Ok(Self(payload))
  }

  fn validate_footer_against_hex_encoded_footer_in_constant_time(
    footer: Option<Footer>,
    encoded_footer_string: &Option<String>,
  ) -> Result<(), V2LocalTokenParseError> {
    if let Some(found_footer_string) = encoded_footer_string {
      //this means we found a footer in the provided token string
      //so that means we should also have a provided footer when this method was called
      if let Some(provided_footer) = footer {
        //encode the found and provided footers
        let encoded_provided_footer = Base64EncodedString::from(provided_footer.as_ref().to_string());
        let encoded_found_footer = found_footer_string.parse::<Base64EncodedString>().unwrap();

        //test for equality using ConstantTimeEquals
        if encoded_provided_footer.ne(&encoded_found_footer) {
          Err(V2LocalTokenParseError::FooterInvalid)
        } else {
          Ok(())
        }
      } else {
        //this means we found a footer in the provided string but there
        //wasn't one provided in the method call
        Err(V2LocalTokenParseError::FooterInvalid)
      }
    } else {
      //this means there was no footer found in the provided token string
      if footer.is_some() {
        //if one was provided anyway, we should err
        Err(V2LocalTokenParseError::FooterInvalid)
      } else {
        Ok(())
      }
    }
  }
}

/// A V2 Local paseto token that has been encrypted with a V2LocalSharedKey
#[derive(Debug, PartialEq)]
pub struct V2LocalToken {
  header: String,
  footer: Option<String>,
  payload: String,
  token: String,
}
impl AsRef<String> for V2LocalToken {
  fn as_ref(&self) -> &String {
    &self.token
  }
}
impl V2LocalToken {
  /// Creates a new token from constituent parts
  pub fn new(message: Payload, key: &V2LocalSharedKey, footer: Option<Footer>) -> V2LocalToken {
    //use a random nonce
    let nonce_key = NonceKey::new_random();

    //build the token
    Self::build_v2_local_token(message, key, footer, &nonce_key)
  }

  fn build_v2_local_token(
    message: Payload,
    key: &V2LocalSharedKey,
    footer: Option<Footer>,
    nonce_key: &NonceKey,
  ) -> V2LocalToken {
    //set a default header for this token type and use
    let header = Header::default();

    //if there was a footer supplied, we'll need to encode it
    //otherwise default to None
    let mut optional_encoded_footer: Option<String> = None;
    if let Some(ref some_footer) = footer {
      optional_encoded_footer = Some(
        Base64EncodedString::from(some_footer.as_ref().to_string())
          .as_ref()
          .to_string(),
      );
    }

    //encrypt the payload
    let payload = Base64EncodedString::from(get_encrypted_raw_payload(
      &message,
      &header,
      &footer.unwrap_or_default(),
      key,
      nonce_key,
    ))
    .as_ref()
    .to_string();

    let token: String;
    if let Some(f) = optional_encoded_footer.clone() {
      token = format!("{}{}.{}", header, payload, f);
    } else {
      token = format!("{}{}", header, payload);
    }

    //produce the token with the values
    V2LocalToken {
      header: header.to_string(), //the header is not base64 encoded
      payload: Base64EncodedString::from(payload).as_ref().to_string(),
      footer: optional_encoded_footer,
      token,
    }
  }
}

impl fmt::Display for V2LocalToken {
  /// Formats the token for display and subsequently allows a to_string implementation
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", self.token)
  }
}

/// A type alias to simplify usage of this tuple (header, payload, potential footer)
/// each value in the tuple EXCEPT for the header should be base64 encoded already
type V2LocalUntrustedEncryptedTokenParts = (String, Option<String>);

/// A private struct for parsing an incoming token string
struct V2LocalUntrustedEncryptedToken(V2LocalUntrustedEncryptedTokenParts);

impl AsRef<V2LocalUntrustedEncryptedTokenParts> for V2LocalUntrustedEncryptedToken {
  fn as_ref(&self) -> &V2LocalUntrustedEncryptedTokenParts {
    &self.0
  }
}

impl FromStr for V2LocalUntrustedEncryptedToken {
  type Err = V2LocalTokenParseError;

  /// This is where the real work is done to parse any ole string which may or may not
  /// be a token.  This parsing function doesn't validate or decrypt the token, it merely
  /// ensures it can be broken down into the various parts which constitute a valid token structure
  fn from_str(s: &str) -> Result<Self, Self::Err> {
    //split the string into it's consituent parts
    let potential_parts = s.split('.').collect::<Vec<_>>();

    //first let's see if there are enough parts
    if potential_parts.len() < 3 || potential_parts.len() > 4 {
      return Err(V2LocalTokenParseError::IncorrectSize);
    };

    //now let's check the header
    //first reconstruct it from the incoming string parts
    let potential_header = format!("{}.{}.", potential_parts[0], potential_parts[1]);
    //if the recreated header is not equal to a valid known Header, then the header is invalid
    if potential_header.ne(Header::default().as_ref()) {
      return Err(V2LocalTokenParseError::WrongHeader);
    }

    //produce the struct based on whether there is a potential footer or not
    match potential_parts.len() {
      //no footer
      3 => Ok(Self((Payload::from(potential_parts[2]).to_string(), None))),
      //otherwise there must be
      _ => Ok(Self((
        Payload::from(potential_parts[2]).to_string(),
        Some(Footer::from(potential_parts[3]).to_string()),
      ))),
    }
  }
}

#[cfg(test)]
mod test_vectors {

  use super::*;
  use crate::{keys::HexKey, Key256Bit, V2LocalSharedKey};
  use serde_json::json;

  #[test]
  fn test_2_e_1() {
    const EXPECTED_TOKEN: &str = "v2.local.97TTOvgwIxNGvV80XKiGZg_kD3tsXM_-qB4dZGHOeN1cTkgQ4PnW8888l802W8d9AvEGnoNBY3BnqHORy8a5cC8aKpbA0En8XELw2yDk2f1sVODyfnDbi6rEGMY3pSfCbLWMM2oHJxvlEl2XbQ";
    // parse the hex string to ensure it will make a valid key
    let hex_key = "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f"
      .parse::<HexKey<Key256Bit>>()
      .expect("Could not parse hex value from string");
    //then generate the V2 local key for it
    let key = &V2LocalSharedKey::from(hex_key);

    //create message for test vector
    let json = json!({
      "data": "this is a signed message",
      "exp": "2019-01-01T00:00:00+00:00"
    })
    .to_string();
    let message = Payload::from(json.as_str());

    //create a local v2 token
    let token = V2LocalToken::build_v2_local_token(message, &key, None, &NonceKey::default());

    //validate the test vector
    assert_eq!(token.to_string(), EXPECTED_TOKEN);

    //now let's try to decrypt it
    let decrypted_payload = V2LocalDecryptedString::parse(token.to_string().as_str(), None, key);
    if let Ok(payload) = decrypted_payload {
      assert_eq!(payload.as_ref(), message.as_ref());
      eprintln!("{}", payload);
    }
  }
}
#[cfg(test)]
mod v2_additional_tests {

  use super::*;

  #[test]
  fn test_v2_local_encrypted_parse_with_footer() {
    let potential_token = "v2.local.some_stuff.aGVyZXNfYV9mb290ZXI".parse::<V2LocalUntrustedEncryptedToken>();
    assert!(potential_token.is_ok());
    let token_parts = potential_token.unwrap();
    let (payload, base64_encoded_footer) = token_parts.as_ref();
    assert!(base64_encoded_footer.is_some());
    assert_eq!(
      base64_encoded_footer.as_ref().unwrap().to_string(),
      Base64EncodedString::from("heres_a_footer".to_string())
        .as_ref()
        .to_string()
    );
    assert_eq!(payload, "some_stuff");
  }

  #[test]
  fn test_v2_local_encrypted_parse_no_footer() {
    let potential_token = "v2.local.some_stuff".parse::<V2LocalUntrustedEncryptedToken>();
    assert!(potential_token.is_ok());
    let token_parts = potential_token.unwrap();
    let (payload, footer) = token_parts.as_ref();
    assert!(footer.is_none());
    assert_eq!(payload, "some_stuff");
  }

  #[test]
  fn test_v2_header_equality() {
    let header = Header::default();
    assert_eq!(&header, "v2.local.")
  }

  #[test]
  fn test_v2_header_outfix_equality_from_str() {
    assert!("v2.local.".eq(&Header::default()));
  }

  #[test]
  fn test_v2_header_outfix_equality() {
    assert!(Header::default().eq("v2.local."));
  }

  #[test]
  fn test_v2_footer() {
    let footer = Footer::default();
    assert_eq!(footer.as_ref(), "");
    assert!(footer.as_ref().is_empty());
  }

  #[test]
  fn test_v2_footer_encoded_equality() {
    let this_footer = Base64EncodedString::from(String::default());
    let that_footer = Base64EncodedString::from(String::default());
    assert!(this_footer == that_footer);
  }

  #[test]
  fn test_set_v2_footer() {
    let footer: Footer = "wubbulubbadubdub".into();
    assert_eq!(footer.as_ref(), "wubbulubbadubdub");
    assert!(!footer.as_ref().is_empty());
  }
}
