use base64::{encode_config, URL_SAFE_NO_PAD};
//use serde_json;
use std::cmp::PartialEq;
use std::convert::{AsRef, From};
use std::default::Default;
use std::fmt;

use crate::crypto::get_encrypted_raw_payload;
use crate::keys::NonceKey;
use crate::V2SymmetricKey;

pub struct Message<'a>(&'a str);
impl<'a> AsRef<str> for Message<'a> {
  fn as_ref(&self) -> &str {
    self.0
  }
}
impl<'a> Default for Message<'a> {
  fn default() -> Self {
    Self("")
  }
}
impl<'a> From<&'a str> for Message<'a> {
  fn from(s: &'a str) -> Self {
    Self(s)
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
#[derive(Clone)]
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
impl<'a> Footer<'a> {
  fn encode(&self) -> String {
    encode_config(self.0, URL_SAFE_NO_PAD)
  }
}
impl<'a> fmt::Display for Footer<'a> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, ".{}", self.0)
  }
}
#[derive(Clone)]
pub struct RawPayload(Vec<u8>);
impl From<Vec<u8>> for RawPayload {
  fn from(s: Vec<u8>) -> Self {
    Self(s)
  }
}
impl RawPayload {
  pub(crate) fn encode(self) -> String {
    encode_config(self.0, URL_SAFE_NO_PAD)
  }
}

/// A V2 Local paseto token that has been encrypted
#[derive(Debug, PartialEq)]
pub struct V2LocalToken {
  header: String,
  footer: Option<String>,
  payload: String,
}
impl V2LocalToken {
  pub fn new(message: Message, key: V2SymmetricKey, footer: Option<Footer>) -> V2LocalToken {
    let nonce_key = NonceKey::new_random();

    V2LocalToken::build_v2_local_token(message, key, footer, &nonce_key)
  }

  pub(crate) fn build_v2_local_token(
    message: Message,
    key: V2SymmetricKey,
    footer: Option<Footer>,
    nonce_key: &NonceKey,
  ) -> V2LocalToken {
    let header = Header::default();
    let payload: RawPayload;

    if let Some(ref f) = footer {
      payload = get_encrypted_raw_payload(&message, &header, f, key, nonce_key);
    } else {
      payload = get_encrypted_raw_payload(&message, &header, &Footer::default(), key, nonce_key);
    }
    let mut temp_footer: Option<String> = None;
    if footer.is_some() {
      temp_footer = Some(footer.as_ref().unwrap().encode());
    }

    V2LocalToken {
      header: header.to_string(),
      payload: payload.encode(),
      footer: temp_footer,
    }
  }
}
impl fmt::Display for V2LocalToken {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    if let Some(provided_footer) = &self.footer {
      write!(f, "{}{}.{}", self.header, self.payload, provided_footer)
    } else {
      write!(f, "{}{}", self.header, self.payload)
    }
  }
}

#[cfg(test)]
mod test_vectors {

  use super::*;
  use crate::{keys::HexKey, Key256Bit, V2SymmetricKey};
  use serde_json::json;

  #[test]
  fn test_2_e_1() {
    const EXPECTED_TOKEN: &str = "v2.local.97TTOvgwIxNGvV80XKiGZg_kD3tsXM_-qB4dZGHOeN1cTkgQ4PnW8888l802W8d9AvEGnoNBY3BnqHORy8a5cC8aKpbA0En8XELw2yDk2f1sVODyfnDbi6rEGMY3pSfCbLWMM2oHJxvlEl2XbQ";
    // parse the hex string to ensure it will make a valid key
    let hex_key = "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f"
      .parse::<HexKey<Key256Bit>>()
      .expect("Could not parse hex value from string");
    //then generate the V2 local key for it
    let key = V2SymmetricKey::from(hex_key);

    //create message for test vector
    let json = json!({
      "data": "this is a signed message",
      "exp": "2019-01-01T00:00:00+00:00"
    })
    .to_string();
    let message = Message::from(json.as_str());

    //create a local v2 token
    let token = V2LocalToken::build_v2_local_token(message, key, None, &NonceKey::default());

    //validate the test vector
    assert_eq!(token.to_string(), EXPECTED_TOKEN);
  }
}
#[cfg(test)]
mod v2_additional_tests {

  use super::*;

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
  fn test_set_v2_footer() {
    let footer: Footer = "wubbulubbadubdub".into();
    assert_eq!(footer.as_ref(), "wubbulubbadubdub");
    assert!(!footer.as_ref().is_empty());
  }
}
