pub(crate) mod v2 {
  use crate::traits::Base64Encodable;
  use crate::{
    common::{Footer, Payload},
    crypto::get_encrypted_raw_payload,
    headers::v2::V2LocalHeader,
    keys::{Key192Bit, Key256Bit, NonceKey, V2LocalSharedKey},
  };
  use std::fmt;

  /// A V2 Local paseto token that has been encrypted with a V2LocalSharedKey
  #[derive(Debug, PartialEq)]
  pub struct V2LocalToken {
    header: String,
    footer: Option<String>,
    payload: String,
  }

  impl V2LocalToken {
    /// Creates a new token from constituent parts
    pub fn new(message: Payload, key: &V2LocalSharedKey, footer: Option<Footer>) -> V2LocalToken {
      //use a random nonce
      let nonce_key = NonceKey::new_random();
      //set a default header for this token type
      let header = V2LocalHeader::default();
      //build and return the token
      Self::build_token(header, message, key, footer, &nonce_key)
    }

    //split for unit and test vectors
    pub(super) fn build_token<H, P, F, SK, NK>(
      header: H,
      message: P,
      key: &SK,
      footer: Option<F>,
      nonce_key: &NK,
    ) -> V2LocalToken
    where
      H: AsRef<str> + std::fmt::Display,
      P: AsRef<str>,
      F: Base64Encodable<str> + Default + Clone,
      SK: AsRef<Key256Bit>,
      NK: AsRef<Key192Bit>,
    {
      //encrypt the payload
      let payload = &get_encrypted_raw_payload(&message, &header, &footer.clone().unwrap_or_default(), key, nonce_key);

      //produce the token with the values
      //the payload and footer are both base64 encoded
      V2LocalToken {
        header: header.to_string(), //the header is not base64 encoded
        payload: payload.encode(),
        footer: footer.as_ref().map(|f| f.encode()),
      }
    }
  }

  impl fmt::Display for V2LocalToken {
    /// Formats the token for display and subsequently allows a to_string implementation
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      if let Some(footer) = &self.footer {
        write!(f, "{}{}.{}", self.header, self.payload, footer)
      } else {
        write!(f, "{}{}", self.header, self.payload)
      }
    }
  }
}

#[cfg(test)]
mod v2_test_vectors {

  use crate::headers::v2::V2LocalHeader;
  use crate::keys::{HexKey, Key256Bit, NonceKey, V2LocalSharedKey};
  use crate::tokens::v2::V2LocalToken;
  use crate::v2::{Footer, Payload};
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
    let header = V2LocalHeader::default();

    //create a local v2 token
    let token = V2LocalToken::build_token::<V2LocalHeader, Payload, Footer, V2LocalSharedKey, NonceKey>(
      header,
      message,
      &key,
      None,
      &NonceKey::default(),
    );

    //validate the test vector
    assert_eq!(token.to_string(), EXPECTED_TOKEN);

    //now let's try to decrypt it
    let decrypted_payload =
      crate::decrypted_tokens::V2LocalDecryptedString::parse(token.to_string().as_str(), None, key);
    if let Ok(payload) = decrypted_payload {
      assert_eq!(payload.as_ref(), message.as_ref());
      eprintln!("{}", payload);
    }
  }
}

#[cfg(test)]
mod unit_tests {

  use crate::untrusted_tokens::*;

  #[test]
  fn test_v2_local_encrypted_parse_with_footer() {
    let potential_token = "v2.local.some_stuff.aGVyZXNfYV9mb290ZXI".parse::<V2LocalUntrustedEncryptedToken>();
    assert!(potential_token.is_ok());
    let token_parts = potential_token.unwrap();
    let (payload, base64_encoded_footer) = token_parts.as_ref();
    assert!(base64_encoded_footer.is_some());
    //  TODO: revisit
    //  assert_eq!(
    //    base64_encoded_footer,
    //    Base64EncodedString::from("heres_a_footer".to_string())
    //      .as_ref()
    //      .to_string()
    //  );
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
}
