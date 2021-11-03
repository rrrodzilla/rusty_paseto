extern crate ed25519_dalek;
use crate::traits::Base64Encodable;
use crate::{
  common::{Footer, Header, Local, Payload, V2},
  crypto::{get_encrypted_raw_payload, get_signed_raw_payload},
  keys::{Key, Key192Bit, Key256Bit, NonceKey},
};
use ed25519_dalek::Keypair;
use std::fmt;
use std::marker::PhantomData;

/// A V2 Local paseto token that has been encrypted with a V2LocalSharedKey
#[derive(Debug, PartialEq)]
pub struct GenericToken<Version, Purpose> {
  purpose: PhantomData<Purpose>,
  version: PhantomData<Version>,
  header: String,
  footer: Option<String>,
  implicit_assertion: Option<String>,
  payload: String,
}

impl<Purpose> GenericToken<V2, Purpose>
where
  Purpose: fmt::Display + Default,
  Key<V2, Purpose>: AsRef<Keypair>,
{
  /// Creates a new token from constituent parts
  pub fn new(message: Payload, key: &Key<V2, Purpose>, footer: Option<Footer>) -> GenericToken<V2, Purpose> {
    //set a default header for this token type
    let header = Header::<V2, Purpose>::default();
    //build and return the token
    Self::build_token(header, message, key, footer)
  }

  //split for unit and test vectors
  pub(super) fn build_token<HEADER, MESSAGE, PUBLICKEY>(
    header: HEADER,
    message: MESSAGE,
    key: &PUBLICKEY,
    footer: Option<Footer>,
  ) -> GenericToken<V2, Purpose>
  where
    HEADER: AsRef<str> + std::fmt::Display + Default,
    MESSAGE: AsRef<str>,
    PUBLICKEY: AsRef<Keypair>,
  {
    //encrypt the payload
    //let payload = Payload::from("test");
    //let key = Ed25519KeyPair::from_pkcs8(key.as_ref())?;
    let payload = &get_signed_raw_payload(&message, &header, &footer.clone().unwrap_or_default(), &key);

    //produce the token with the values
    //the payload and footer are both base64 encoded
    GenericToken::<V2, Purpose> {
      purpose: PhantomData,
      version: PhantomData,
      header: header.to_string(), //the header is not base64 encoded
      payload: payload.encode(),
      footer: footer.as_ref().map(|f| f.encode()),
      implicit_assertion: None,
    }
  }
}

impl<Version> GenericToken<Version, Local>
where
  Version: fmt::Display + Default,
  Key<Version, Local>: AsRef<[u8; 32]>,
{
  /// Creates a new token from constituent parts
  pub fn new(message: Payload, key: &Key<Version, Local>, footer: Option<Footer>) -> GenericToken<Version, Local> {
    //use a random nonce
    let nonce_key = NonceKey::new_random();
    //set a default header for this token type
    let header = Header::<Version, Local>::default();
    //build and return the token
    Self::build_token(header, message, key, footer, &nonce_key)
  }

  //split for unit and test vectors
  pub(super) fn build_token<HEADER, MESSAGE, SHAREDKEY, NONCEKEY>(
    header: HEADER,
    message: MESSAGE,
    key: &SHAREDKEY,
    footer: Option<Footer>,
    nonce_key: &NONCEKEY,
  ) -> GenericToken<Version, Local>
  where
    HEADER: AsRef<str> + std::fmt::Display + Default,
    MESSAGE: AsRef<str>,
    SHAREDKEY: AsRef<Key256Bit>,
    NONCEKEY: AsRef<Key192Bit>,
  {
    //encrypt the payload
    let payload = &get_encrypted_raw_payload(&message, &header, &footer.clone().unwrap_or_default(), key, nonce_key);

    //produce the token with the values
    //the payload and footer are both base64 encoded
    GenericToken::<Version, Local> {
      purpose: PhantomData,
      version: PhantomData,
      header: header.to_string(), //the header is not base64 encoded
      payload: payload.encode(),
      footer: footer.as_ref().map(|f| f.encode()),
      implicit_assertion: None,
    }
  }
}

impl<Version, Purpose> fmt::Display for GenericToken<Version, Purpose> {
  /// Formats the token for display and subsequently allows a to_string implementation
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    if let Some(footer) = &self.footer {
      write!(f, "{}{}.{}", self.header, self.payload, footer)
    } else {
      write!(f, "{}{}", self.header, self.payload)
    }
  }
}

#[cfg(test)]
mod v2_test_vectors {

  use crate::common::{Footer, Header, Local, Payload, Public, V2};
  use crate::keys::{HexKey, Key, Key192Bit, Key256Bit, Key512Bit, NonceKey};
  use crate::tokens::GenericToken;
  use anyhow::Result;
  use serde_json::{json, Value};
  use std::convert::TryFrom;

  fn test_vector(nonce: &str, key: &str, expected_token: &str, payload: &Value, footer: Option<Footer>) -> Result<()> {
    // parse the hex string to ensure it will make a valid key
    let hex_key = key.parse::<HexKey<Key256Bit>>()?;
    //then generate the V2 local key for it
    let key = &Key::<V2, Local>::from(hex_key);

    let nonce_key = nonce.parse::<HexKey<Key192Bit>>()?;
    let nonce = NonceKey::from(nonce_key);
    //create message for test vector
    let json = payload.to_string();
    //  eprintln!("\nJSON INFO: {}\n", json);
    let message = Payload::from(json.as_str());
    let header = Header::<V2, Local>::default();

    //  //create a local v2 token
    let token = GenericToken::<V2, Local>::build_token(header, message, &key, footer, &nonce);

    //validate the test vector
    assert_eq!(token.to_string(), expected_token);

    //now let's try to decrypt it
    let decrypted_payload =
      crate::decrypted_tokens::GenericTokenDecrypted::<V2, Local>::parse(token.to_string().as_str(), None, key);
    if let Ok(payload) = decrypted_payload {
      assert_eq!(payload.as_ref(), message.as_ref());
    }
    Ok(())
  }

  #[test]
  fn test_2_s_1() -> Result<()> {
    //then generate the V2 local key for it
    let secret_key = "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2"
        .parse::<HexKey<Key512Bit>>()?;
    let key = Key::<V2, Public>::try_from(secret_key.as_ref())?;
    let payload = json!({"data": "this is a signed message","exp": "2019-01-01T00:00:00+00:00"}).to_string();

    //create message for test vector
    //  eprintln!("\nJSON INFO: {}\n", json);
    let message = Payload::from(payload.as_str());
    let header = Header::<V2, Public>::default();

    //  //  //create a local v2 token
    let token = GenericToken::<V2, Public>::build_token(header, message, &key, None);

    //  //validate the test vector
    assert_eq!(token.to_string(), "v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9HQr8URrGntTu7Dz9J2IF23d1M7-9lH9xiqdGyJNvzp4angPW5Esc7C5huy_M8I8_DjJK2ZXC2SUYuOFM-Q_5Cw");

    //now let's try to decrypt it
    let decrypted_payload =
      crate::decrypted_tokens::GenericTokenDecrypted::<V2, Public>::parse(token.to_string().as_str(), None, &key);
    if let Ok(payload) = decrypted_payload {
      assert_eq!(payload.as_ref(), message.as_ref());
    }
    Ok(())
  }

  #[test]
  fn test_2_e_1() -> Result<()> {
    test_vector("000000000000000000000000000000000000000000000000",  "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",  "v2.local.97TTOvgwIxNGvV80XKiGZg_kD3tsXM_-qB4dZGHOeN1cTkgQ4PnW8888l802W8d9AvEGnoNBY3BnqHORy8a5cC8aKpbA0En8XELw2yDk2f1sVODyfnDbi6rEGMY3pSfCbLWMM2oHJxvlEl2XbQ", &json!({"data": "this is a signed message","exp": "2019-01-01T00:00:00+00:00"}), None)?;

    Ok(())
  }

  #[test]
  fn test_2_e_2() -> Result<()> {
    test_vector("000000000000000000000000000000000000000000000000",  "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",  "v2.local.CH50H-HM5tzdK4kOmQ8KbIvrzJfjYUGuu5Vy9ARSFHy9owVDMYg3-8rwtJZQjN9ABHb2njzFkvpr5cOYuRyt7CRXnHt42L5yZ7siD-4l-FoNsC7J2OlvLlIwlG06mzQVunrFNb7Z3_CHM0PK5w", &json!({
        "data": "this is a secret message",
        "exp": "2019-01-01T00:00:00+00:00"
      }), None)?;

    Ok(())
  }

  #[test]
  fn test_2_e_3() -> Result<()> {
    test_vector("45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b",  "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",  "v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bbjo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6Qclw3qTKIIl5-O5xRBN076fSDPo5xUCPpBA", &json!({
        "data": "this is a signed message",
        "exp": "2019-01-01T00:00:00+00:00"
      }), None)?;

    Ok(())
  }

  #[test]
  fn test_2_e_4() -> Result<()> {
    test_vector("45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b",  "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",  "v2.local.pvFdDeNtXxknVPsbBCZF6MGedVhPm40SneExdClOxa9HNR8wFv7cu1cB0B4WxDdT6oUc2toyLR6jA6sc-EUM5ll1EkeY47yYk6q8m1RCpqTIzUrIu3B6h232h62DPbIxtjGvNRAwsLK7LcV8oQ", &json!({
        "data": "this is a secret message",
        "exp": "2019-01-01T00:00:00+00:00"
      }), None)?;

    Ok(())
  }

  #[test]
  fn test_2_e_5() -> Result<()> {
    test_vector("45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b",  "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",  "v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bbjo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6Qclw3qTKIIl5-zSLIrxZqOLwcFLYbVK1SrQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9", &json!({
        "data": "this is a signed message",
        "exp": "2019-01-01T00:00:00+00:00"
      }), Some(Footer::from("{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}")))?;

    Ok(())
  }

  #[test]
  fn test_2_e_6() -> Result<()> {
    test_vector("45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b",  "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",  "v2.local.pvFdDeNtXxknVPsbBCZF6MGedVhPm40SneExdClOxa9HNR8wFv7cu1cB0B4WxDdT6oUc2toyLR6jA6sc-EUM5ll1EkeY47yYk6q8m1RCpqTIzUrIu3B6h232h62DnMXKdHn_Smp6L_NfaEnZ-A.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9", &json!({
        "data": "this is a secret message",
        "exp": "2019-01-01T00:00:00+00:00"
      }), Some(Footer::from("{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}")))?;

    Ok(())
  }

  #[test]
  fn test_2_e_7() -> Result<()> {
    test_vector("45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b",  "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",  "v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bbjo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6Qclw3qTKIIl5-zSLIrxZqOLwcFLYbVK1SrQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9", &json!({
        "data": "this is a signed message",
        "exp": "2019-01-01T00:00:00+00:00"
      }), Some(Footer::from("{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}")))?;

    Ok(())
  }

  #[test]
  fn test_2_e_8() -> Result<()> {
    test_vector("45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b",  "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",  "v2.local.pvFdDeNtXxknVPsbBCZF6MGedVhPm40SneExdClOxa9HNR8wFv7cu1cB0B4WxDdT6oUc2toyLR6jA6sc-EUM5ll1EkeY47yYk6q8m1RCpqTIzUrIu3B6h232h62DnMXKdHn_Smp6L_NfaEnZ-A.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9", &json!({
        "data": "this is a secret message",
        "exp": "2019-01-01T00:00:00+00:00"
      }), Some(Footer::from("{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}")))?;

    Ok(())
  }

  #[test]
  fn test_2_e_9() -> Result<()> {
    test_vector("45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b",  "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",  "v2.local.pvFdDeNtXxknVPsbBCZF6MGedVhPm40SneExdClOxa9HNR8wFv7cu1cB0B4WxDdT6oUc2toyLR6jA6sc-EUM5ll1EkeY47yYk6q8m1RCpqTIzUrIu3B6h232h62DoOJbyKBGPZG50XDZ6mbPtw.YXJiaXRyYXJ5LXN0cmluZy10aGF0LWlzbid0LWpzb24", &json!({
        "data": "this is a secret message",
        "exp": "2019-01-01T00:00:00+00:00"
      }), Some(Footer::from("arbitrary-string-that-isn't-json")))?;

    Ok(())
  }
}

#[cfg(test)]
mod unit_tests {

  use crate::untrusted_tokens::*;

  #[test]
  fn test_v2_local_encrypted_parse_with_footer() {
    let potential_token = "v2.local.some_stuff.aGVyZXNfYV9mb290ZXI".parse::<UntrustedEncryptedToken>();
    assert!(potential_token.is_ok());
    let token_parts = potential_token.unwrap();
    let (payload, header, base64_encoded_footer) = token_parts.as_ref();
    assert!(base64_encoded_footer.is_some());
    assert_eq!(payload, "some_stuff");
    assert_eq!(header, "v2.local.");
  }

  #[test]
  fn test_v2_local_encrypted_parse_no_footer() {
    let potential_token = "v2.local.some_stuff".parse::<UntrustedEncryptedToken>();
    assert!(potential_token.is_ok());
    let token_parts = potential_token.unwrap();
    let (payload, header, footer) = token_parts.as_ref();
    assert_eq!(header, "v2.local.");
    assert!(footer.is_none());
    assert_eq!(payload, "some_stuff");
  }
}
