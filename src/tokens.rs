pub(crate) mod v2 {
  use crate::traits::Base64Encodable;
  use crate::{
    common::{Footer, Payload, PurposeLocal, Version2},
    crypto::get_encrypted_raw_payload,
    headers::v2::Header,
    keys::{Key, Key192Bit, Key256Bit, NonceKey},
  };
  use std::fmt;
  use std::marker::PhantomData;

  /// A V2 Local paseto token that has been encrypted with a V2LocalSharedKey
  #[derive(Debug, PartialEq)]
  pub struct Token<Version, Purpose> {
    purpose: PhantomData<Purpose>,
    version: PhantomData<Version>,
    header: String,
    footer: Option<String>,
    payload: String,
  }

  impl Token<Version2, PurposeLocal> {
    /// Creates a new token from constituent parts
    pub fn new(
      message: Payload,
      key: &Key<Version2, PurposeLocal>,
      footer: Option<Footer>,
    ) -> Token<Version2, PurposeLocal> {
      //use a random nonce
      let nonce_key = NonceKey::new_random();
      //set a default header for this token type
      let header = Header::<Version2, PurposeLocal>::default();
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
    ) -> Token<Version2, PurposeLocal>
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
      Token::<Version2, PurposeLocal> {
        purpose: PhantomData,
        version: PhantomData,
        header: header.to_string(), //the header is not base64 encoded
        payload: payload.encode(),
        footer: footer.as_ref().map(|f| f.encode()),
      }
    }
  }

  impl fmt::Display for Token<Version2, PurposeLocal> {
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

  use crate::common::{PurposeLocal, Version2};
  use crate::headers::v2::Header;
  use crate::keys::{HexKey, Key, Key192Bit, Key256Bit, NonceKey};
  use crate::tokens::v2::Token;
  use crate::v2::{Footer, Payload};
  use anyhow::Result;
  use serde_json::{json, Value};

  fn test_vector(nonce: &str, key: &str, expected_token: &str, payload: &Value, footer: Option<Footer>) -> Result<()> {
    // parse the hex string to ensure it will make a valid key
    let hex_key = key.parse::<HexKey<Key256Bit>>()?;
    //then generate the V2 local key for it
    let key = &Key::<Version2, PurposeLocal>::from(hex_key);

    let nonce_key = nonce.parse::<HexKey<Key192Bit>>()?;
    let nonce = NonceKey::from(nonce_key);
    //create message for test vector
    let json = payload.to_string();
    //  eprintln!("\nJSON INFO: {}\n", json);
    let message = Payload::from(json.as_str());
    let header = Header::<Version2, PurposeLocal>::default();

    //  //create a local v2 token
    let token = Token::<Version2, PurposeLocal>::build_token::<
      Header<Version2, PurposeLocal>,
      Payload,
      Footer,
      Key<Version2, PurposeLocal>,
      NonceKey,
    >(header, message, &key, footer, &nonce);

    //validate the test vector
    assert_eq!(token.to_string(), expected_token);

    //now let's try to decrypt it
    let decrypted_payload =
      crate::decrypted_tokens::DecryptedToken::<Version2, PurposeLocal>::parse(token.to_string().as_str(), None, key);
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

  use crate::common::*;
  use crate::untrusted_tokens::*;

  #[test]
  fn test_v2_local_encrypted_parse_with_footer() {
    let potential_token =
      "v2.local.some_stuff.aGVyZXNfYV9mb290ZXI".parse::<UntrustedEncryptedToken<Version2, PurposeLocal>>();
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
    let potential_token = "v2.local.some_stuff".parse::<UntrustedEncryptedToken<Version2, PurposeLocal>>();
    assert!(potential_token.is_ok());
    let token_parts = potential_token.unwrap();
    let (payload, footer) = token_parts.as_ref();
    assert!(footer.is_none());
    assert_eq!(payload, "some_stuff");
  }
}
