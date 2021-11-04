use crate::common::ImplicitAssertion;
use crate::traits::{AsymmetricKey, Base64Encodable, Sodium, SymmetricKey};
use crate::{
  common::{Footer, Header, Local, Payload, Public, V2, V4},
  crypto::{try_encrypt_payload, try_sign_payload},
  keys::{Key, Key256Bit, NonceKey},
};
use std::default::Default;
use std::fmt;
use std::fmt::Display;
use std::marker::PhantomData;

#[derive(Debug, PartialEq)]
pub struct BasicTokenBuilder<Version: Default + Display, Purpose: Default + Display> {
  purpose: PhantomData<Purpose>,
  version: PhantomData<Version>,
  header: Header<Version, Purpose>,
  footer: Option<Footer>,
  nonce_key: NonceKey,
  implicit_assertion: Option<ImplicitAssertion>,
  payload: Payload,
}

impl<Version, Purpose> BasicTokenBuilder<Version, Purpose>
where
  Version: Display + Default,
  Purpose: Display + Default,
{
  fn new() -> Self {
    Self {
      purpose: PhantomData,
      version: PhantomData,
      header: Header::<Version, Purpose>::default(),
      footer: None,
      nonce_key: NonceKey::new_random(),
      implicit_assertion: None,
      payload: Payload::from(""),
    }
  }

  pub fn set_footer(&mut self, footer: Footer) -> &mut Self {
    self.footer = Some(footer);
    self
  }
  pub fn set_payload(&mut self, payload: Payload) -> &mut Self {
    self.payload = payload;
    self
  }
}

impl<Purpose> BasicTokenBuilder<V4, Purpose>
where
  Purpose: Display + Default,
{
  pub fn set_implicit_assertion(&mut self, assertion: ImplicitAssertion) -> &mut Self {
    self.implicit_assertion = Some(assertion);
    self
  }
}

impl BasicTokenBuilder<V4, Public>
where
  Key<V4, Public>: AsymmetricKey,
{
  //split for unit and test vectors
  pub(super) fn build(&mut self, key: &impl AsymmetricKey) -> BasicToken<V4, Public> {
    let default = &ImplicitAssertion::default();
    let assertion = &self.implicit_assertion.as_ref().unwrap_or(default);
    //encrypt the payload
    let payload = &try_sign_payload(
      &self.payload,
      &self.header,
      &self.footer.clone().unwrap_or_default(),
      &Some(assertion),
      &key,
    );

    let encoded_footer = self.footer.as_ref().map(|f| f.encode());
    if let Some(footer) = encoded_footer {
      BasicToken {
        version: PhantomData,
        purpose: PhantomData,
        token: format!("{}{}.{}", self.header, payload.encode(), footer),
      }
    } else {
      BasicToken {
        version: PhantomData,
        purpose: PhantomData,
        token: format!("{}{}", self.header, payload.encode()),
      }
    }
  }
}

impl BasicTokenBuilder<V2, Public>
where
  Key<V2, Public>: AsymmetricKey,
{
  //split for unit and test vectors
  pub(super) fn build(&mut self, key: &impl AsymmetricKey) -> BasicToken<V2, Public> {
    //encrypt the payload
    let payload = &try_sign_payload(
      &self.payload,
      &self.header,
      &self.footer.clone().unwrap_or_default(),
      &None::<&str>,
      &key,
    );

    let encoded_footer = self.footer.as_ref().map(|f| f.encode());
    if let Some(footer) = encoded_footer {
      BasicToken {
        version: PhantomData,
        purpose: PhantomData,
        token: format!("{}{}.{}", self.header, payload.encode(), footer),
      }
    } else {
      BasicToken {
        version: PhantomData,
        purpose: PhantomData,
        token: format!("{}{}", self.header, payload.encode()),
      }
    }
  }
}

impl<Version> BasicTokenBuilder<Version, Local>
where
  Version: Sodium,
  Key<Version, Local>: SymmetricKey,
{
  //    /// Creates a new token from constituent parts
  //    pub fn new(message: Payload, key: &Key<Version, Local>, footer: Option<Footer>) -> BasicTokenBuilder<Version, Local> {
  //      //use a random nonce
  //      let nonce_key = NonceKey::new_random();
  //      //set a default header for this token type
  //      let header = Header::<Version, Local>::default();
  //      //build and return the token
  //      Self::build_token(header, message, key, footer, &nonce_key)
  //    }
  //
  #[allow(dead_code)]
  pub(self) fn set_nonce_key(&mut self, nonce_key: NonceKey) -> &mut Self {
    self.nonce_key = nonce_key;
    self
  }

  pub fn build<SHAREDKEY>(&mut self, key: &SHAREDKEY) -> BasicToken<Version, Local>
  where
    SHAREDKEY: AsRef<Key256Bit>,
  {
    //encrypt the payload
    let payload = &try_encrypt_payload(
      &self.payload,
      &self.header,
      &self.footer.clone().unwrap_or_default(),
      key,
      &self.nonce_key,
    );
    let encoded_footer = self.footer.as_ref().map(|f| f.encode());
    if let Some(footer) = encoded_footer {
      BasicToken::<Version, Local> {
        version: PhantomData,
        purpose: PhantomData,
        token: format!("{}{}.{}", self.header, payload.encode(), footer),
      }
    } else {
      BasicToken::<Version, Local> {
        version: PhantomData,
        purpose: PhantomData,
        token: format!("{}{}", self.header, payload.encode()),
      }
    }

    //produce the token with the values
    //the payload and footer are both base64 encoded
    //  BasicToken {
    //    token: payload.encode(),
    //  }
  } //split for unit and test vectors
}
impl<Version: Display + Default, Purpose: Display + Default> Default for BasicTokenBuilder<Version, Purpose> {
  fn default() -> Self {
    Self::new()
  }
}

pub struct BasicToken<Version, Purpose> {
  purpose: PhantomData<Purpose>,
  version: PhantomData<Version>,
  pub token: String,
}

impl<Version: Display + Default, Purpose: Display + Default> BasicToken<Version, Purpose> {
  pub fn builder() -> BasicTokenBuilder<Version, Purpose> {
    BasicTokenBuilder::default()
  }
}

impl<Version: Display + Default, Purpose: Display + Default> fmt::Display for BasicToken<Version, Purpose> {
  /// Formats the token for display and subsequently allows a to_string implementation
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", self.token)
  }
}

#[cfg(test)]
mod v4_test_vectors {

  use crate::common::{Footer, ImplicitAssertion, Local, Payload, Public, V4};
  use crate::keys::{HexKey, Key, Key192Bit, Key256Bit, Key512Bit, NonceKey};
  use crate::tokens::BasicTokenBuilder;
  use anyhow::Result;
  use serde_json::{json, Value};
  use std::convert::TryFrom;

  #[test]
  fn test_4_s_1() -> Result<()> {
    //then generate the V2 local key for it
    let secret_key = "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2"
        .parse::<HexKey<Key512Bit>>()?;
    let key = Key::<V4, Public>::try_from(secret_key.as_ref())?;
    let payload = json!({"data": "this is a signed message","exp": "2022-01-01T00:00:00+00:00"}).to_string();

    //create message for test vector
    //  eprintln!("\nJSON INFO: {}\n", json);
    let message = Payload::from(payload.as_str());

    //  //  //create a local v2 token
    //let token = BasicTokenBuilder::<V2, Public>::build_token(header, message, &key, None);
    let token = BasicTokenBuilder::<V4, Public>::default()
      .set_payload(message.clone())
      .build(&key);

    //  //validate the test vector
    assert_eq!(token.to_string(), "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9bg_XBBzds8lTZShVlwwKSgeKpLT3yukTw6JUz3W4h_ExsQV-P0V54zemZDcAxFaSeef1QlXEFtkqxT1ciiQEDA");

    //now let's try to decrypt it
    let decrypted_payload =
      crate::verified_tokens::BasicTokenVerified::<V4, Public>::parse(token.to_string().as_str(), None, None, &key);
    if let Ok(payload) = decrypted_payload {
      assert_eq!(payload.as_ref(), message.as_ref());
    }
    Ok(())
  }

  #[test]
  fn test_4_s_2() -> Result<()> {
    //then generate the V2 local key for it
    let secret_key = "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2"
        .parse::<HexKey<Key512Bit>>()?;
    let key = Key::<V4, Public>::try_from(secret_key.as_ref())?;
    let payload = json!({"data": "this is a signed message","exp": "2022-01-01T00:00:00+00:00"}).to_string();
    let footer = json!({"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}).to_string();

    //create message for test vector
    //  eprintln!("\nJSON INFO: {}\n", json);
    let message = Payload::from(payload.as_str());
    let footer = Footer::from(footer.as_str());

    //  //  //create a local v2 token
    //let token = BasicTokenBuilder::<V2, Public>::build_token(header, message, &key, None);
    let token = BasicTokenBuilder::<V4, Public>::default()
      .set_payload(message.clone())
      .set_footer(footer.clone())
      .build(&key);

    //  //validate the test vector
    assert_eq!(token.to_string(), "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9v3Jt8mx_TdM2ceTGoqwrh4yDFn0XsHvvV_D0DtwQxVrJEBMl0F2caAdgnpKlt4p7xBnx1HcO-SPo8FPp214HDw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9");

    //now let's try to decrypt it
    let decrypted_payload = crate::verified_tokens::BasicTokenVerified::<V4, Public>::parse(
      token.to_string().as_str(),
      Some(footer),
      None,
      &key,
    );
    if let Ok(payload) = decrypted_payload {
      assert_eq!(payload.as_ref(), message.as_ref());
    }
    Ok(())
  }

  #[test]
  fn test_4_s_3() -> Result<()> {
    //then generate the V2 local key for it
    let secret_key = "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2"
        .parse::<HexKey<Key512Bit>>()?;
    let key = Key::<V4, Public>::try_from(secret_key.as_ref())?;
    let payload = json!({"data": "this is a signed message","exp": "2022-01-01T00:00:00+00:00"}).to_string();
    let footer = json!({"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}).to_string();
    let assertion = json!({"test-vector":"4-S-3"}).to_string();

    //create message for test vector
    //  eprintln!("\nJSON INFO: {}\n", json);
    let message = Payload::from(payload.as_str());
    let footer = Footer::from(footer.as_str());
    let assertion = ImplicitAssertion::from(assertion.as_str());

    //  //  //create a local v2 token
    //let token = BasicTokenBuilder::<V2, Public>::build_token(header, message, &key, None);
    let token = BasicTokenBuilder::<V4, Public>::default()
      .set_payload(message.clone())
      .set_footer(footer.clone())
      .set_implicit_assertion(assertion)
      .build(&key);

    //  //validate the test vector
    assert_eq!(token.to_string(), "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9NPWciuD3d0o5eXJXG5pJy-DiVEoyPYWs1YSTwWHNJq6DZD3je5gf-0M4JR9ipdUSJbIovzmBECeaWmaqcaP0DQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9");

    //now let's try to decrypt it
    let decrypted_payload = crate::verified_tokens::BasicTokenVerified::<V4, Public>::parse(
      token.to_string().as_str(),
      Some(footer),
      None,
      &key,
    );
    if let Ok(payload) = decrypted_payload {
      assert_eq!(payload.as_ref(), message.as_ref());
    }
    Ok(())
  }
}

#[cfg(test)]
mod v2_test_vectors {

  use crate::common::{Footer, Local, Payload, Public, V2};
  use crate::keys::{HexKey, Key, Key192Bit, Key256Bit, Key512Bit, NonceKey};
  use crate::tokens::BasicTokenBuilder;
  use anyhow::Result;
  use core::panic;
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

    let mut token_builder = BasicTokenBuilder::<V2, Local>::default();
    token_builder.set_payload(message.clone()).set_nonce_key(nonce);
    if let Some(footer) = footer {
      token_builder.set_footer(footer);
    }
    let token = token_builder.build(&key);
    //  if let Some(footer) = &self.footer {
    //    token_builder.set_footer(footer.clone());
    //  }
    //  let basic_token = token_builder.build(key);
    //  //  //create a local v2 token
    //  let token = BasicTokenBuilder::<V2, Local>::build_token(header, message, &key, footer, &nonce);

    //validate the test vector
    assert_eq!(token.to_string(), expected_token);

    //  //now let's try to decrypt it
    //  let decrypted_payload =
    //    crate::decrypted_tokens::BasicTokenDecrypted::<V2, Local>::parse(token.to_string().as_str(), None, key);
    //  if let Ok(payload) = decrypted_payload {
    //    assert_eq!(payload.as_ref(), message.as_ref());
    //  }
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

  #[test]
  fn test_2_s_1() -> Result<()> {
    //then generate the V2 local key for it
    let secret_key = "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2"
        .parse::<HexKey<Key512Bit>>()?;
    let key = Key::<V2, Public>::try_from(secret_key.as_ref())?;
    let payload = json!({"data": "this is a signed message","exp": "2019-01-01T00:00:00+00:00"}).to_string();
    //  let footer = json!({"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}).to_string();
    //  let assertion = json!({"test-vector":"4-S-3"}).to_string();

    //create message for test vector
    //  eprintln!("\nJSON INFO: {}\n", json);
    let message = Payload::from(payload.as_str());
    //  let footer = Footer::from(footer.as_str());
    //  let assertion = ImplicitAssertion::from(assertion.as_str());

    //  //  //create a local v2 token
    //let token = BasicTokenBuilder::<V2, Public>::build_token(header, message, &key, None);
    let token = BasicTokenBuilder::<V2, Public>::default()
      .set_payload(message.clone())
      //      .set_footer(footer.clone())
      .build(&key);

    //  //validate the test vector
    assert_eq!(token.to_string(), "v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9HQr8URrGntTu7Dz9J2IF23d1M7-9lH9xiqdGyJNvzp4angPW5Esc7C5huy_M8I8_DjJK2ZXC2SUYuOFM-Q_5Cw");

    //now let's try to decrypt it
    let decrypted_payload =
      crate::verified_tokens::BasicTokenVerified::<V2, Public>::parse(token.to_string().as_str(), None, &key);
    if let Ok(payload) = decrypted_payload {
      assert_eq!(payload.as_ref(), message.as_ref());
    }
    Ok(())
  }

  #[test]
  fn test_2_s_2() -> Result<()> {
    //then generate the V2 local key for it
    let secret_key = "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2"
        .parse::<HexKey<Key512Bit>>()?;
    let key = Key::<V2, Public>::try_from(secret_key.as_ref())?;
    let payload = json!({"data": "this is a signed message","exp": "2019-01-01T00:00:00+00:00"}).to_string();
    let footer = json!({"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}).to_string();
    //  let assertion = json!({"test-vector":"4-S-3"}).to_string();

    //create message for test vector
    //  eprintln!("\nJSON INFO: {}\n", json);
    let message = Payload::from(payload.as_str());
    let footer = Footer::from(footer.as_str());
    //  let assertion = ImplicitAssertion::from(assertion.as_str());

    //  //  //create a local v2 token
    //let token = BasicTokenBuilder::<V2, Public>::build_token(header, message, &key, None);
    let token = BasicTokenBuilder::<V2, Public>::default()
      .set_payload(message.clone())
      .set_footer(footer.clone())
      .build(&key);

    //  //validate the test vector
    assert_eq!(token.to_string(), "v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9flsZsx_gYCR0N_Ec2QxJFFpvQAs7h9HtKwbVK2n1MJ3Rz-hwe8KUqjnd8FAnIJZ601tp7lGkguU63oGbomhoBw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9");

    //now let's try to decrypt it
    let decrypted_payload =
      crate::verified_tokens::BasicTokenVerified::<V2, Public>::parse(token.to_string().as_str(), None, &key);
    if let Ok(payload) = decrypted_payload {
      assert_eq!(payload.as_ref(), message.as_ref());
    }
    Ok(())
  }

  #[test]
  fn test_2_s_3() -> Result<()> {
    //then generate the V2 local key for it
    let secret_key = "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2"
        .parse::<HexKey<Key512Bit>>()?;
    let key = Key::<V2, Public>::try_from(secret_key.as_ref())?;
    let payload = json!({"data": "this is a signed message","exp": "2019-01-01T00:00:00+00:00"}).to_string();
    let footer = json!({"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}).to_string();
    //  let assertion = json!({"test-vector":"4-S-3"}).to_string();

    //create message for test vector
    //  eprintln!("\nJSON INFO: {}\n", json);
    let message = Payload::from(payload.as_str());
    let footer = Footer::from(footer.as_str());
    //  let assertion = ImplicitAssertion::from(assertion.as_str());

    //  //  //create a local v2 token
    //let token = BasicTokenBuilder::<V2, Public>::build_token(header, message, &key, None);
    let token = BasicTokenBuilder::<V2, Public>::default()
      .set_payload(message.clone())
      .set_footer(footer.clone())
      // the compiler prevents the user from adding an assertion on v2 tokens so this test passes
      //.set_implicit_assertion(ImplicitAssertion::from("discarded-anyway"))
      .build(&key);

    //  //validate the test vector
    assert_eq!(token.to_string(), "v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9flsZsx_gYCR0N_Ec2QxJFFpvQAs7h9HtKwbVK2n1MJ3Rz-hwe8KUqjnd8FAnIJZ601tp7lGkguU63oGbomhoBw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9");

    //now let's try to decrypt it
    let decrypted_payload =
      crate::verified_tokens::BasicTokenVerified::<V2, Public>::parse(token.to_string().as_str(), None, &key);
    if let Ok(payload) = decrypted_payload {
      assert_eq!(payload.as_ref(), message.as_ref());
    }
    Ok(())
  }

  #[test]
  #[should_panic]
  fn test_2_f_1() {
    //then generate the V2 local key for it
    let secret_key = "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2"
        .parse::<HexKey<Key512Bit>>().unwrap();
    let key = Key::<V2, Public>::try_from(secret_key.as_ref()).unwrap();
    let payload = json!({"data": "this is a signed message","exp": "2019-01-01T00:00:00+00:00"}).to_string();
    let footer = json!({"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}).to_string();
    //  let assertion = json!({"test-vector":"4-S-3"}).to_string();

    //create message for test vector
    //  eprintln!("\nJSON INFO: {}\n", json);
    let message = Payload::from(payload.as_str());
    let footer = Footer::from(footer.as_str());
    //  let assertion = ImplicitAssertion::from(assertion.as_str());

    //  //  //create a local v2 token
    //let token = BasicTokenBuilder::<V2, Public>::build_token(header, message, &key, None);
    let token = BasicTokenBuilder::<V2, Public>::default()
      //setting no payload
      .set_footer(footer.clone())
      // the compiler prevents the user from adding an assertion on v2 tokens so this test passes
      //.set_implicit_assertion(ImplicitAssertion::from("discarded-anyway"))
      .build(&key);

    //  //validate the test vector
    assert_eq!(token.to_string(), "v2.local.pN9Y9kTFKnCskKr7B13IoceBabSTMS0LkUg3SeAqONg6EJsq9h-CLWdWaA_rMZX4MhGsOQn5I0EsIgYeOA2NPJZU0uulsahH-k871PBq.YXJiaXRyYXJ5LXN0cmluZy10aGF0LWlzbid0LWpzb24");

    //now let's try to decrypt it
    let decrypted_payload =
      crate::verified_tokens::BasicTokenVerified::<V2, Public>::parse(token.to_string().as_str(), None, &key);
    if let Ok(payload) = decrypted_payload {
      assert_eq!(payload.as_ref(), message.as_ref());
    }
  }

  #[test]
  #[should_panic]
  fn test_2_f_2() {
    //this test vector attempts to use the wrong key (a local key) for the public token.
    //in our implementation, the compiler refuses to allow that and so this test passes since
    //there's no way to compile the incorrect code
    panic!("non-compileable test")
  }

  #[test]
  #[should_panic]
  fn test_2_f_3() {
    //this test vector attempts to use the wrong key (a local key) for the public token.
    //in our implementation, the compiler refuses to allow that and so this test passes since
    //there's no way to compile the incorrect code
    panic!("non-compileable test")
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
