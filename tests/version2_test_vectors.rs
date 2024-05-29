#[cfg(all(test, feature = "v2"))]
mod v2_test_vectors {
  use anyhow::Result;
  use rusty_paseto::core::*;
  use serde_json::json;

  #[cfg(feature = "v2_local")]
  #[test]
  fn test_2_e_1() -> Result<()> {
    //setup
    let key = PasetoSymmetricKey::<V2, Local>::from(Key::<32>::try_from(
      "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
    )?);
    let nonce = Key::<24>::try_from("000000000000000000000000000000000000000000000000")?;
    let nonce = PasetoNonce::<V2, Local>::from(&nonce);

    let payload = json!({"data": "this is a signed message", "exp":"2019-01-01T00:00:00+00:00"}).to_string();
    let payload = payload.as_str();
    let payload = Payload::from(payload);

    //  //  //create a public V2 token
    let token = Paseto::<V2, Local>::builder()
      .set_payload(payload)
      .try_encrypt(&key, &nonce)?;

    //  //validate the test vector
    assert_eq!(token.to_string(), "v2.local.97TTOvgwIxNGvV80XKiGZg_kD3tsXM_-qB4dZGHOeN1cTkgQ4PnW8888l802W8d9AvEGnoNBY3BnqHORy8a5cC8aKpbA0En8XELw2yDk2f1sVODyfnDbi6rEGMY3pSfCbLWMM2oHJxvlEl2XbQ");

    ////now let's try to decrypt it
    let json = Paseto::<V2, Local>::try_decrypt(&token, &key, None)?;
    assert_eq!(payload, json);
    Ok(())
  }

  #[cfg(feature = "v2_local")]
  #[test]
  fn test_2_e_2() -> Result<()> {
    //setup
    let key = PasetoSymmetricKey::<V2, Local>::from(Key::<32>::try_from(
      "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
    )?);
    let nonce = Key::<24>::try_from("000000000000000000000000000000000000000000000000")?;
    let nonce = PasetoNonce::<V2, Local>::from(&nonce);

    let payload = json!({"data": "this is a secret message", "exp":"2019-01-01T00:00:00+00:00"}).to_string();
    let payload = payload.as_str();
    let payload = Payload::from(payload);

    //  //  //create a public V2 token
    let token = Paseto::<V2, Local>::builder()
      .set_payload(payload)
      .try_encrypt(&key, &nonce)?;

    //  //validate the test vector
    assert_eq!(token.to_string(), "v2.local.CH50H-HM5tzdK4kOmQ8KbIvrzJfjYUGuu5Vy9ARSFHy9owVDMYg3-8rwtJZQjN9ABHb2njzFkvpr5cOYuRyt7CRXnHt42L5yZ7siD-4l-FoNsC7J2OlvLlIwlG06mzQVunrFNb7Z3_CHM0PK5w");

    ////now let's try to decrypt it
    let json = Paseto::<V2, Local>::try_decrypt(&token, &key, None)?;
    assert_eq!(payload, json);
    Ok(())
  }

  #[cfg(feature = "v2_local")]
  #[test]
  fn test_2_e_3() -> Result<()> {
    //setup
    let key = PasetoSymmetricKey::<V2, Local>::from(Key::<32>::try_from(
      "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
    )?);
    let nonce = Key::<24>::try_from("45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b")?;
    let nonce = PasetoNonce::<V2, Local>::from(&nonce);

    let payload = json!({"data": "this is a signed message", "exp":"2019-01-01T00:00:00+00:00"}).to_string();
    let payload = payload.as_str();
    let payload = Payload::from(payload);

    //  //  //create a public V2 token
    let token = Paseto::<V2, Local>::builder()
      .set_payload(payload)
      .try_encrypt(&key, &nonce)?;

    //  //validate the test vector
    assert_eq!(token.to_string(), "v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bbjo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6Qclw3qTKIIl5-O5xRBN076fSDPo5xUCPpBA");

    ////now let's try to decrypt it
    let json = Paseto::<V2, Local>::try_decrypt(&token, &key, None)?;
    assert_eq!(payload, json);
    Ok(())
  }

  #[cfg(feature = "v2_local")]
  #[test]
  fn test_2_e_4() -> Result<()> {
    //setup
    let key = PasetoSymmetricKey::<V2, Local>::from(Key::<32>::try_from(
      "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
    )?);
    let nonce = Key::<24>::try_from("45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b")?;
    let nonce = PasetoNonce::<V2, Local>::from(&nonce);

    let payload = json!({"data": "this is a secret message", "exp":"2019-01-01T00:00:00+00:00"}).to_string();
    let payload = payload.as_str();
    let payload = Payload::from(payload);

    //let footer = Footer::from("{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}");

    //  //  //create a public V2 token
    let token = Paseto::<V2, Local>::builder()
      .set_payload(payload)
      .try_encrypt(&key, &nonce)?;

    //  //validate the test vector
    assert_eq!(token.to_string(), "v2.local.pvFdDeNtXxknVPsbBCZF6MGedVhPm40SneExdClOxa9HNR8wFv7cu1cB0B4WxDdT6oUc2toyLR6jA6sc-EUM5ll1EkeY47yYk6q8m1RCpqTIzUrIu3B6h232h62DPbIxtjGvNRAwsLK7LcV8oQ");

    ////now let's try to decrypt it
    let json = Paseto::<V2, Local>::try_decrypt(&token, &key, None)?;
    assert_eq!(payload, json);
    Ok(())
  }

  #[cfg(feature = "v2_local")]
  #[test]
  fn test_2_e_5() -> Result<()> {
    //setup
    let key = PasetoSymmetricKey::<V2, Local>::from(Key::<32>::try_from(
      "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
    )?);
    let nonce = Key::<24>::try_from("45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b")?;
    let nonce = PasetoNonce::<V2, Local>::from(&nonce);

    let payload = json!({"data": "this is a signed message", "exp":"2019-01-01T00:00:00+00:00"}).to_string();
    let payload = payload.as_str();
    let payload = Payload::from(payload);

    let footer = json!({"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}).to_string();
    let footer = footer.as_str();
    let footer = Footer::from(footer);
    //  //  //create a public V2 token
    let token = Paseto::<V2, Local>::builder()
      .set_payload(payload)
      .set_footer(footer)
      .try_encrypt(&key, &nonce)?;

    //  //validate the test vector
    assert_eq!(token.to_string(), "v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bbjo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6Qclw3qTKIIl5-zSLIrxZqOLwcFLYbVK1SrQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9");

    ////now let's try to decrypt it
    let json = Paseto::<V2, Local>::try_decrypt(&token, &key, footer)?;
    assert_eq!(payload, json);
    Ok(())
  }

  #[cfg(feature = "v2_local")]
  #[test]
  fn test_2_e_6() -> Result<()> {
    //setup
    let key = PasetoSymmetricKey::<V2, Local>::from(Key::<32>::try_from(
      "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
    )?);
    let nonce = Key::<24>::try_from("45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b")?;
    let nonce = PasetoNonce::<V2, Local>::from(&nonce);

    let payload = json!({"data": "this is a secret message", "exp":"2019-01-01T00:00:00+00:00"}).to_string();
    let payload = payload.as_str();
    let payload = Payload::from(payload);

    let footer = json!({"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}).to_string();
    let footer = footer.as_str();
    let footer = Footer::from(footer);
    //  //  //create a public V2 token
    let token = Paseto::<V2, Local>::builder()
      .set_payload(payload)
      .set_footer(footer)
      .try_encrypt(&key, &nonce)?;

    //  //validate the test vector
    assert_eq!(token.to_string(), "v2.local.pvFdDeNtXxknVPsbBCZF6MGedVhPm40SneExdClOxa9HNR8wFv7cu1cB0B4WxDdT6oUc2toyLR6jA6sc-EUM5ll1EkeY47yYk6q8m1RCpqTIzUrIu3B6h232h62DnMXKdHn_Smp6L_NfaEnZ-A.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9");

    ////now let's try to decrypt it
    let json = Paseto::<V2, Local>::try_decrypt(&token, &key, footer)?;
    assert_eq!(payload, json);
    Ok(())
  }

  #[cfg(feature = "v2_local")]
  #[test]
  fn test_2_e_7() -> Result<()> {
    //setup
    let key = PasetoSymmetricKey::<V2, Local>::from(Key::<32>::try_from(
      "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
    )?);
    let nonce = Key::<24>::try_from("45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b")?;
    let nonce = PasetoNonce::<V2, Local>::from(&nonce);

    let payload = json!({"data": "this is a signed message", "exp":"2019-01-01T00:00:00+00:00"}).to_string();
    let payload = payload.as_str();
    let payload = Payload::from(payload);

    let footer = json!({"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}).to_string();
    let footer = footer.as_str();
    let footer = Footer::from(footer);

    //  //  //create a public V2 token
    let token = Paseto::<V2, Local>::builder()
      .set_payload(payload)
      .set_footer(footer)
      .try_encrypt(&key, &nonce)?;

    //  //validate the test vector
    assert_eq!(token.to_string(), "v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bbjo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6Qclw3qTKIIl5-zSLIrxZqOLwcFLYbVK1SrQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9");

    ////now let's try to decrypt it
    let json = Paseto::<V2, Local>::try_decrypt(&token, &key, footer)?;
    assert_eq!(payload, json);
    Ok(())
  }

  #[cfg(feature = "v2_local")]
  #[test]
  fn test_2_e_8() -> Result<()> {
    //setup
    let key = PasetoSymmetricKey::<V2, Local>::from(Key::<32>::try_from(
      "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
    )?);
    let nonce = Key::<24>::try_from("45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b")?;
    let nonce = PasetoNonce::<V2, Local>::from(&nonce);

    let payload = json!({"data": "this is a secret message", "exp":"2019-01-01T00:00:00+00:00"}).to_string();
    let payload = payload.as_str();
    let payload = Payload::from(payload);

    let footer = json!({"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}).to_string();
    let footer = footer.as_str();
    let footer = Footer::from(footer);

    //  //  //create a public V2 token
    let token = Paseto::<V2, Local>::builder()
      .set_payload(payload)
      .set_footer(footer)
      .try_encrypt(&key, &nonce)?;

    //  //validate the test vector
    assert_eq!(token.to_string(), "v2.local.pvFdDeNtXxknVPsbBCZF6MGedVhPm40SneExdClOxa9HNR8wFv7cu1cB0B4WxDdT6oUc2toyLR6jA6sc-EUM5ll1EkeY47yYk6q8m1RCpqTIzUrIu3B6h232h62DnMXKdHn_Smp6L_NfaEnZ-A.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9");

    ////now let's try to decrypt it
    let json = Paseto::<V2, Local>::try_decrypt(&token, &key, footer)?;
    assert_eq!(payload, json);
    Ok(())
  }

  #[cfg(feature = "v2_local")]
  #[test]
  fn test_2_e_9() -> Result<()> {
    //setup
    let key = PasetoSymmetricKey::<V2, Local>::from(Key::<32>::try_from(
      "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
    )?);
    let nonce = Key::<24>::try_from("45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b")?;
    let nonce = PasetoNonce::<V2, Local>::from(&nonce);

    let payload = json!({"data": "this is a secret message", "exp":"2019-01-01T00:00:00+00:00"}).to_string();
    let payload = payload.as_str();
    let payload = Payload::from(payload);

    let footer = Footer::from("arbitrary-string-that-isn't-json");

    //  //  //create a public V2 token
    let token = Paseto::<V2, Local>::builder()
      .set_payload(payload)
      .set_footer(footer)
      .try_encrypt(&key, &nonce)?;

    //  //validate the test vector
    assert_eq!(token.to_string(), "v2.local.pvFdDeNtXxknVPsbBCZF6MGedVhPm40SneExdClOxa9HNR8wFv7cu1cB0B4WxDdT6oUc2toyLR6jA6sc-EUM5ll1EkeY47yYk6q8m1RCpqTIzUrIu3B6h232h62DoOJbyKBGPZG50XDZ6mbPtw.YXJiaXRyYXJ5LXN0cmluZy10aGF0LWlzbid0LWpzb24");

    ////now let's try to decrypt it
    let json = Paseto::<V2, Local>::try_decrypt(&token, &key, footer)?;
    assert_eq!(payload, json);
    Ok(())
  }

  #[cfg(feature = "v2_public")]
  #[test]
  fn test_2_s_1() -> Result<()> {
    let private_key = Key::<64>::try_from("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")?;
    let private_key = PasetoAsymmetricPrivateKey::<V2, Public>::from(&private_key);

    let public_key = Key::<32>::try_from("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")?;
    let public_key = PasetoAsymmetricPublicKey::<V2, Public>::from(&public_key);

    let payload = json!({"data": "this is a signed message", "exp":"2019-01-01T00:00:00+00:00"}).to_string();
    let payload = payload.as_str();
    let payload = Payload::from(payload);

    //  //  //create a public V2 token
    let token = Paseto::<V2, Public>::builder()
      .set_payload(payload)
      .try_sign(&private_key)?;

    //  //validate the test vector
    assert_eq!(token.to_string(), "v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9HQr8URrGntTu7Dz9J2IF23d1M7-9lH9xiqdGyJNvzp4angPW5Esc7C5huy_M8I8_DjJK2ZXC2SUYuOFM-Q_5Cw");

    ////now let's try to decrypt it
    let json = Paseto::<V2, Public>::try_verify(&token, &public_key, None)?;
    assert_eq!(payload, json);
    Ok(())
  }

  #[cfg(feature = "v2_public")]
  #[test]
  fn test_2_s_2() -> Result<()> {
    //setup
    let private_key = Key::<64>::try_from("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")?;
    let private_key = PasetoAsymmetricPrivateKey::<V2, Public>::from(&private_key);

    let public_key = Key::<32>::try_from("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")?;
    let public_key = PasetoAsymmetricPublicKey::<V2, Public>::from(&public_key);

    let payload = json!({"data": "this is a signed message","exp": "2019-01-01T00:00:00+00:00"}).to_string();
    let footer = json!({"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}).to_string();

    //create message for test vector
    //  eprintln!("\nJSON INFO: {}\n", json);
    let message = Payload::from(payload.as_str());
    let footer = Footer::from(footer.as_str());

    //  //  //create a local v2 token
    //let token = Paseto::<V2, Public>::build_token(header, message, &key, None);
    let token = Paseto::<V2, Public>::default()
      .set_payload(message.clone())
      .set_footer(footer.clone())
      .try_sign(&private_key)?;

    //  //validate the test vector
    assert_eq!(token, "v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9flsZsx_gYCR0N_Ec2QxJFFpvQAs7h9HtKwbVK2n1MJ3Rz-hwe8KUqjnd8FAnIJZ601tp7lGkguU63oGbomhoBw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9");

    //now let's try to decrypt it
    let json = Paseto::<V2, Public>::try_verify(&token, &public_key, footer)?;
    assert_eq!(payload, json);
    Ok(())
  }

  #[cfg(feature = "v2_public")]
  #[test]
  fn test_2_s_3() -> Result<()> {
    //setup
    let private_key = Key::<64>::try_from("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")?;
    let private_key = PasetoAsymmetricPrivateKey::<V2, Public>::from(&private_key);

    let public_key = Key::<32>::try_from("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")?;
    let public_key = PasetoAsymmetricPublicKey::<V2, Public>::from(&public_key);

    let payload = json!({"data": "this is a signed message","exp": "2019-01-01T00:00:00+00:00"}).to_string();
    let footer = json!({"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}).to_string();

    //create message for test vector
    //  eprintln!("\nJSON INFO: {}\n", json);
    let message = Payload::from(payload.as_str());
    let footer = Footer::from(footer.as_str());

    //  //  //create a local v2 token
    //let token = Paseto::<V2, Public>::build_token(header, message, &key, None);
    let token = Paseto::<V2, Public>::default()
      .set_payload(message.clone())
      .set_footer(footer.clone())
      .try_sign(&private_key)?;

    //  //validate the test vector
    assert_eq!(token.to_string(), "v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9flsZsx_gYCR0N_Ec2QxJFFpvQAs7h9HtKwbVK2n1MJ3Rz-hwe8KUqjnd8FAnIJZ601tp7lGkguU63oGbomhoBw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9");

    //now let's try to decrypt it
    let json = Paseto::<V2, Public>::try_verify(&token, &public_key, footer)?;
    assert_eq!(payload, json);
    Ok(())
  }

  #[cfg(feature = "public")]
  #[test]
  #[should_panic]
  fn test_2_f_1() {
    //this test is prevented at compile time and passes by defacto
    panic!("non-compileable test")
  }

  #[cfg(feature = "public")]
  #[test]
  #[should_panic]
  fn test_2_f_2() {
    //this test is prevented at compile time and passes by defacto
    panic!("non-compileable test")
  }

  #[cfg(feature = "public")]
  #[test]
  #[should_panic]
  fn test_2_f_3() {
    //this test is prevented at compile time and passes by defacto
    panic!("non-compileable test")
  }
}
