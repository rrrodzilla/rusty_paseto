#[cfg(all(test, feature = "v3"))]
mod v3_test_vectors {
  use anyhow::Result;
  use rusty_paseto::core::*;
  use serde_json::json;

  #[cfg(all(test, feature = "v3_local"))]
  #[test]
  fn test_3_e_1() -> Result<()> {
    //setup
    let key = PasetoSymmetricKey::<V3, Local>::from(Key::<32>::try_from(
      "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
    )?);
    let nonce = Key::<32>::try_from("0000000000000000000000000000000000000000000000000000000000000000")?;
    let nonce = PasetoNonce::<V3, Local>::from(&nonce);

    let payload = json!({"data": "this is a secret message", "exp":"2022-01-01T00:00:00+00:00"}).to_string();
    let payload = payload.as_str();
    let payload = Payload::from(payload);

    //  //  //create a public V3 token
    let token = Paseto::<V3, Local>::builder()
      .set_payload(payload)
      .try_encrypt(&key, &nonce)?;

    //  //validate the test vector
    assert_eq!(token.to_string(), "v3.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADbfcIURX_0pVZVU1mAESUzrKZAsRm2EsD6yBoZYn6cpVZNzSJOhSDN-sRaWjfLU-yn9OJH1J_B8GKtOQ9gSQlb8yk9Iza7teRdkiR89ZFyvPPsVjjFiepFUVcMa-LP18zV77f_crJrVXWa5PDNRkCSeHfBBeg");

    ////now let's try to decrypt it
    let json = Paseto::<V3, Local>::try_decrypt(&token, &key, None, None)?;
    assert_eq!(payload, json);
    Ok(())
  }

  #[cfg(all(test, feature = "v3_local"))]
  #[test]
  fn test_3_e_2() -> Result<()> {
    let key = PasetoSymmetricKey::<V3, Local>::from(Key::<32>::try_from(
      "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
    )?);
    let nonce = Key::<32>::try_from("0000000000000000000000000000000000000000000000000000000000000000")?;
    let nonce = PasetoNonce::<V3, Local>::from(&nonce);

    let payload = json!({"data": "this is a hidden message", "exp":"2022-01-01T00:00:00+00:00"}).to_string();
    let payload = payload.as_str();
    let payload = Payload::from(payload);

    //  //  //create a public V3 token
    let token = Paseto::<V3, Local>::builder()
      .set_payload(payload)
      .try_encrypt(&key, &nonce)?;

    //  //validate the test vector
    assert_eq!(token.to_string(), "v3.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADbfcIURX_0pVZVU1mAESUzrKZAqhWxBMDgyBoZYn6cpVZNzSJOhSDN-sRaWjfLU-yn9OJH1J_B8GKtOQ9gSQlb8yk9IzZfaZpReVpHlDSwfuygx1riVXYVs-UjcrG_apl9oz3jCVmmJbRuKn5ZfD8mHz2db0A");

    ////now let's try to decrypt it
    let json = Paseto::<V3, Local>::try_decrypt(&token, &key, None, None)?;
    assert_eq!(payload, json);
    Ok(())
  }

  #[cfg(all(test, feature = "v3_local"))]
  #[test]
  fn test_3_e_3() -> Result<()> {
    //setup

    let key = PasetoSymmetricKey::<V3, Local>::from(Key::<32>::try_from(
      "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
    )?);
    let nonce = Key::<32>::try_from("26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2")?;
    let nonce = PasetoNonce::<V3, Local>::from(&nonce);

    let payload = json!({"data": "this is a secret message", "exp":"2022-01-01T00:00:00+00:00"}).to_string();
    let payload = payload.as_str();
    let payload = Payload::from(payload);

    //  //  //create a public V3 token
    let token = Paseto::<V3, Local>::builder()
      .set_payload(payload)
      .try_encrypt(&key, &nonce)?;

    //  //validate the test vector
    assert_eq!(token.to_string(), "v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0ROIIykcrGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJlxnt5xyhQjFJomwnt7WW_7r2VT0G704ifult011-TgLCyQ2X8imQhniG_hAQ4BydM");

    ////now let's try to decrypt it
    let json = Paseto::<V3, Local>::try_decrypt(&token, &key, None, None)?;
    assert_eq!(payload, json);
    Ok(())
  }

  #[cfg(all(test, feature = "v3_local"))]
  #[test]
  fn test_3_e_4() -> Result<()> {
    //setup

    let key = PasetoSymmetricKey::<V3, Local>::from(Key::<32>::try_from(
      "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
    )?);
    let nonce = Key::<32>::try_from("26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2")?;
    let nonce = PasetoNonce::<V3, Local>::from(&nonce);

    let payload = json!({"data": "this is a hidden message", "exp":"2022-01-01T00:00:00+00:00"}).to_string();
    let payload = payload.as_str();
    let payload = Payload::from(payload);

    //  //  //create a public V3 token
    let token = Paseto::<V3, Local>::builder()
      .set_payload(payload)
      .try_encrypt(&key, &nonce)?;

    //  //validate the test vector
    assert_eq!(token.to_string(), "v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0X-4P3EcxGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJlBZa_gOpVj4gv0M9lV6Pwjp8JS_MmaZaTA1LLTULXybOBZ2S4xMbYqYmDRhh3IgEk");

    ////now let's try to decrypt it
    let json = Paseto::<V3, Local>::try_decrypt(&token, &key, None, None)?;
    assert_eq!(payload, json);
    Ok(())
  }

  #[cfg(all(test, feature = "v3_local"))]
  #[test]
  fn test_3_e_5() -> Result<()> {
    //setup

    let key = PasetoSymmetricKey::<V3, Local>::from(Key::<32>::try_from(
      "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
    )?);
    let nonce = Key::<32>::try_from("26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2")?;
    let nonce = PasetoNonce::<V3, Local>::from(&nonce);

    let payload = json!({"data": "this is a secret message", "exp":"2022-01-01T00:00:00+00:00"}).to_string();
    let payload = payload.as_str();
    let payload = Payload::from(payload);

    let footer = json!({"kid":"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo"}).to_string();
    let footer = footer.as_str();
    let footer = Footer::from(footer);
    //  //  //create a public V3 token
    let token = Paseto::<V3, Local>::builder()
      .set_payload(payload)
      .set_footer(footer)
      .try_encrypt(&key, &nonce)?;

    //  //validate the test vector
    assert_eq!(token.to_string(), "v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0ROIIykcrGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJlkYSIbXOgVuIQL65UMdW9WcjOpmqvjqD40NNzed-XPqn1T3w-bJvitYpUJL_rmihc.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9");

    ////now let's try to decrypt it
    let json = Paseto::<V3, Local>::try_decrypt(&token, &key, footer, None)?;
    assert_eq!(payload, json);
    Ok(())
  }

  #[cfg(all(test, feature = "v3_local"))]
  #[test]
  fn test_3_e_6() -> Result<()> {
    //setup

    let key = PasetoSymmetricKey::<V3, Local>::from(Key::<32>::try_from(
      "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
    )?);
    let nonce = Key::<32>::try_from("26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2")?;
    let nonce = PasetoNonce::<V3, Local>::from(&nonce);

    let payload = json!({"data": "this is a hidden message", "exp":"2022-01-01T00:00:00+00:00"}).to_string();
    let payload = payload.as_str();
    let payload = Payload::from(payload);

    let footer = json!({"kid":"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo"}).to_string();
    let footer = footer.as_str();
    let footer = Footer::from(footer);
    //  //  //create a public V3 token
    let token = Paseto::<V3, Local>::builder()
      .set_payload(payload)
      .set_footer(footer)
      .try_encrypt(&key, &nonce)?;

    //  //validate the test vector
    assert_eq!(token.to_string(), "v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0X-4P3EcxGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJmSeEMphEWHiwtDKJftg41O1F8Hat-8kQ82ZIAMFqkx9q5VkWlxZke9ZzMBbb3Znfo.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9");

    ////now let's try to decrypt it
    let json = Paseto::<V3, Local>::try_decrypt(&token, &key, footer, None)?;
    assert_eq!(payload, json);
    Ok(())
  }

  #[cfg(all(test, feature = "v3_local"))]
  #[test]
  fn test_3_e_7() -> Result<()> {
    //setup

    let key = PasetoSymmetricKey::<V3, Local>::from(Key::<32>::try_from(
      "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
    )?);
    let nonce = Key::<32>::try_from("26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2")?;
    let nonce = PasetoNonce::<V3, Local>::from(&nonce);

    let payload = json!({"data": "this is a secret message", "exp":"2022-01-01T00:00:00+00:00"}).to_string();
    let payload = payload.as_str();
    let payload = Payload::from(payload);

    let footer = json!({"kid":"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo"}).to_string();
    let footer = footer.as_str();
    let footer = Footer::from(footer);

    let implicit_assertion = json!({"test-vector":"3-E-7"}).to_string();
    let implicit_assertion = implicit_assertion.as_str();
    let implicit_assertion = ImplicitAssertion::from(implicit_assertion);
    //  //  //create a public V3 token
    let token = Paseto::<V3, Local>::builder()
      .set_payload(payload)
      .set_footer(footer)
      .set_implicit_assertion(implicit_assertion)
      .try_encrypt(&key, &nonce)?;

    //  //validate the test vector
    assert_eq!(token.to_string(), "v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0ROIIykcrGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJkzWACWAIoVa0bz7EWSBoTEnS8MvGBYHHo6t6mJunPrFR9JKXFCc0obwz5N-pxFLOc.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9");

    ////now let's try to decrypt it
    let json = Paseto::<V3, Local>::try_decrypt(&token, &key, footer, implicit_assertion)?;
    assert_eq!(payload, json);
    Ok(())
  }

  #[cfg(all(test, feature = "v3_local"))]
  #[test]
  fn test_3_e_8() -> Result<()> {
    //setup

    let key = PasetoSymmetricKey::<V3, Local>::from(Key::<32>::try_from(
      "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
    )?);
    let nonce = Key::<32>::try_from("26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2")?;
    let nonce = PasetoNonce::<V3, Local>::from(&nonce);

    let payload = json!({"data": "this is a hidden message", "exp":"2022-01-01T00:00:00+00:00"}).to_string();
    let payload = payload.as_str();
    let payload = Payload::from(payload);

    let footer = json!({"kid":"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo"}).to_string();
    let footer = footer.as_str();
    let footer = Footer::from(footer);

    let implicit_assertion = json!({"test-vector":"3-E-8"}).to_string();
    let implicit_assertion = implicit_assertion.as_str();
    let implicit_assertion = ImplicitAssertion::from(implicit_assertion);
    //  //  //create a public V3 token
    let token = Paseto::<V3, Local>::builder()
      .set_payload(payload)
      .set_footer(footer)
      .set_implicit_assertion(implicit_assertion)
      .try_encrypt(&key, &nonce)?;

    //  //validate the test vector
    assert_eq!(token.to_string(), "v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0X-4P3EcxGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJmZHSSKYR6AnPYJV6gpHtx6dLakIG_AOPhu8vKexNyrv5_1qoom6_NaPGecoiz6fR8.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9");

    ////now let's try to decrypt it
    let json = Paseto::<V3, Local>::try_decrypt(&token, &key, footer, implicit_assertion)?;
    assert_eq!(payload, json);
    Ok(())
  }

  #[cfg(all(test, feature = "v3_local"))]
  #[test]
  fn test_3_e_9() -> Result<()> {
    //setup

    let key = PasetoSymmetricKey::<V3, Local>::from(Key::<32>::try_from(
      "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
    )?);
    let nonce = Key::<32>::try_from("26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2")?;
    let nonce = PasetoNonce::<V3, Local>::from(&nonce);

    let payload = json!({"data": "this is a hidden message", "exp":"2022-01-01T00:00:00+00:00"}).to_string();
    let payload = payload.as_str();
    let payload = Payload::from(payload);

    let footer = Footer::from("arbitrary-string-that-isn't-json");

    let implicit_assertion = json!({"test-vector":"3-E-9"}).to_string();
    let implicit_assertion = implicit_assertion.as_str();
    let implicit_assertion = ImplicitAssertion::from(implicit_assertion);
    //  //  //create a public V3 token
    let token = Paseto::<V3, Local>::builder()
      .set_payload(payload)
      .set_footer(footer)
      .set_implicit_assertion(implicit_assertion)
      .try_encrypt(&key, &nonce)?;

    //  //validate the test vector
    assert_eq!(token.to_string(), "v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0X-4P3EcxGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJlk1nli0_wijTH_vCuRwckEDc82QWK8-lG2fT9wQF271sgbVRVPjm0LwMQZkvvamqU.YXJiaXRyYXJ5LXN0cmluZy10aGF0LWlzbid0LWpzb24");

    ////now let's try to decrypt it
    let json = Paseto::<V3, Local>::try_decrypt(&token, &key, footer, implicit_assertion)?;
    assert_eq!(payload, json);
    Ok(())
  }

  //V3 Public
  #[cfg(feature = "v3_public")]
  #[test]
  fn test_3_s_1() -> Result<()> {
    //setup
    let private_key = Key::<48>::try_from(
      "20347609607477aca8fbfbc5e6218455f3199669792ef8b466faa87bdc67798144c848dd03661eed5ac62461340cea96",
    )?;
    let private_key = PasetoAsymmetricPrivateKey::<V3, Public>::from(&private_key);

    let public_key = Key::<49>::try_from(
      "02fbcb7c69ee1c60579be7a334134878d9c5c5bf35d552dab63c0140397ed14cef637d7720925c44699ea30e72874c72fb",
    )?;
    let public_key = PasetoAsymmetricPublicKey::<V3, Public>::try_from(&public_key)?;

    let payload = json!({"data":"this is a signed message","exp":"2022-01-01T00:00:00+00:00"}).to_string();

    //create message for test vector
    let message = Payload::from(payload.as_str());
    //  let footer = Footer::default();
    //  let assertion = ImplicitAssertion::default();

    //  //  //create a local v2 token
    let token = Paseto::<V3, Public>::default()
      .set_payload(message.clone())
      .try_sign(&private_key)?;

    //  //validate the test vector
    assert_eq!(token.to_string(), "v3.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9qqEwwrKHKi5lJ7b9MBKc0G4MGZy0ptUiMv3lAUAaz-JY_zjoqBSIxMxhfAoeNYiSyvfUErj76KOPWm1OeNnBPkTSespeSXDGaDfxeIrl3bRrPEIy7tLwLAIsRzsXkfph");

    //now let's try to decrypt it
    let json = Paseto::<V3, Public>::try_verify(&token, &public_key, None, None)?;
    assert_eq!(payload, json);
    Ok(())
  }

  #[cfg(feature = "v3_public")]
  #[test]
  fn test_3_s_2() -> Result<()> {
    //setup
    let private_key = Key::<48>::try_from(
      "20347609607477aca8fbfbc5e6218455f3199669792ef8b466faa87bdc67798144c848dd03661eed5ac62461340cea96",
    )?;
    let private_key = PasetoAsymmetricPrivateKey::<V3, Public>::from(&private_key);

    let public_key = Key::<49>::try_from(
      "02fbcb7c69ee1c60579be7a334134878d9c5c5bf35d552dab63c0140397ed14cef637d7720925c44699ea30e72874c72fb",
    )?;
    let public_key = PasetoAsymmetricPublicKey::<V3, Public>::try_from(&public_key)?;

    let payload = json!({"data":"this is a signed message","exp":"2022-01-01T00:00:00+00:00"}).to_string();

    //create message for test vector
    let message = Payload::from(payload.as_str());
    let footer = Footer::from("{\"kid\":\"dYkISylxQeecEcHELfzF88UZrwbLolNiCdpzUHGw9Uqn\"}");
    //  let assertion = ImplicitAssertion::default();

    //  //  //create a local v2 token
    let token = Paseto::<V3, Public>::default()
      .set_payload(message.clone())
      .set_footer(footer.clone())
      .try_sign(&private_key)?;

    //  //validate the test vector
    assert_eq!(token.to_string(), "v3.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9ZWrbGZ6L0MDK72skosUaS0Dz7wJ_2bMcM6tOxFuCasO9GhwHrvvchqgXQNLQQyWzGC2wkr-VKII71AvkLpC8tJOrzJV1cap9NRwoFzbcXjzMZyxQ0wkshxZxx8ImmNWP.eyJraWQiOiJkWWtJU3lseFFlZWNFY0hFTGZ6Rjg4VVpyd2JMb2xOaUNkcHpVSEd3OVVxbiJ9");

    //now let's try to decrypt it
    let json = Paseto::<V3, Public>::try_verify(&token, &public_key, footer, None)?;
    assert_eq!(payload, json);
    Ok(())
  }

  #[cfg(feature = "v3_public")]
  #[test]
  fn test_3_s_3() -> Result<()> {
    //setup
    let private_key = Key::<48>::try_from(
      "20347609607477aca8fbfbc5e6218455f3199669792ef8b466faa87bdc67798144c848dd03661eed5ac62461340cea96",
    )?;
    let private_key = PasetoAsymmetricPrivateKey::<V3, Public>::from(&private_key);

    let public_key = Key::<49>::try_from(
      "02fbcb7c69ee1c60579be7a334134878d9c5c5bf35d552dab63c0140397ed14cef637d7720925c44699ea30e72874c72fb",
    )?;
    let public_key = PasetoAsymmetricPublicKey::<V3, Public>::try_from(&public_key)?;

    let payload = json!({"data":"this is a signed message","exp":"2022-01-01T00:00:00+00:00"}).to_string();

    //create message for test vector
    let message = Payload::from(payload.as_str());
    let footer = Footer::from("{\"kid\":\"dYkISylxQeecEcHELfzF88UZrwbLolNiCdpzUHGw9Uqn\"}");
    let assertion = ImplicitAssertion::from("{\"test-vector\":\"3-S-3\"}");

    //  //  //create a local v2 token
    let token = Paseto::<V3, Public>::default()
      .set_payload(message.clone())
      .set_footer(footer.clone())
      .set_implicit_assertion(assertion.clone())
      .try_sign(&private_key)?;

    //  //validate the test vector
    assert_eq!(token.to_string(), "v3.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ94SjWIbjmS7715GjLSnHnpJrC9Z-cnwK45dmvnVvCRQDCCKAXaKEopTajX0DKYx1Xqr6gcTdfqscLCAbiB4eOW9jlt-oNqdG8TjsYEi6aloBfTzF1DXff_45tFlnBukEX.eyJraWQiOiJkWWtJU3lseFFlZWNFY0hFTGZ6Rjg4VVpyd2JMb2xOaUNkcHpVSEd3OVVxbiJ9");

    //now let's try to decrypt it
    let json = Paseto::<V3, Public>::try_verify(&token, &public_key, footer, assertion)?;
    assert_eq!(payload, json);
    Ok(())
  }

  #[cfg(feature = "v3_public")]
  #[test]
  fn test_3_f_1() -> Result<()> {
    //setup
    let private_key = Key::<48>::try_from(
      "20347609607477aca8fbfbc5e6218455f3199669792ef8b466faa87bdc67798144c848dd03661eed5ac62461340cea96",
    )?;
    let private_key = PasetoAsymmetricPrivateKey::<V3, Public>::from(&private_key);

    //create message for test vector
    let footer = Footer::from("arbitrary-string-that-isn't-json");
    let assertion = ImplicitAssertion::from("\"test-vector\":\"3-F-1\"}");

    //  //  //create a v3 public signed token
    let token = Paseto::<V3, Public>::default()
      //.set_payload(message.clone())
      .set_footer(footer.clone())
      .set_implicit_assertion(assertion.clone())
      .try_sign(&private_key)?;

    //  //validate the test vector
    assert_ne!(token.to_string(), "v3.local.tthw-G1Da_BzYeMu_GEDp-IyQ7jzUCQHxCHRdDY6hQjKg6CuxECXfjOzlmNgNJ-WELjN61gMDnldG9OLkr3wpxuqdZksCzH9Ul16t3pXCLGPoHQ9_l51NOqVmMLbFVZOPhsmdhef9RxJwmqvzQ_Mo_JkYRlrNA.YXJiaXRyYXJ5LXN0cmluZy10aGF0LWlzbid0LWpzb24");

    Ok(())
  }

  #[cfg(feature = "v3_local")]
  #[test]
  fn test_3_f_2() -> Result<()> {
    //setup

    let key = PasetoSymmetricKey::<V3, Local>::from(Key::<32>::try_from(
      "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
    )?);
    let nonce = Key::<32>::try_from("df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8")?;
    let nonce = PasetoNonce::<V3, Local>::from(&nonce);

    //  let payload = json!({"data": "this is a hidden message", "exp":"2022-01-01T00:00:00+00:00"}).to_string();
    //  let payload = payload.as_str();
    //  let payload = Payload::from(payload);

    let footer = Footer::from("{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}");

    let implicit_assertion = ImplicitAssertion::from("{\"test-vector\":\"3-F-2\"}");
    //  //  //create a public V3 token
    let token = Paseto::<V3, Local>::builder()
      //      .set_payload(payload)
      .set_footer(footer)
      .set_implicit_assertion(implicit_assertion)
      .try_encrypt(&key, &nonce)?;

    let test_token =  "v3.public.eyJpbnZhbGlkIjoidGhpcyBzaG91bGQgbmV2ZXIgZGVjb2RlIn1hbzIBD_EU54TYDTvsN9bbCU1QPo7FDeIhijkkcB9BrVH73XyM3Wwvu1pJaGCOEc0R5DVe9hb1ka1cYBd0goqVHt0NQ2NhPtILz4W36eCCqyU4uV6xDMeLI8ni6r3GnaY.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";
    //  //validate the test vector
    assert_ne!(token.to_string(), test_token);

    ////now let's try to decrypt it
    let verify_attempt = Paseto::<V3, Local>::try_decrypt(&test_token, &key, footer, implicit_assertion);
    assert!(verify_attempt.is_err());
    Ok(())
  }

  #[cfg(feature = "v3_local")]
  #[test]
  fn test_3_f_3() -> Result<()> {
    //setup

    let key = PasetoSymmetricKey::<V3, Local>::from(Key::<32>::try_from(
      "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
    )?);
    let nonce = Key::<32>::try_from("26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2")?;
    let nonce = PasetoNonce::<V3, Local>::from(&nonce);

    //  let payload = json!({"data": "this is a hidden message", "exp":"2022-01-01T00:00:00+00:00"}).to_string();
    //  let payload = payload.as_str();
    //  let payload = Payload::from(payload);

    let footer = Footer::from("arbitrary-string-that-isn't-json");

    let implicit_assertion = ImplicitAssertion::from("{\"test-vector\":\"3-F-3\"}");
    //  //  //create a public V3 token
    let token = Paseto::<V3, Local>::builder()
      //      .set_payload(payload)
      .set_footer(footer)
      .set_implicit_assertion(implicit_assertion)
      .try_encrypt(&key, &nonce)?;

    let test_token =  "v4.local.1JgN1UG8TFAYS49qsx8rxlwh-9E4ONUm3slJXYi5EibmzxpF0Q-du6gakjuyKCBX8TvnSLOKqCPu8Yh3WSa5yJWigPy33z9XZTJF2HQ9wlLDPtVn_Mu1pPxkTU50ZaBKblJBufRA.YXJiaXRyYXJ5LXN0cmluZy10aGF0LWlzbid0LWpzb24";
    //  //validate the test vector
    assert_ne!(token.to_string(), test_token);

    ////now let's try to decrypt it
    let verify_attempt = Paseto::<V3, Local>::try_decrypt(&test_token, &key, footer, implicit_assertion);
    assert!(verify_attempt.is_err());
    Ok(())
  }

  #[cfg(feature = "v3_local")]
  #[test]
  fn test_3_f_4() -> Result<()> {
    //setup

    let key = PasetoSymmetricKey::<V3, Local>::from(Key::<32>::try_from(
      "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
    )?);
    let nonce = Key::<32>::try_from("0000000000000000000000000000000000000000000000000000000000000000")?;
    let nonce = PasetoNonce::<V3, Local>::from(&nonce);

    //  let payload = json!({"data": "this is a hidden message", "exp":"2022-01-01T00:00:00+00:00"}).to_string();
    //  let payload = payload.as_str();
    //  let payload = Payload::from(payload);

    let footer = Footer::default();

    let implicit_assertion = ImplicitAssertion::default();
    //  //  //create a public V3 token
    let token = Paseto::<V3, Local>::builder()
      //      .set_payload(payload)
      .set_footer(footer)
      .set_implicit_assertion(implicit_assertion)
      .try_encrypt(&key, &nonce)?;

    let test_token =  "v3.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADbfcIURX_0pVZVU1mAESUzrKZAsRm2EsD6yBoZYn6cpVZNzSJOhSDN-sRaWjfLU-yn9OJH1J_B8GKtOQ9gSQlb8yk9Iza7teRdkiR89ZFyvPPsVjjFiepFUVcMa-LP18zV77f_crJrVXWa5PDNRkCSeHfBBeh";
    //  //validate the test vector
    assert_ne!(token.to_string(), test_token);

    ////now let's try to decrypt it
    let verify_attempt = Paseto::<V3, Local>::try_decrypt(&test_token, &key, footer, implicit_assertion);
    assert!(verify_attempt.is_err());
    Ok(())
  }

  #[cfg(feature = "v3_local")]
  #[test]
  fn test_3_f_5() -> Result<()> {
    //setup

    let key = PasetoSymmetricKey::<V3, Local>::from(Key::<32>::try_from(
      "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
    )?);
    let nonce = Key::<32>::try_from("26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2")?;
    let nonce = PasetoNonce::<V3, Local>::from(&nonce);

    //  let payload = json!({"data": "this is a hidden message", "exp":"2022-01-01T00:00:00+00:00"}).to_string();
    //  let payload = payload.as_str();
    //  let payload = Payload::from(payload);

    let footer = Footer::from("{\"kid\":\"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo\"}");

    let implicit_assertion = ImplicitAssertion::default();
    //  //  //create a public V3 token
    let token = Paseto::<V3, Local>::builder()
      //      .set_payload(payload)
      .set_footer(footer)
      .set_implicit_assertion(implicit_assertion)
      .try_encrypt(&key, &nonce)?;

    let test_token =  "v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0ROIIykcrGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJlkYSIbXOgVuIQL65UMdW9WcjOpmqvjqD40NNzed-XPqn1T3w-bJvitYpUJL_rmihc=.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9";
    //  //validate the test vector
    assert_ne!(token.to_string(), test_token);

    ////now let's try to decrypt it
    let verify_attempt = Paseto::<V3, Local>::try_decrypt(&test_token, &key, footer, implicit_assertion);
    assert!(verify_attempt.is_err());
    // assert_ne!(verify_attempt, "");
    Ok(())
  }
}
