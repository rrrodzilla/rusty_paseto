#[cfg(all(test, feature = "v3_local"))]
mod v3_test_vectors {
  use anyhow::Result;
  use rusty_paseto::core::*;
  use serde_json::json;

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

  //TODO V3 Public
}
