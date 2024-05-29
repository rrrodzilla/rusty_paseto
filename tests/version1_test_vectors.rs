#[cfg(all(test, feature = "v1"))]
mod v1_test_vectors {
  use anyhow::Result;
  use rusty_paseto::core::*;
  use serde_json::json;

  #[cfg(feature = "v1_local")]
  #[test]
  fn test_1_e_1() -> Result<()> {
    //setup
    //let key = Key::<32>::try_from("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")?;
    let key = PasetoSymmetricKey::<V1, Local>::from(Key::<32>::try_from(
      "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
    )?);
    let nonce = Key::<32>::try_from("0000000000000000000000000000000000000000000000000000000000000000")?;
    let nonce = PasetoNonce::<V1, Local>::from(&nonce);

    let payload = json!({"data": "this is a signed message", "exp":"2019-01-01T00:00:00+00:00"}).to_string();
    let payload = payload.as_str();
    let payload = Payload::from(payload);

    //  //  //create a public V1 token
    let token = Paseto::<V1, Local>::builder()
      .set_payload(payload)
      .try_encrypt(&key, &nonce)?;

    //  //validate the test vector
    assert_eq!(token.to_string(), "v1.local.WzhIh1MpbqVNXNt7-HbWvL-JwAym3Tomad9Pc2nl7wK87vGraUVvn2bs8BBNo7jbukCNrkVID0jCK2vr5bP18G78j1bOTbBcP9HZzqnraEdspcjd_PvrxDEhj9cS2MG5fmxtvuoHRp3M24HvxTtql9z26KTfPWxJN5bAJaAM6gos8fnfjJO8oKiqQMaiBP_Cqncmqw8");

    ////now let's try to decrypt it
    let json = Paseto::<V1, Local>::try_decrypt(&token, &key, None)?;
    assert_eq!(payload, json);
    Ok(())
  }

  #[cfg(feature = "v1_local")]
  #[test]
  fn test_1_e_2() -> Result<()> {
    //setup
    let key = PasetoSymmetricKey::<V1, Local>::from(Key::<32>::try_from(
      "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
    )?);
    let nonce = Key::<32>::try_from("0000000000000000000000000000000000000000000000000000000000000000")?;
    let nonce = PasetoNonce::<V1, Local>::from(&nonce);

    let payload = json!({"data": "this is a secret message", "exp":"2019-01-01T00:00:00+00:00"}).to_string();
    let payload = payload.as_str();
    let payload = Payload::from(payload);

    //  //  //create a public V1 token
    let token = Paseto::<V1, Local>::builder()
      .set_payload(payload)
      .try_encrypt(&key, &nonce)?;

    //  //validate the test vector
    assert_eq!(token.to_string(), "v1.local.w_NOpjgte4bX-2i1JAiTQzHoGUVOgc2yqKqsnYGmaPaCu_KWUkRGlCRnOvZZxeH4HTykY7AE_jkzSXAYBkQ1QnwvKS16uTXNfnmp8IRknY76I2m3S5qsM8klxWQQKFDuQHl8xXV0MwAoeFh9X6vbwIqrLlof3s4PMjRDwKsxYzkMr1RvfDI8emoPoW83q4Q60_xpHaw");

    ////now let's try to decrypt it
    let json = Paseto::<V1, Local>::try_decrypt(&token, &key, None)?;
    assert_eq!(payload, json);
    Ok(())
  }

  #[cfg(feature = "v1_local")]
  #[test]
  fn test_1_e_3() -> Result<()> {
    //setup
    let key = PasetoSymmetricKey::<V1, Local>::from(Key::<32>::try_from(
      "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
    )?);
    let nonce = Key::<32>::try_from("26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2")?;
    let nonce = PasetoNonce::<V1, Local>::from(&nonce);

    let payload = json!({"data": "this is a signed message", "exp":"2019-01-01T00:00:00+00:00"}).to_string();
    let payload = payload.as_str();
    let payload = Payload::from(payload);

    //  //  //create a public V1 token
    let token = Paseto::<V1, Local>::builder()
      .set_payload(payload)
      .try_encrypt(&key, &nonce)?;

    //  //validate the test vector
    assert_eq!(token.to_string(), "v1.local.4VyfcVcFAOAbB8yEM1j1Ob7Iez5VZJy5kHNsQxmlrAwKUbOtq9cv39T2fC0MDWafX0nQJ4grFZzTdroMvU772RW-X1oTtoFBjsl_3YYHWnwgqzs0aFc3ejjORmKP4KUM339W3syBYyjKIOeWnsFQB6Yef-1ov9rvqt7TmwONUHeJUYk4IK_JEdUeo_uFRqAIgHsiGCg");

    ////now let's try to decrypt it
    let json = Paseto::<V1, Local>::try_decrypt(&token, &key, None)?;
    assert_eq!(payload, json);
    Ok(())
  }

  #[cfg(feature = "v1_local")]
  #[test]
  fn test_1_e_4() -> Result<()> {
    //setup
    let key = PasetoSymmetricKey::<V1, Local>::from(Key::<32>::try_from(
      "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
    )?);
    let nonce = Key::<32>::try_from("26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2")?;
    let nonce = PasetoNonce::<V1, Local>::from(&nonce);

    let payload = json!({"data": "this is a secret message", "exp":"2019-01-01T00:00:00+00:00"}).to_string();
    let payload = payload.as_str();
    let payload = Payload::from(payload);

    //let footer = Footer::from("{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}");

    //  //  //create a public V1 token
    let token = Paseto::<V1, Local>::builder()
      .set_payload(payload)
      .try_encrypt(&key, &nonce)?;

    //  //validate the test vector
    assert_eq!(token.to_string(), "v1.local.IddlRQmpk6ojcD10z1EYdLexXvYiadtY0MrYQaRnq3dnqKIWcbbpOcgXdMIkm3_3gksirTj81bvWrWkQwcUHilt-tQo7LZK8I6HCK1V78B9YeEqGNeeWXOyWWHoJQIe0d5nTdvejdt2Srz_5Q0QG4oiz1gB_wmv4U5pifedaZbHXUTWXchFEi0etJ4u6tqgxZSklcec");

    ////now let's try to decrypt it
    let json = Paseto::<V1, Local>::try_decrypt(&token, &key, None)?;
    assert_eq!(payload, json);
    Ok(())
  }

  #[cfg(feature = "v1_local")]
  #[test]
  fn test_1_e_5() -> Result<()> {
    //setup
    let key = PasetoSymmetricKey::<V1, Local>::from(Key::<32>::try_from(
      "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
    )?);
    let nonce = Key::<32>::try_from("26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2")?;
    let nonce = PasetoNonce::<V1, Local>::from(&nonce);

    let payload = json!({"data": "this is a signed message", "exp":"2019-01-01T00:00:00+00:00"}).to_string();
    let payload = payload.as_str();
    let payload = Payload::from(payload);

    let footer = json!({"kid":"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo"}).to_string();
    let footer = footer.as_str();
    let footer = Footer::from(footer);
    //  //  //create a public V1 token
    let token = Paseto::<V1, Local>::builder()
      .set_payload(payload)
      .set_footer(footer)
      .try_encrypt(&key, &nonce)?;

    //  //validate the test vector
    assert_eq!(token.to_string(), "v1.local.4VyfcVcFAOAbB8yEM1j1Ob7Iez5VZJy5kHNsQxmlrAwKUbOtq9cv39T2fC0MDWafX0nQJ4grFZzTdroMvU772RW-X1oTtoFBjsl_3YYHWnwgqzs0aFc3ejjORmKP4KUM339W3szA28OabR192eRqiyspQ6xPM35NMR-04-FhRJZEWiF0W5oWjPVtGPjeVjm2DI4YtJg.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9");

    ////now let's try to decrypt it
    let json = Paseto::<V1, Local>::try_decrypt(&token, &key, footer)?;
    assert_eq!(payload, json);
    Ok(())
  }

  #[cfg(feature = "v1_local")]
  #[test]
  fn test_1_e_6() -> Result<()> {
    //setup
    let key = PasetoSymmetricKey::<V1, Local>::from(Key::<32>::try_from(
      "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
    )?);
    let nonce = Key::<32>::try_from("26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2")?;
    let nonce = PasetoNonce::<V1, Local>::from(&nonce);

    let payload = json!({"data": "this is a secret message", "exp":"2019-01-01T00:00:00+00:00"}).to_string();
    let payload = payload.as_str();
    let payload = Payload::from(payload);

    let footer = json!({"kid":"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo"}).to_string();
    let footer = footer.as_str();
    let footer = Footer::from(footer);
    //  //  //create a public V1 token
    let token = Paseto::<V1, Local>::builder()
      .set_payload(payload)
      .set_footer(footer)
      .try_encrypt(&key, &nonce)?;

    //  //validate the test vector
    assert_eq!(token.to_string(), "v1.local.IddlRQmpk6ojcD10z1EYdLexXvYiadtY0MrYQaRnq3dnqKIWcbbpOcgXdMIkm3_3gksirTj81bvWrWkQwcUHilt-tQo7LZK8I6HCK1V78B9YeEqGNeeWXOyWWHoJQIe0d5nTdvcT2vnER6NrJ7xIowvFba6J4qMlFhBnYSxHEq9v9NlzcKsz1zscdjcAiXnEuCHyRSc.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9");

    ////now let's try to decrypt it
    let json = Paseto::<V1, Local>::try_decrypt(&token, &key, footer)?;
    assert_eq!(payload, json);
    Ok(())
  }

  #[cfg(feature = "v1_local")]
  #[test]
  fn test_1_e_7() -> Result<()> {
    //setup
    let key = PasetoSymmetricKey::<V1, Local>::from(Key::<32>::try_from(
      "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
    )?);
    let nonce = Key::<32>::try_from("26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2")?;
    let nonce = PasetoNonce::<V1, Local>::from(&nonce);

    let payload = json!({"data": "this is a signed message", "exp":"2019-01-01T00:00:00+00:00"}).to_string();
    let payload = payload.as_str();
    let payload = Payload::from(payload);

    let footer = json!({"kid":"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo"}).to_string();
    let footer = footer.as_str();
    let footer = Footer::from(footer);

    //  //  //create a public V1 token
    let token = Paseto::<V1, Local>::builder()
      .set_payload(payload)
      .set_footer(footer)
      .try_encrypt(&key, &nonce)?;

    //  //validate the test vector
    assert_eq!(token.to_string(), "v1.local.4VyfcVcFAOAbB8yEM1j1Ob7Iez5VZJy5kHNsQxmlrAwKUbOtq9cv39T2fC0MDWafX0nQJ4grFZzTdroMvU772RW-X1oTtoFBjsl_3YYHWnwgqzs0aFc3ejjORmKP4KUM339W3szA28OabR192eRqiyspQ6xPM35NMR-04-FhRJZEWiF0W5oWjPVtGPjeVjm2DI4YtJg.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9");

    ////now let's try to decrypt it
    let json = Paseto::<V1, Local>::try_decrypt(&token, &key, footer)?;
    assert_eq!(payload, json);
    Ok(())
  }

  #[cfg(feature = "v1_local")]
  #[test]
  fn test_1_e_8() -> Result<()> {
    //setup
    let key = PasetoSymmetricKey::<V1, Local>::from(Key::<32>::try_from(
      "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
    )?);
    let nonce = Key::<32>::try_from("26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2")?;
    let nonce = PasetoNonce::<V1, Local>::from(&nonce);

    let payload = json!({"data": "this is a secret message", "exp":"2019-01-01T00:00:00+00:00"}).to_string();
    let payload = payload.as_str();
    let payload = Payload::from(payload);

    let footer = json!({"kid":"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo"}).to_string();
    let footer = footer.as_str();
    let footer = Footer::from(footer);

    //  //  //create a public V1 token
    let token = Paseto::<V1, Local>::builder()
      .set_payload(payload)
      .set_footer(footer)
      .try_encrypt(&key, &nonce)?;

    //  //validate the test vector
    assert_eq!(token.to_string(), "v1.local.IddlRQmpk6ojcD10z1EYdLexXvYiadtY0MrYQaRnq3dnqKIWcbbpOcgXdMIkm3_3gksirTj81bvWrWkQwcUHilt-tQo7LZK8I6HCK1V78B9YeEqGNeeWXOyWWHoJQIe0d5nTdvcT2vnER6NrJ7xIowvFba6J4qMlFhBnYSxHEq9v9NlzcKsz1zscdjcAiXnEuCHyRSc.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9");

    ////now let's try to decrypt it
    let json = Paseto::<V1, Local>::try_decrypt(&token, &key, footer)?;
    assert_eq!(payload, json);
    Ok(())
  }

  #[cfg(feature = "v1_local")]
  #[test]
  fn test_1_e_9() -> Result<()> {
    //setup
    let key = PasetoSymmetricKey::<V1, Local>::from(Key::<32>::try_from(
      "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
    )?);
    let nonce = Key::<32>::try_from("26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2")?;
    let nonce = PasetoNonce::<V1, Local>::from(&nonce);

    let payload = json!({"data": "this is a secret message", "exp":"2019-01-01T00:00:00+00:00"}).to_string();
    let payload = payload.as_str();
    let payload = Payload::from(payload);

    let footer = Footer::from("arbitrary-string-that-isn't-json");

    //  //  //create a public V1 token
    let token = Paseto::<V1, Local>::builder()
      .set_payload(payload)
      .set_footer(footer)
      .try_encrypt(&key, &nonce)?;

    //  //validate the test vector
    assert_eq!(token.to_string(), "v1.local.IddlRQmpk6ojcD10z1EYdLexXvYiadtY0MrYQaRnq3dnqKIWcbbpOcgXdMIkm3_3gksirTj81bvWrWkQwcUHilt-tQo7LZK8I6HCK1V78B9YeEqGNeeWXOyWWHoJQIe0d5nTdvdgNpe3vI21jV2YL7WVG5p63_JxxzLckBu9azQ0GlDMdPxNAxoyvmU1wbpSbRB9Iw4.YXJiaXRyYXJ5LXN0cmluZy10aGF0LWlzbid0LWpzb24");

    ////now let's try to decrypt it
    let json = Paseto::<V1, Local>::try_decrypt(&token, &key, footer)?;
    assert_eq!(payload, json);
    Ok(())
  }

  #[cfg(feature = "v1_public")]
  #[test]
  fn test_1_s_1() -> Result<()> {
    let private_key = include_bytes!("v1_public_test_vectors_private_key.pk8");
    let pk: &[u8] = private_key;
    let private_key = PasetoAsymmetricPrivateKey::<V1, Public>::from(pk);

    let public_key = include_bytes!("v1_public_test_vectors_public_key.der");
    let pubk: &[u8] = public_key;
    let public_key = PasetoAsymmetricPublicKey::<V1, Public>::from(pubk);

    let payload = json!({"data": "this is a signed message", "exp":"2019-01-01T00:00:00+00:00"}).to_string();
    let payload = payload.as_str();
    let payload = Payload::from(payload);

    //create a public V1 token
    let token = Paseto::<V1, Public>::builder()
      .set_payload(payload)
      .try_sign(&private_key)?;

    //now let's try to decrypt it
    let json = Paseto::<V1, Public>::try_verify(&token, &public_key, None)?;
    assert_eq!(payload, json);
    Ok(())
  }

  #[cfg(feature = "v1_public")]
  #[test]
  fn test_1_s_2() -> Result<()> {
    //setup
    let private_key = include_bytes!("v1_public_test_vectors_private_key.pk8");
    let pk: &[u8] = private_key;

    let private_key = PasetoAsymmetricPrivateKey::<V1, Public>::from(pk);

    let public_key = include_bytes!("v1_public_test_vectors_public_key.der");
    let pubk: &[u8] = public_key;
    let public_key = PasetoAsymmetricPublicKey::<V1, Public>::from(pubk);

    let payload = json!({"data": "this is a signed message","exp": "2019-01-01T00:00:00+00:00"}).to_string();
    let footer = json!({"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}).to_string();

    //create message for test vector
    //  eprintln!("\nJSON INFO: {}\n", json);
    let message = Payload::from(payload.as_str());
    let footer = Footer::from(footer.as_str());

    //  //  //create a local v2 token
    //let token = Paseto::<V1, Public>::build_token(header, message, &key, None);
    let token = Paseto::<V1, Public>::default()
      .set_payload(message.clone())
      .set_footer(footer.clone())
      .try_sign(&private_key)?;

    //  //validate the test vector
    //now let's try to decrypt it
    let json = Paseto::<V1, Public>::try_verify(&token, &public_key, footer)?;
    assert_eq!(payload, json);
    Ok(())
  }

  #[cfg(feature = "v1_public")]
  #[test]
  fn test_1_s_3() -> Result<()> {
    //setup
    let private_key = include_bytes!("v1_public_test_vectors_private_key.pk8");
    let pk: &[u8] = private_key;

    let private_key = PasetoAsymmetricPrivateKey::<V1, Public>::from(pk);

    let public_key = include_bytes!("v1_public_test_vectors_public_key.der");
    let pubk: &[u8] = public_key;
    let public_key = PasetoAsymmetricPublicKey::<V1, Public>::from(pubk);

    let payload = json!({"data": "this is a signed message","exp": "2019-01-01T00:00:00+00:00"}).to_string();
    let footer = json!({"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}).to_string();

    //create message for test vector
    //  eprintln!("\nJSON INFO: {}\n", json);
    let message = Payload::from(payload.as_str());
    let footer = Footer::from(footer.as_str());

    //  //  //create a local v2 token
    //let token = Paseto::<V1, Public>::build_token(header, message, &key, None);
    let token = Paseto::<V1, Public>::default()
      .set_payload(message.clone())
      .set_footer(footer.clone())
      .try_sign(&private_key)?;

    //now let's try to decrypt it
    let json = Paseto::<V1, Public>::try_verify(&token, &public_key, footer)?;
    assert_eq!(payload, json);
    Ok(())
  }

  #[cfg(feature = "v1_public")]
  #[test]
  #[should_panic]
  fn test_1_f_1() {
    //this test is prevented at compile time and passes by defacto
    panic!("non-compileable test")
  }

  #[cfg(feature = "v1_public")]
  #[test]
  #[should_panic]
  fn test_1_f_2() {
    //this test is prevented at compile time and passes by defacto
    panic!("non-compileable test")
  }
}
