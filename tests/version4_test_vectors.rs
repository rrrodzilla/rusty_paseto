#[cfg(all(test, feature = "v4"))]
mod v4_test_vectors {
    use anyhow::{Result};
    use serde_json::json;

    use rusty_paseto::core::*;

    #[cfg(feature = "local")]
    #[test]
    fn test_4_e_1() -> Result<()> {
        //setup
        let key = PasetoSymmetricKey::<V4, Local>::from(Key::<32>::try_from(
            "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
        )?);
        let nonce = Key::<32>::try_from("0000000000000000000000000000000000000000000000000000000000000000")?;
        let nonce = PasetoNonce::<V4, Local>::from(&nonce);

        let payload = json!({"data": "this is a secret message", "exp":"2022-01-01T00:00:00+00:00"}).to_string();
        let payload = payload.as_str();
        let payload = Payload::from(payload);

        //  //  //create a public v4 token
        let token = Paseto::<V4, Local>::builder()
            .set_payload(payload)
            .try_encrypt(&key, &nonce)?;

        //  //validate the test vector
        assert_eq!(token.to_string(), "v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAr68PS4AXe7If_ZgesdkUMvSwscFlAl1pk5HC0e8kApeaqMfGo_7OpBnwJOAbY9V7WU6abu74MmcUE8YWAiaArVI8XJ5hOb_4v9RmDkneN0S92dx0OW4pgy7omxgf3S8c3LlQg");

        ////now let's try to decrypt it
        let json = Paseto::<V4, Local>::try_decrypt(&token, &key, None, None)?;
        assert_eq!(payload, json);
        Ok(())
    }

    #[cfg(feature = "local")]
    #[test]
    fn test_4_e_2() -> Result<()> {
        //setup
        let key = PasetoSymmetricKey::<V4, Local>::from(Key::<32>::try_from(
            "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
        )?);
        let nonce = Key::<32>::try_from("0000000000000000000000000000000000000000000000000000000000000000")?;
        let nonce = PasetoNonce::<V4, Local>::from(&nonce);

        let payload = json!({"data": "this is a hidden message", "exp":"2022-01-01T00:00:00+00:00"}).to_string();
        let payload = payload.as_str();
        let payload = Payload::from(payload);

        //  //  //create a public v4 token
        let token = Paseto::<V4, Local>::builder()
            .set_payload(payload)
            .try_encrypt(&key, &nonce)?;

        //  //validate the test vector
        assert_eq!(token.to_string(), "v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAr68PS4AXe7If_ZgesdkUMvS2csCgglvpk5HC0e8kApeaqMfGo_7OpBnwJOAbY9V7WU6abu74MmcUE8YWAiaArVI8XIemu9chy3WVKvRBfg6t8wwYHK0ArLxxfZP73W_vfwt5A");

        ////now let's try to decrypt it
        let json = Paseto::<V4, Local>::try_decrypt(&token, &key, None, None)?;
        assert_eq!(payload, json);
        Ok(())
    }

    #[cfg(feature = "local")]
    #[test]
    fn test_4_e_3() -> Result<()> {
        //setup
        let key = PasetoSymmetricKey::<V4, Local>::from(Key::<32>::try_from(
            "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
        )?);
        let nonce = Key::<32>::try_from("df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8")?;
        let nonce = PasetoNonce::<V4, Local>::from(&nonce);

        let payload = json!({"data": "this is a secret message", "exp":"2022-01-01T00:00:00+00:00"}).to_string();
        let payload = payload.as_str();
        let payload = Payload::from(payload);

        //  //  //create a public v4 token
        let token = Paseto::<V4, Local>::builder()
            .set_payload(payload)
            .try_encrypt(&key, &nonce)?;

        //  //validate the test vector
        assert_eq!(token.to_string(), "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WkwMsYXw6FSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t6-tyebyWG6Ov7kKvBdkrrAJ837lKP3iDag2hzUPHuMKA");

        ////now let's try to decrypt it
        let json = Paseto::<V4, Local>::try_decrypt(&token, &key, None, None)?;
        assert_eq!(payload, json);
        Ok(())
    }

    #[cfg(feature = "local")]
    #[test]
    fn test_4_e_4() -> Result<()> {
        //setup
        let key = PasetoSymmetricKey::<V4, Local>::from(Key::<32>::try_from(
            "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
        )?);
        let nonce = Key::<32>::try_from("df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8")?;
        let nonce = PasetoNonce::<V4, Local>::from(&nonce);

        let payload = json!({"data": "this is a hidden message", "exp":"2022-01-01T00:00:00+00:00"}).to_string();
        let payload = payload.as_str();
        let payload = Payload::from(payload);

        //  //  //create a public v4 token
        let token = Paseto::<V4, Local>::builder()
            .set_payload(payload)
            .try_encrypt(&key, &nonce)?;

        //  //validate the test vector
        assert_eq!(token.to_string(), "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WiA8rd3wgFSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t4gt6TiLm55vIH8c_lGxxZpE3AWlH4WTR0v45nsWoU3gQ");

        ////now let's try to decrypt it
        let json = Paseto::<V4, Local>::try_decrypt(&token, &key, None, None)?;
        assert_eq!(payload, json);
        Ok(())
    }

    #[cfg(feature = "local")]
    #[test]
    fn test_4_e_5() -> Result<()> {
        //setup
        let key = PasetoSymmetricKey::<V4, Local>::from(Key::<32>::try_from(
            "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
        )?);
        let nonce = Key::<32>::try_from("df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8")?;
        let nonce = PasetoNonce::<V4, Local>::from(&nonce);

        let payload = json!({"data": "this is a secret message", "exp":"2022-01-01T00:00:00+00:00"}).to_string();
        let payload = payload.as_str();
        let payload = Payload::from(payload);

        let footer = json!({"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}).to_string();
        let footer = footer.as_str();
        let footer = Footer::from(footer);
        //  //  //create a public v4 token
        let token = Paseto::<V4, Local>::builder()
            .set_payload(payload)
            .set_footer(footer)
            .try_encrypt(&key, &nonce)?;

        //  //validate the test vector
        assert_eq!(token.to_string(), "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WkwMsYXw6FSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t4x-RMNXtQNbz7FvFZ_G-lFpk5RG3EOrwDL6CgDqcerSQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9");

        ////now let's try to decrypt it
        let json = Paseto::<V4, Local>::try_decrypt(&token, &key, footer, None)?;
        assert_eq!(payload, json);
        Ok(())
    }

    #[cfg(feature = "local")]
    #[test]
    fn test_4_e_6() -> Result<()> {
        //setup
        let key = PasetoSymmetricKey::<V4, Local>::from(Key::<32>::try_from(
            "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
        )?);
        let nonce = Key::<32>::try_from("df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8")?;
        let nonce = PasetoNonce::<V4, Local>::from(&nonce);

        let payload = json!({"data": "this is a hidden message", "exp":"2022-01-01T00:00:00+00:00"}).to_string();
        let payload = payload.as_str();
        let payload = Payload::from(payload);

        let footer = json!({"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}).to_string();
        let footer = footer.as_str();
        let footer = Footer::from(footer);
        //  //  //create a public v4 token
        let token = Paseto::<V4, Local>::builder()
            .set_payload(payload)
            .set_footer(footer)
            .try_encrypt(&key, &nonce)?;

        //  //validate the test vector
        assert_eq!(token.to_string(), "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WiA8rd3wgFSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t6pWSA5HX2wjb3P-xLQg5K5feUCX4P2fpVK3ZLWFbMSxQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9");

        ////now let's try to decrypt it
        let json = Paseto::<V4, Local>::try_decrypt(&token, &key, footer, None)?;
        assert_eq!(payload, json);
        Ok(())
    }

    #[cfg(feature = "local")]
    #[test]
    fn test_4_e_7() -> Result<()> {
        //setup
        let key = PasetoSymmetricKey::<V4, Local>::from(Key::<32>::try_from(
            "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
        )?);
        let nonce = Key::<32>::try_from("df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8")?;
        let nonce = PasetoNonce::<V4, Local>::from(&nonce);

        let payload = json!({"data": "this is a secret message", "exp":"2022-01-01T00:00:00+00:00"}).to_string();
        let payload = payload.as_str();
        let payload = Payload::from(payload);

        let footer = json!({"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}).to_string();
        let footer = footer.as_str();
        let footer = Footer::from(footer);

        let implicit_assertion = json!({"test-vector":"4-E-7"}).to_string();
        let implicit_assertion = implicit_assertion.as_str();
        let implicit_assertion = ImplicitAssertion::from(implicit_assertion);
        //  //  //create a public v4 token
        let token = Paseto::<V4, Local>::builder()
            .set_payload(payload)
            .set_footer(footer)
            .set_implicit_assertion(implicit_assertion)
            .try_encrypt(&key, &nonce)?;

        //  //validate the test vector
        assert_eq!(token.to_string(), "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WkwMsYXw6FSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t40KCCWLA7GYL9KFHzKlwY9_RnIfRrMQpueydLEAZGGcA.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9");

        ////now let's try to decrypt it
        let json = Paseto::<V4, Local>::try_decrypt(&token, &key, footer, implicit_assertion)?;
        assert_eq!(payload, json);
        Ok(())
    }

    #[cfg(feature = "local")]
    #[test]
    fn test_4_e_8() -> Result<()> {
        //setup
        let key = PasetoSymmetricKey::<V4, Local>::from(Key::<32>::try_from(
            "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
        )?);
        let nonce = Key::<32>::try_from("df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8")?;
        let nonce = PasetoNonce::<V4, Local>::from(&nonce);

        let payload = json!({"data": "this is a hidden message", "exp":"2022-01-01T00:00:00+00:00"}).to_string();
        let payload = payload.as_str();
        let payload = Payload::from(payload);

        let footer = json!({"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}).to_string();
        let footer = footer.as_str();
        let footer = Footer::from(footer);

        let implicit_assertion = json!({"test-vector":"4-E-8"}).to_string();
        let implicit_assertion = implicit_assertion.as_str();
        let implicit_assertion = ImplicitAssertion::from(implicit_assertion);
        //  //  //create a public v4 token
        let token = Paseto::<V4, Local>::builder()
            .set_payload(payload)
            .set_footer(footer)
            .set_implicit_assertion(implicit_assertion)
            .try_encrypt(&key, &nonce)?;

        //  //validate the test vector
        assert_eq!(token.to_string(), "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WiA8rd3wgFSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t5uvqQbMGlLLNYBc7A6_x7oqnpUK5WLvj24eE4DVPDZjw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9");

        ////now let's try to decrypt it
        let json = Paseto::<V4, Local>::try_decrypt(&token, &key, footer, implicit_assertion)?;
        assert_eq!(payload, json);
        Ok(())
    }

    #[cfg(feature = "local")]
    #[test]
    fn test_4_e_9() -> Result<()> {
        //setup
        let key = PasetoSymmetricKey::<V4, Local>::from(Key::<32>::try_from(
            "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
        )?);
        let nonce = Key::<32>::try_from("df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8")?;
        let nonce = PasetoNonce::<V4, Local>::from(&nonce);

        let payload = json!({"data": "this is a hidden message", "exp":"2022-01-01T00:00:00+00:00"}).to_string();
        let payload = payload.as_str();
        let payload = Payload::from(payload);

        let footer = Footer::from("arbitrary-string-that-isn't-json");

        let implicit_assertion = json!({"test-vector":"4-E-9"}).to_string();
        let implicit_assertion = implicit_assertion.as_str();
        let implicit_assertion = ImplicitAssertion::from(implicit_assertion);
        //  //  //create a public v4 token
        let token = Paseto::<V4, Local>::builder()
            .set_payload(payload)
            .set_footer(footer)
            .set_implicit_assertion(implicit_assertion)
            .try_encrypt(&key, &nonce)?;

        //  //validate the test vector
        assert_eq!(token.to_string(), "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WiA8rd3wgFSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t6tybdlmnMwcDMw0YxA_gFSE_IUWl78aMtOepFYSWYfQA.YXJiaXRyYXJ5LXN0cmluZy10aGF0LWlzbid0LWpzb24");

        ////now let's try to decrypt it
        let json = Paseto::<V4, Local>::try_decrypt(&token, &key, footer, implicit_assertion)?;
        assert_eq!(payload, json);
        Ok(())
    }

    #[cfg(feature = "v4_public")]
    #[test]
    fn test_4_s_1() -> Result<()> {
        //then generate the V2 local key for it
        //setup
        //let key = Key::<32>::try_from("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")?;
        //let key = PasetoKey::<V4, Local>::from(&key);
        //let nonce = Key::<32>::try_from("0000000000000000000000000000000000000000000000000000000000000000")?;
        //let nonce = PasetoNonce::<V4, Local>::from(&nonce);
        let private_key = Key::<64>::try_from("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")?;
        let pk: &[u8] = private_key.as_slice();
        let private_key = PasetoAsymmetricPrivateKey::<V4, Public>::from(pk);
        let public_key = Key::<32>::try_from("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")?;
        let public_key = PasetoAsymmetricPublicKey::<V4, Public>::from(&public_key);

        let payload = json!({"data": "this is a signed message", "exp":"2022-01-01T00:00:00+00:00"}).to_string();
        let payload = payload.as_str();
        let payload = Payload::from(payload);

        //  //  //create a public v4 token
        let token = Paseto::<V4, Public>::builder()
            .set_payload(payload)
            .try_sign(&private_key)?;

        //  //validate the test vector
        assert_eq!(token.to_string(), "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9bg_XBBzds8lTZShVlwwKSgeKpLT3yukTw6JUz3W4h_ExsQV-P0V54zemZDcAxFaSeef1QlXEFtkqxT1ciiQEDA");

        ////now let's try to decrypt it
        let json = Paseto::<V4, Public>::try_verify(&token, &public_key, None, None)?;
        assert_eq!(payload, json);
        Ok(())
    }

    #[cfg(feature = "public")]
    #[test]
    fn test_4_s_2() -> Result<()> {
        //setup
        let private_key = Key::<64>::try_from("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")?;
        let pk: &[u8] = private_key.as_slice();
        let private_key = PasetoAsymmetricPrivateKey::<V4, Public>::from(pk);

        let public_key = Key::<32>::try_from("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")?;
        let public_key = PasetoAsymmetricPublicKey::<V4, Public>::from(&public_key);

        let payload = json!({"data": "this is a signed message","exp": "2022-01-01T00:00:00+00:00"}).to_string();
        let footer = json!({"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}).to_string();

        //create message for test vector
        //  eprintln!("\nJSON INFO: {}\n", json);
        let message = Payload::from(payload.as_str());
        let footer = Footer::from(footer.as_str());

        //  //  //create a local v2 token
        //let token = Paseto::<V2, Public>::build_token(header, message, &key, None);
        let token = Paseto::<V4, Public>::default()
            .set_payload(message.clone())
            .set_footer(footer.clone())
            .try_sign(&private_key);
        match token {
            Ok(token) => {
                //  //validate the test vector
                assert_eq!(token, "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9v3Jt8mx_TdM2ceTGoqwrh4yDFn0XsHvvV_D0DtwQxVrJEBMl0F2caAdgnpKlt4p7xBnx1HcO-SPo8FPp214HDw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9");

                //now let's try to decrypt it
                let json = Paseto::<V4, Public>::try_verify(&token, &public_key, footer, None)?;
                assert_eq!(payload, json);
                Ok(())
            }
            Err(thiserror) => {
                eprintln!("here's the error: {}", thiserror);
                Err(anyhow::Error::from(thiserror))
            }
        }
    }

    #[cfg(feature = "public")]
    #[test]
    fn test_4_s_3() -> Result<()> {
        //setup
        let private_key = Key::<64>::try_from("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")?;
        let pk: &[u8] = private_key.as_slice();
        let private_key = PasetoAsymmetricPrivateKey::<V4, Public>::from(pk);

        let public_key = Key::<32>::try_from("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")?;
        let public_key = PasetoAsymmetricPublicKey::<V4, Public>::from(&public_key);

        let payload = json!({"data": "this is a signed message","exp": "2022-01-01T00:00:00+00:00"}).to_string();
        let footer = json!({"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}).to_string();
        let assertion = json!({"test-vector":"4-S-3"}).to_string();

        //create message for test vector
        //  eprintln!("\nJSON INFO: {}\n", json);
        let message = Payload::from(payload.as_str());
        let footer = Footer::from(footer.as_str());
        let assertion = ImplicitAssertion::from(assertion.as_str());

        //  //  //create a local v2 token
        //let token = Paseto::<V2, Public>::build_token(header, message, &key, None);
        let token = Paseto::<V4, Public>::default()
            .set_payload(message.clone())
            .set_footer(footer.clone())
            .set_implicit_assertion(assertion)
            .try_sign(&private_key)?;

        //  //validate the test vector
        assert_eq!(token.to_string(), "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9NPWciuD3d0o5eXJXG5pJy-DiVEoyPYWs1YSTwWHNJq6DZD3je5gf-0M4JR9ipdUSJbIovzmBECeaWmaqcaP0DQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9");

        //now let's try to decrypt it
        let json = Paseto::<V4, Public>::try_verify(&token, &public_key, footer, assertion)?;
        assert_eq!(payload, json);
        Ok(())
    }

    #[cfg(feature = "public")]
    #[test]
    #[should_panic]
    fn test_4_f_1() {
        //this test is prevented at compile time and passes by defacto
        panic!("non-compileable test")
    }

    #[cfg(feature = "public")]
    #[test]
    #[should_panic]
    fn test_4_f_2() {
        //this test is prevented at compile time and passes by defacto
        panic!("non-compileable test")
    }

    #[cfg(feature = "public")]
    #[test]
    #[should_panic]
    fn test_4_f_3() {
        //this test is prevented at compile time and passes by defacto
        panic!("non-compileable test")
    }
}
