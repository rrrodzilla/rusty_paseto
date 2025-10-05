#[cfg(all(test, feature = "v4_local"))]
mod key_rotation_tests {
    use rusty_paseto::core::*;
    use serde_json::json;
    use std::collections::HashMap;

    // Simulates a key store with multiple keys for rotation
    struct KeyStore {
        keys: HashMap<String, PasetoSymmetricKey<V4, Local>>,
    }

    impl KeyStore {
        fn new() -> Self {
            let mut keys = HashMap::new();

            // Add some keys with identifiers
            keys.insert(
                "key-1".to_string(),
                PasetoSymmetricKey::<V4, Local>::from(Key::<32>::from(
                    *b"key1key1key1key1key1key1key1key1",
                )),
            );

            keys.insert(
                "key-2".to_string(),
                PasetoSymmetricKey::<V4, Local>::from(Key::<32>::from(
                    *b"key2key2key2key2key2key2key2key2",
                )),
            );

            Self { keys }
        }

        fn get(&self, kid: &str) -> Option<&PasetoSymmetricKey<V4, Local>> {
            self.keys.get(kid)
        }
    }

    #[test]
    fn test_key_rotation_with_untrusted_footer() -> Result<(), Box<dyn std::error::Error>> {
        let key_store = KeyStore::new();

        // Create a token with key-1, including the key identifier in the footer
        let key1 = key_store.get("key-1").expect("key-1 should exist");
        let nonce = Key::<32>::try_new_random()?;
        let nonce = PasetoNonce::<V4, Local>::from(&nonce);

        let payload = json!({"data": "sensitive information", "user": "alice"}).to_string();
        let payload_str = payload.as_str();
        let payload = Payload::from(payload_str);

        let footer_data = json!({"kid": "key-1"});
        let footer_str = footer_data.to_string();
        let footer = Footer::from(footer_str.as_str());

        let token = Paseto::<V4, Local>::builder()
            .set_payload(payload)
            .set_footer(footer)
            .try_encrypt(key1, &nonce)?;

        // Now simulate receiving this token and needing to determine which key to use
        // Step 1: Extract the footer from the untrusted token
        let untrusted = UntrustedToken::try_parse(&token)?;

        let extracted_footer = untrusted
            .footer_str()?
            .expect("footer should be present");

        // Step 2: Parse the footer to extract the key identifier
        let footer_json: serde_json::Value = serde_json::from_str(&extracted_footer)?;
        let kid = footer_json["kid"]
            .as_str()
            .expect("kid should be a string");

        assert_eq!(kid, "key-1");

        // Step 3: Select the appropriate key from the key store
        let selected_key = key_store.get(kid).expect("key should exist in store");

        // Step 4: Verify the token with the selected key and expected footer
        let decrypted_payload = Paseto::<V4, Local>::try_decrypt(
            &token,
            selected_key,
            Footer::from(extracted_footer.as_str()),
            None,
        )?;

        assert_eq!(decrypted_payload, payload_str);

        Ok(())
    }

    #[test]
    fn test_key_rotation_with_footer_convenience_method(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key_store = KeyStore::new();

        // Create a token with key-2
        let key2 = key_store.get("key-2").expect("key-2 should exist");
        let nonce = Key::<32>::try_new_random()?;
        let nonce = PasetoNonce::<V4, Local>::from(&nonce);

        let payload = json!({"data": "another secret", "user": "bob"}).to_string();
        let payload_str = payload.as_str();
        let payload = Payload::from(payload_str);

        let footer_data = json!({"kid": "key-2", "version": "2024-01-01"});
        let footer_str = footer_data.to_string();
        let footer = Footer::from(footer_str.as_str());

        let token = Paseto::<V4, Local>::builder()
            .set_payload(payload)
            .set_footer(footer)
            .try_encrypt(key2, &nonce)?;

        // Use the Footer convenience method to extract the footer
        let extracted_footer =
            Footer::try_from_token(&token)?.expect("footer should be present");

        // Parse the footer to extract the key identifier
        let footer_json: serde_json::Value = serde_json::from_str(&extracted_footer)?;
        let kid = footer_json["kid"]
            .as_str()
            .expect("kid should be a string");

        assert_eq!(kid, "key-2");

        // Select and verify with the appropriate key
        let selected_key = key_store.get(kid).expect("key should exist in store");

        let decrypted_payload = Paseto::<V4, Local>::try_decrypt(
            &token,
            selected_key,
            Footer::from(extracted_footer.as_str()),
            None,
        )?;

        assert_eq!(decrypted_payload, payload_str);

        Ok(())
    }

    #[test]
    fn test_token_without_footer_returns_none() -> Result<(), Box<dyn std::error::Error>> {
        let key = PasetoSymmetricKey::<V4, Local>::from(Key::<32>::from(
            b"testkey_testkey_testkey_32bytes!",
        ));
        let nonce = Key::<32>::try_new_random()?;
        let nonce = PasetoNonce::<V4, Local>::from(&nonce);

        let payload = Payload::from(r#"{"data":"no footer here"}"#);

        // Create token without footer
        let token = Paseto::<V4, Local>::builder()
            .set_payload(payload)
            .try_encrypt(&key, &nonce)?;

        // Try to extract footer - should return None
        let footer_result = Footer::try_from_token(&token)?;
        assert!(footer_result.is_none());

        let untrusted = UntrustedToken::try_parse(&token)?;
        assert!(untrusted.footer_base64().is_none());
        assert!(untrusted.footer_str()?.is_none());

        Ok(())
    }

    #[test]
    fn test_footer_mismatch_fails_verification() -> Result<(), Box<dyn std::error::Error>> {
        let key = PasetoSymmetricKey::<V4, Local>::from(Key::<32>::from(
            b"testkey_testkey_testkey_32bytes!",
        ));
        let nonce = Key::<32>::try_new_random()?;
        let nonce = PasetoNonce::<V4, Local>::from(&nonce);

        let payload = Payload::from(r#"{"data":"secret"}"#);
        let footer = Footer::from(r#"{"kid":"key-1"}"#);

        let token = Paseto::<V4, Local>::builder()
            .set_payload(payload)
            .set_footer(footer)
            .try_encrypt(&key, &nonce)?;

        // Extract the footer
        let extracted_footer =
            Footer::try_from_token(&token)?.expect("footer should be present");

        assert_eq!(&extracted_footer, r#"{"kid":"key-1"}"#);

        // Try to verify with a different footer - should fail
        let wrong_footer = Footer::from(r#"{"kid":"key-2"}"#);
        let result = Paseto::<V4, Local>::try_decrypt(&token, &key, wrong_footer, None);

        assert!(matches!(result, Err(PasetoError::FooterInvalid)));

        Ok(())
    }
}

#[cfg(all(test, feature = "v4_public"))]
mod public_key_rotation_tests {
    use rusty_paseto::core::*;
    use serde_json::json;

    #[test]
    fn test_public_key_rotation_with_untrusted_footer() -> Result<(), Box<dyn std::error::Error>>
    {
        // Generate a key pair
        let private_key_bytes = Key::<64>::try_from("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")?;
        let private_key = PasetoAsymmetricPrivateKey::<V4, Public>::from(&private_key_bytes);

        let public_key_bytes =
            Key::<32>::try_from("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")?;
        let public_key = PasetoAsymmetricPublicKey::<V4, Public>::from(&public_key_bytes);

        // Create a signed token with a footer containing key identifier
        let payload = json!({"data": "signed message", "user": "charlie"}).to_string();
        let payload_str = payload.as_str();
        let payload = Payload::from(payload_str);

        let footer_data = json!({"kid": "signing-key-1", "alg": "EdDSA"});
        let footer_str = footer_data.to_string();
        let footer = Footer::from(footer_str.as_str());

        let token = Paseto::<V4, Public>::builder()
            .set_payload(payload)
            .set_footer(footer)
            .try_sign(&private_key)?;

        // Extract footer to determine which public key to use for verification
        let extracted_footer =
            Footer::try_from_token(&token)?.expect("footer should be present");

        let footer_json: serde_json::Value = serde_json::from_str(&extracted_footer)?;
        let kid = footer_json["kid"]
            .as_str()
            .expect("kid should be a string");

        assert_eq!(kid, "signing-key-1");

        // Verify the token with the public key
        let verified_payload = Paseto::<V4, Public>::try_verify(
            &token,
            &public_key,
            Footer::from(extracted_footer.as_str()),
            None,
        )?;

        assert_eq!(verified_payload, payload_str);

        Ok(())
    }
}
