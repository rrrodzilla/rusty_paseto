#![cfg(feature = "v4_local")]

use std::str;

use ring::constant_time::verify_slices_are_equal as ConstantTimeEquals;

use crate::core::{Footer, Header, ImplicitAssertion, Key, Local, Paseto, PasetoError, PasetoNonce, PasetoSymmetricKey, V4};
use crate::core::common::{AuthenticationKey, AuthenticationKeySeparator, CipherText, EncryptionKey, EncryptionKeySeparator, PreAuthenticationEncoding, RawPayload, Tag};

impl<'a> Paseto<'a, V4, Local> {
    /// Attempts to decrypt a PASETO token
    /// ```
    /// # use serde_json::json;
    /// # use rusty_paseto::core::*;
    /// # let key = PasetoSymmetricKey::<V4, Local>::from(Key::<32>::try_from("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")?);
    /// # let nonce = Key::<32>::try_from("0000000000000000000000000000000000000000000000000000000000000000")?;
    /// # let nonce = PasetoNonce::<V4, Local>::from(&nonce);
    /// # let payload = json!({"data": "this is a secret message", "exp":"2022-01-01T00:00:00+00:00"}).to_string();
    /// # let payload = payload.as_str();
    /// # let payload = Payload::from(payload);
    /// # let token = Paseto::<V4, Local>::builder().set_payload(payload).try_encrypt(&key, &nonce)?;
    /// // decrypt a public v4 token
    /// let json = Paseto::<V4, Local>::try_decrypt(&token, &key, None, None)?;
    /// # assert_eq!(payload, json);
    /// # Ok::<(),anyhow::Error>(())
    /// ```
    pub fn try_decrypt(
        token: &'a str,
        key: &PasetoSymmetricKey<V4, Local>,
        footer: (impl Into<Option<Footer<'a>>> + Copy),
        implicit_assertion: (impl Into<Option<ImplicitAssertion<'a>>> + Copy),
    ) -> Result<String, PasetoError> {
        //get footer

        let decoded_payload = Self::parse_raw_token(token, footer, &V4::default(), &Local::default())?;
        let nonce = Key::from(&decoded_payload[..32]);
        let nonce = PasetoNonce::<V4, Local>::from(&nonce);

        let authentication_key =
            AuthenticationKey::<V4, Local>::from(&(AuthenticationKeySeparator::default() + &nonce), key);
        let encryption_key = EncryptionKey::<V4, Local>::from(&(EncryptionKeySeparator::default() + &nonce), key);

        let ciphertext = &decoded_payload[32..(decoded_payload.len() - 32)];

        //pack preauth
        let pae = PreAuthenticationEncoding::parse(&[
            &Header::<V4, Local>::default(),
            nonce.as_ref(),
            ciphertext,
            &footer.into().unwrap_or_default(),
            &implicit_assertion.into().unwrap_or_default(),
        ]);

        //generate tags
        let tag = &decoded_payload[(nonce.len() + ciphertext.len())..];
        let tag2 = &Tag::<V4, Local>::from(authentication_key, &pae);
        //compare tags
        ConstantTimeEquals(tag, tag2)?;

        //decrypt payload
        let ciphertext = CipherText::<V4, Local>::from(ciphertext, &encryption_key);

        let decoded_str = str::from_utf8(&ciphertext)?;

        //return decrypted payload
        Ok(decoded_str.to_owned())
    }

    /// Attempts to encrypt a PASETO token
    /// ```
    /// # use serde_json::json;
    /// # use rusty_paseto::core::*;
    /// # let key = PasetoSymmetricKey::<V4, Local>::from(Key::<32>::try_from("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")?);
    /// # let nonce = Key::<32>::try_from("0000000000000000000000000000000000000000000000000000000000000000")?;
    /// # // generate a random nonce with
    /// # // let nonce = Key::<32>::try_new_random()?;
    /// # let nonce = PasetoNonce::<V4, Local>::from(&nonce);
    /// # let payload = json!({"data": "this is a secret message", "exp":"2022-01-01T00:00:00+00:00"}).to_string();
    /// # let payload = payload.as_str();
    /// # let payload = Payload::from(payload);
    /// //create a public v4 token
    /// let token = Paseto::<V4, Local>::builder().set_payload(payload).try_encrypt(&key, &nonce)?;
    /// #  let json = Paseto::<V4, Local>::try_decrypt(&token, &key, None, None)?;
    /// # assert_eq!(payload, json);
    /// # Ok::<(),anyhow::Error>(())
    /// ```
    pub fn try_encrypt(
        &mut self,
        key: &PasetoSymmetricKey<V4, Local>,
        nonce: &PasetoNonce<V4, Local>,
    ) -> Result<String, PasetoError> {
        //setup
        let footer = self.footer.unwrap_or_default();
        let implicit_assertion = self.implicit_assertion.unwrap_or_default();

        //split key
        let authentication_key =
            AuthenticationKey::<V4, Local>::from(&(AuthenticationKeySeparator::default() + nonce), key);
        let encryption_key = EncryptionKey::<V4, Local>::from(&(EncryptionKeySeparator::default() + nonce), key);

        //encrypt payload
        let ciphertext = CipherText::<V4, Local>::from(&self.payload, &encryption_key);

        //pack preauth
        let pae =
            PreAuthenticationEncoding::parse(&[&self.header, nonce.as_ref(), &ciphertext, &footer, &implicit_assertion]);

        //generate tag
        let tag = Tag::<V4, Local>::from(authentication_key, &pae);

        //generate appended and base64 encoded payload
        let raw_payload = RawPayload::<V4, Local>::try_from(nonce, &ciphertext, &tag)?;

        //format as paseto with header and optional footer
        Ok(self.format_token(&raw_payload))
    }
}
