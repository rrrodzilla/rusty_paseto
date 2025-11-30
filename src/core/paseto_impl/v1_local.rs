#![cfg(feature = "v1_local")]
use std::str;
use hmac::{Hmac, Mac};
use subtle::ConstantTimeEq;
use crate::core::{Footer, Header, Key, Local, Paseto, PasetoError, PasetoNonce, PasetoSymmetricKey, V1};
use crate::core::common::{AuthenticationKey, AuthenticationKeySeparator, CipherText, EncryptionKey, EncryptionKeySeparator, PreAuthenticationEncoding, RawPayload, Tag};
use sha2::Sha384;

impl<'a> Paseto<'a, V1, Local> {
    /// Attempts to decrypt a PASETO token
    /// ```
    /// # use serde_json::json;
    /// # use rusty_paseto::core::*;
    /// # let key = PasetoSymmetricKey::<V1, Local>::from(Key::<32>::try_from("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")?);
    /// # let nonce = Key::<32>::try_from("0000000000000000000000000000000000000000000000000000000000000000")?;
    /// # let nonce = PasetoNonce::<V1, Local>::from(&nonce);
    /// # let payload = json!({"data": "this is a secret message", "exp":"2022-01-01T00:00:00+00:00"}).to_string();
    /// # let payload = payload.as_str();
    /// # let payload = Payload::from(payload);
    /// # let token = Paseto::<V1, Local>::builder().set_payload(payload).try_encrypt(&key, &nonce)?;
    /// // decrypt a public v1 token
    /// let json = Paseto::<V1, Local>::try_decrypt(&token, &key, None)?;
    /// # assert_eq!(payload, json);
    /// # Ok::<(),anyhow::Error>(())
    /// ```
    pub fn try_decrypt(
        token: &'a str,
        key: &PasetoSymmetricKey<V1, Local>,
        footer: impl Into<Option<Footer<'a>>> + Copy,
    ) -> Result<String, PasetoError> {
        // V1 local token structure: nonce (32 bytes) + ciphertext (variable) + tag (48 bytes)
        const NONCE_SIZE: usize = 32;
        const TAG_SIZE: usize = 48;
        const MIN_PAYLOAD_SIZE: usize = NONCE_SIZE + TAG_SIZE;

        let decoded_payload = Self::parse_raw_token(token, footer, &V1::default(), &Local::default())?;

        // Validate minimum payload size before slicing
        if decoded_payload.len() < MIN_PAYLOAD_SIZE {
            return Err(PasetoError::IncorrectSize);
        }

        // Safe slicing with bounds-checked access
        let nonce_bytes = decoded_payload.get(..NONCE_SIZE).ok_or(PasetoError::IncorrectSize)?;
        let nonce = Key::from(nonce_bytes);
        let nonce = PasetoNonce::<V1, Local>::from(&nonce);

        let aks: &[u8] = &AuthenticationKeySeparator::default();
        let authentication_key = AuthenticationKey::<V1, Local>::try_from(&Key::from(aks), key, &nonce)?;
        let eks: &[u8] = &EncryptionKeySeparator::default();
        let encryption_key = EncryptionKey::<V1, Local>::try_from(&Key::from(eks), key, &nonce)?;

        // Ciphertext is between nonce and tag
        let ciphertext_end = decoded_payload.len().saturating_sub(TAG_SIZE);
        let ciphertext = decoded_payload.get(NONCE_SIZE..ciphertext_end).ok_or(PasetoError::IncorrectSize)?;

        //pack preauth
        let pae = PreAuthenticationEncoding::parse(&[
            &Header::<V1, Local>::default(),
            nonce.as_ref(),
            ciphertext,
            &footer.into().unwrap_or_default(),
        ]);

        //generate tags - tag is the last TAG_SIZE bytes
        let tag_start = NONCE_SIZE + ciphertext.len();
        let tag = decoded_payload.get(tag_start..).ok_or(PasetoError::IncorrectSize)?;
        let tag2 = Tag::<V1, Local>::try_from(authentication_key, &pae)?;
        //compare tags
        if !bool::from(tag.ct_eq(tag2.as_ref())) {
            return Err(PasetoError::Cryption);
        }

        //decrypt payload
        let ciphertext = CipherText::<V1, Local>::from(ciphertext, &encryption_key);

        let decoded_str = str::from_utf8(&ciphertext)?;

        //return decrypted payload
        Ok(decoded_str.to_owned())
    }

    /// Attempts to encrypt a PASETO token
    /// ```
    /// # use serde_json::json;
    /// # use rusty_paseto::core::*;
    /// # let key = PasetoSymmetricKey::<V1, Local>::from(Key::<32>::try_from("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")?);
    /// # let nonce = Key::<32>::try_from("0000000000000000000000000000000000000000000000000000000000000000")?;
    /// # let nonce = PasetoNonce::<V1, Local>::from(&nonce);
    /// # let payload = json!({"data": "this is a secret message", "exp":"2022-01-01T00:00:00+00:00"}).to_string();
    /// # let payload = payload.as_str();
    /// # let payload = Payload::from(payload);
    /// // encrypt a public v1 token
    /// let token = Paseto::<V1, Local>::builder().set_payload(payload).try_encrypt(&key, &nonce)?;
    /// # let json = Paseto::<V1, Local>::try_decrypt(&token, &key, None)?;
    /// # assert_eq!(payload, json);
    /// # Ok::<(),anyhow::Error>(())
    /// ```
    pub fn try_encrypt(
        &mut self,
        key: &PasetoSymmetricKey<V1, Local>,
        nonce: &PasetoNonce<V1, Local>,
    ) -> Result<String, PasetoError> {
        //setup
        let footer = self.footer.unwrap_or_default();

        //calculate nonce
        type HmacSha384 = Hmac<Sha384>;
        let mut mac = HmacSha384::new_from_slice(nonce.as_ref())
            .map_err(|_| PasetoError::InvalidKey)?;

        mac.update(&self.payload);
        let out = mac.finalize();
        let hmac_bytes = out.into_bytes();
        let nonce_bytes = hmac_bytes.get(..32).ok_or(PasetoError::IncorrectSize)?;
        let nonce = Key::from(nonce_bytes);
        let nonce = PasetoNonce::<V1, Local>::from(&nonce);

        //split key
        let aks: &[u8] = &AuthenticationKeySeparator::default();
        let authentication_key = AuthenticationKey::<V1, Local>::try_from(&Key::from(aks), key, &nonce)?;
        let eks: &[u8] = &EncryptionKeySeparator::default();
        let encryption_key = EncryptionKey::<V1, Local>::try_from(&Key::from(eks), key, &nonce)?;

        //encrypt payload
        let ciphertext = CipherText::<V1, Local>::from(&self.payload, &encryption_key);

        //pack preauth
        let pae = PreAuthenticationEncoding::parse(&[&self.header, nonce.as_ref(), &ciphertext, &footer]);

        //generate tag
        let tag = Tag::<V1, Local>::try_from(authentication_key, &pae)?;

        //generate appended and base64 encoded payload
        let raw_payload = RawPayload::<V1, Local>::from(&nonce, &ciphertext, &tag)?;

        //format as paseto with header and optional footer
        Ok(self.format_token(&raw_payload))
    }
}
