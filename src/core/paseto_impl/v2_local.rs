#![cfg(feature = "v2_local")]
use blake2::Blake2bMac;
use blake2::digest::{FixedOutput, Mac};
use chacha20poly1305::XNonce;
use crate::core::{Footer, Header, Local, Paseto, PasetoError, PasetoNonce, PasetoSymmetricKey, V2};
use crate::core::common::{CipherText, PreAuthenticationEncoding, RawPayload};
use std::str;
impl<'a> Paseto<'a, V2, Local> {
    /// Attempts to decrypt a PASETO token
    /// ```
    /// # use serde_json::json;
    /// # use rusty_paseto::core::*;
    /// # let key = PasetoSymmetricKey::<V2, Local>::from(Key::<32>::try_from("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")?);
    /// # let nonce = Key::<32>::try_from("0000000000000000000000000000000000000000000000000000000000000000")?;
    /// # let nonce = PasetoNonce::<V2, Local>::from(&nonce);
    /// # let payload = json!({"data": "this is a secret message", "exp":"2022-01-01T00:00:00+00:00"}).to_string();
    /// # let payload = payload.as_str();
    /// # let payload = Payload::from(payload);
    /// # let token = Paseto::<V2, Local>::builder().set_payload(payload).try_encrypt(&key, &nonce)?;
    /// // decrypt a public v2 token
    /// let json = Paseto::<V2, Local>::try_decrypt(&token, &key, None)?;
    /// # assert_eq!(payload, json);
    /// # Ok::<(),anyhow::Error>(())
    /// ```
    pub fn try_decrypt(
        token: &'a str,
        key: &PasetoSymmetricKey<V2, Local>,
        footer: (impl Into<Option<Footer<'a>>> + Copy),
    ) -> Result<String, PasetoError> {
        //get footer

        let decoded_payload = Self::parse_raw_token(token, footer, &V2::default(), &Local::default())?;
        let (nonce, ciphertext) = decoded_payload.split_at(24);

        //pack preauth
        let pae = &PreAuthenticationEncoding::parse(&[
            &Header::<V2, Local>::default(),
            nonce,
            &footer.into().unwrap_or_default(),
        ]);

        //create the nonce
        let nonce = XNonce::from_slice(nonce);

        //encrypt payload
        let ciphertext = CipherText::<V2, Local>::try_decrypt_from(key, nonce, ciphertext, pae)?;

        //generate appended and base64 encoded payload
        let decoded_str = str::from_utf8(&ciphertext)?;

        //return decrypted payload
        Ok(decoded_str.to_owned())
    }

    /// Attempts to encrypt a PASETO token
    /// ```
    /// # use serde_json::json;
    /// # use rusty_paseto::core::*;
    /// # let key = PasetoSymmetricKey::<V2, Local>::from(Key::<32>::try_from("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")?);
    /// # let nonce = Key::<32>::try_from("0000000000000000000000000000000000000000000000000000000000000000")?;
    /// # let nonce = PasetoNonce::<V2, Local>::from(&nonce);
    /// # let payload = json!({"data": "this is a secret message", "exp":"2022-01-01T00:00:00+00:00"}).to_string();
    /// # let payload = payload.as_str();
    /// # let payload = Payload::from(payload);
    /// // encrypt a public v2 token
    /// let token = Paseto::<V2, Local>::builder().set_payload(payload).try_encrypt(&key, &nonce)?;
    /// # let json = Paseto::<V2, Local>::try_decrypt(&token, &key, None)?;
    /// # assert_eq!(payload, json);
    /// # Ok::<(),anyhow::Error>(())
    /// ```
    pub fn try_encrypt(
        &self,
        key: &PasetoSymmetricKey<V2, Local>,
        nonce: &PasetoNonce<V2, Local>,
    ) -> Result<String, PasetoError> {
        //setup
        let footer = self.footer.unwrap_or_default();

        //create the blake2 context to generate the nonce
        let mut blake2 = Blake2bMac::new_from_slice(nonce.as_ref())?;
        blake2.update(&self.payload);
        let mut context = [0u8; 24];
        blake2.finalize_into((&mut context).into());

        //create the nonce
        let nonce = XNonce::from_slice(&context);

        //pack preauth
        let pae = PreAuthenticationEncoding::parse(&[&self.header, nonce, &footer]);

        //encrypt payload
        let ciphertext = CipherText::<V2, Local>::try_from(key, nonce, &self.payload, &pae)?;

        //generate appended and base64 encoded payload
        let raw_payload = RawPayload::<V2, Local>::from(&context, &ciphertext);

        //format as paseto with header and optional footer
        Ok(self.format_token(&raw_payload))
    }
}
