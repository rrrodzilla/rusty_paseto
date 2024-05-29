#![cfg(feature = "v1_public")]
use ring::rand::SystemRandom;
use ring::signature::{RSA_PSS_SHA384, RsaKeyPair};
use crate::core::{Footer, Paseto, PasetoAsymmetricPrivateKey, PasetoAsymmetricPublicKey, PasetoError, Public, V1};
use crate::core::common::{CipherText, PreAuthenticationEncoding, RawPayload};

impl<'a> Paseto<'a, V1, Public> {
    /// Verifies a signed V1 Public Paseto
    pub fn try_verify(
        signature: &'a str,
        public_key: &PasetoAsymmetricPublicKey<V1, Public>,
        footer: (impl Into<Option<Footer<'a>>> + Copy),
    ) -> Result<String, PasetoError> {
        let decoded_payload = Self::parse_raw_token(signature, footer, &V1::default(), &Public::default())?;

        let ciphertext =
            CipherText::<V1, Public>::try_verify(&decoded_payload, public_key, &footer.into().unwrap_or_default())?
                .ciphertext;

        Ok(String::from_utf8(ciphertext)?)
    }

    /// Attempts to sign a V1 Public Paseto
    /// Fails with a PasetoError if the token is malformed or the private key isn't in a valid pkcs#8
    /// format
    pub fn try_sign(&mut self, key: &PasetoAsymmetricPrivateKey<V1, Public>) -> Result<String, PasetoError> {
        let footer = self.footer.unwrap_or_default();

        let key_pair = RsaKeyPair::from_pkcs8(key.as_ref())?;

        let pae = PreAuthenticationEncoding::parse(&[&self.header, &self.payload, &footer]);
        let random = SystemRandom::new();

        let mut signature = [0; 256];

        key_pair
            .sign(&RSA_PSS_SHA384, &random, &pae, &mut signature)
            .map_err(|_| PasetoError::InvalidSignature)?;

        let raw_payload = RawPayload::<V1, Public>::from(&self.payload, &signature);

        Ok(self.format_token(&raw_payload))
    }
}
