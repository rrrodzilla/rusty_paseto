#![cfg(feature = "v1_public")]
use std::marker::PhantomData;
use ring::signature::{RSA_PSS_2048_8192_SHA384, UnparsedPublicKey};
use crate::core::common::{CipherText, PreAuthenticationEncoding};
use crate::core::{Footer, Header, PasetoError, Public, V1};

impl CipherText<V1, Public> {
    pub(crate) fn try_verify(decoded_payload: &[u8], public_key: &impl AsRef<[u8]>, footer: &Footer) -> Result<Self, PasetoError> {
        let signature = decoded_payload[(decoded_payload.len() - 256)..].as_ref();
        let public_key = UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA384, public_key);
        let msg = decoded_payload[..(decoded_payload.len() - 256)].as_ref();

        let pae = PreAuthenticationEncoding::parse(&[&Header::<V1, Public>::default(), msg, footer]);

        public_key.verify(&pae, signature)?;

        let ciphertext = Vec::from(msg);

        Ok(CipherText {
            ciphertext,
            version: PhantomData,
            purpose: PhantomData,
        })
    }
}