#![cfg(feature = "v1_public_insecure")]
use std::marker::PhantomData;
use ring::signature::{RSA_PSS_2048_8192_SHA384, UnparsedPublicKey};
use crate::core::common::{CipherText, PreAuthenticationEncoding};
use crate::core::{Footer, Header, PasetoError, Public, V1};

const SIGNATURE_SIZE: usize = 256;

impl CipherText<V1, Public> {
    pub(crate) fn try_verify(decoded_payload: &[u8], public_key: &impl AsRef<[u8]>, footer: &Footer) -> Result<Self, PasetoError> {
        // Validate minimum payload size to prevent panic from underflow
        if decoded_payload.len() < SIGNATURE_SIZE {
            return Err(PasetoError::IncorrectSize);
        }

        // Use safe .get() access with bounds already validated above
        let msg_len = decoded_payload.len().saturating_sub(SIGNATURE_SIZE);
        let signature = decoded_payload.get(msg_len..).ok_or(PasetoError::IncorrectSize)?;
        let public_key = UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA384, public_key);
        let msg = decoded_payload.get(..msg_len).ok_or(PasetoError::IncorrectSize)?;

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