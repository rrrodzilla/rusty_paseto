#![cfg(feature = "v2_local")]
use std::marker::PhantomData;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use chacha20poly1305::aead::{Aead, Payload};
use crate::core::common::{CipherText, PreAuthenticationEncoding};
use crate::core::{Local, PasetoError, PasetoSymmetricKey, V2};

impl CipherText<V2, Local> {
    pub(crate) fn try_decrypt_from(
        key: &PasetoSymmetricKey<V2, Local>,
        nonce: &XNonce,
        payload: &[u8],
        pre_auth: &PreAuthenticationEncoding,
    ) -> Result<Self, PasetoError> {
        //let ciphertext = CipherText::try_from(&key, &nonce, &payload, &pae)?;

        let aead = XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| PasetoError::Cryption)?;
        //encrypt cipher_text
        let ciphertext = aead
            .decrypt(
                nonce,
                Payload {
                    msg: payload,
                    aad: pre_auth.as_ref(),
                },
            )
            .map_err(|_| PasetoError::ChaChaCipherError)?;

        Ok(CipherText {
            ciphertext,
            version: PhantomData,
            purpose: PhantomData,
        })
    }

    pub(crate) fn try_from(
        key: &PasetoSymmetricKey<V2, Local>,
        nonce: &XNonce,
        payload: &[u8],
        pre_auth: &PreAuthenticationEncoding,
    ) -> Result<Self, PasetoError> {
        let aead = XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| PasetoError::Cryption)?;
        //encrypt cipher_text
        let ciphertext = aead
            .encrypt(
                nonce,
                Payload {
                    msg: payload,
                    aad: pre_auth.as_ref(),
                },
            )
            .map_err(|_| PasetoError::ChaChaCipherError)?;

        Ok(CipherText {
            ciphertext,
            version: PhantomData,
            purpose: PhantomData,
        })
    }
}