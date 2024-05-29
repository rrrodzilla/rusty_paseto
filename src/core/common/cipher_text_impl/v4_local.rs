#![cfg(feature = "v4_local")]
use std::marker::PhantomData;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use crate::core::common::{CipherText, EncryptionKey};
use crate::core::{Local, V4};

impl CipherText<V4, Local> {
    pub(crate) fn from(payload: &[u8], encryption_key: &EncryptionKey<V4, Local>) -> Self {
        let mut ciphertext = vec![0u8; payload.len()];
        ciphertext.copy_from_slice(payload);

        let n2 = encryption_key.counter_nonce();
        let mut cipher = chacha20::XChaCha20::new(encryption_key.as_ref(), n2);
        cipher.apply_keystream(&mut ciphertext);

        CipherText {
            ciphertext,
            version: PhantomData,
            purpose: PhantomData,
        }
    }
}
