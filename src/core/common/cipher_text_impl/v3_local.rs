#![cfg(feature = "v3_local")]
use std::marker::PhantomData;
use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};
use ctr::cipher::generic_array::GenericArray;
use ctr::Ctr128BE;
use crate::core::common::{CipherText, EncryptionKey};
use crate::core::{Local, V3};

type Aes256Ctr = Ctr128BE<Aes256>;

impl CipherText<V3, Local> {
    pub(crate) fn from(payload: &[u8], encryption_key: &EncryptionKey<V3, Local>) -> Self {
        let key = GenericArray::from_slice(encryption_key.as_ref());
        let nonce = GenericArray::from_slice(encryption_key.counter_nonce());
        let mut cipher = Aes256Ctr::new(key, nonce);
        let mut ciphertext = vec![0u8; payload.len()];

        ciphertext.copy_from_slice(payload);

        cipher.apply_keystream(&mut ciphertext);

        CipherText {
            ciphertext,
            version: PhantomData,
            purpose: PhantomData,
        }
    }
}