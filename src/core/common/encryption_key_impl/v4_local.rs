#![cfg(feature = "v4_local")]
use std::marker::PhantomData;
use std::ops::Deref;
use blake2::digest::consts::U56;
use blake2::{Blake2bMac, digest::Update};
use blake2::digest::FixedOutput;
use digest::KeyInit;
use chacha20::{XNonce, Key};
use crate::core::common::EncryptionKey;
use crate::core::{Local, PasetoSymmetricKey, V4};

impl EncryptionKey<V4, Local> {
    pub(crate) fn from(message: &crate::core::Key<53>, key: &PasetoSymmetricKey<V4, Local>) -> Self {
        let mut context = Blake2bMac::<U56>::new_from_slice(key.as_ref()).unwrap();
        context.update(message.as_ref());
        let binding = context.finalize_fixed();
        let context = binding.to_vec();
        let key = context[..32].to_vec();
        let nonce = context[32..56].to_vec();

        assert_eq!(key.len(), 32);
        assert_eq!(nonce.len(), 24);
        Self {
            key,
            nonce,
            version: PhantomData,
            purpose: PhantomData,
        }

    }
    pub(crate) fn counter_nonce(&self) -> &XNonce {
        XNonce::from_slice(&self.nonce)
    }
}

impl AsRef<Key> for EncryptionKey<V4, Local> {
    fn as_ref(&self) -> &Key {
        Key::from_slice(&self.key)
    }
}

impl Deref for EncryptionKey<V4, Local> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        Key::from_slice(&self.key)
    }
}