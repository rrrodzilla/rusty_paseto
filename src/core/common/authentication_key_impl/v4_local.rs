#![cfg(feature = "v4_local")]
use std::marker::PhantomData;
use std::ops::Deref;
use blake2::digest::consts::U32;
use blake2::{Blake2bMac, digest::Update};
use blake2::digest::FixedOutput;
use digest::KeyInit;
use crate::core::{Key, Local, PasetoSymmetricKey, V4};

impl crate::core::common::authentication_key::AuthenticationKey<V4, Local> {
    pub(crate) fn from(message: &Key<56>, key: &PasetoSymmetricKey<V4, Local>) -> Self {
        let mut context = Blake2bMac::<U32>::new_from_slice(key.as_ref()).unwrap();
        context.update(message.as_ref());
        let binding = context.finalize_fixed();
        let key = binding.to_vec();
        Self {
            version: PhantomData,
            purpose: PhantomData,
            key,
        }
    }
}