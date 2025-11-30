#![cfg(feature = "v4_local")]
use std::marker::PhantomData;
use std::ops::Deref;
use blake2::digest::consts::U32;
use blake2::{Blake2bMac, digest::Update};
use blake2::digest::FixedOutput;
use digest::KeyInit;
use crate::core::{Key, Local, PasetoError, PasetoSymmetricKey, V4};

impl crate::core::common::authentication_key::AuthenticationKey<V4, Local> {
    pub(crate) fn try_from(message: &Key<56>, key: &PasetoSymmetricKey<V4, Local>) -> Result<Self, PasetoError> {
        let mut context = Blake2bMac::<U32>::new_from_slice(key.as_ref())?;
        context.update(message.as_ref());
        let binding = context.finalize_fixed();
        let key_bytes = binding.to_vec();
        Ok(Self {
            version: PhantomData,
            purpose: PhantomData,
            key: key_bytes,
        })
    }
}