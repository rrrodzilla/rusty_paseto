#![cfg(feature = "v4_local")]
use std::marker::PhantomData;
use std::ops::Deref;
use blake2::digest::consts::U32;
use blake2::{Blake2bMac, digest::Update};
use blake2::digest::FixedOutput;
use digest::KeyInit;
use crate::core::common::PreAuthenticationEncoding;
use crate::core::{Local, PasetoError, V4};

impl crate::core::common::tag::Tag<V4, Local> {
    pub(crate) fn try_from(authentication_key: impl AsRef<[u8]>, pae: &PreAuthenticationEncoding) -> Result<Self, PasetoError> {
        let mut tag_context = Blake2bMac::<U32>::new_from_slice(authentication_key.as_ref())?;
        tag_context.update(pae.as_ref());
        let binding = tag_context.finalize_fixed();
        let value = binding.to_vec();
        Ok(Self {
            value,
            version: PhantomData,
            purpose: PhantomData,
        })
    }
}

