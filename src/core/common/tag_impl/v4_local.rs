#![cfg(feature = "v4_local")]
use std::marker::PhantomData;
use std::ops::Deref;
use blake2::digest::consts::U32;
use blake2::{Blake2bMac, digest::Update};
use blake2::digest::FixedOutput;
use digest::KeyInit;
use crate::core::common::PreAuthenticationEncoding;
use crate::core::{Local, V4};

impl crate::core::common::tag::Tag<V4, Local> {
    pub(crate) fn from(authentication_key: impl AsRef<[u8]>, pae: &PreAuthenticationEncoding) -> Self {
        let mut tag_context = Blake2bMac::<U32>::new_from_slice(authentication_key.as_ref()).unwrap();
        tag_context.update(pae.as_ref());
        let binding = tag_context.finalize_fixed();
        let tag = binding.to_vec();
        Self {
            tag,
            version: PhantomData,
            purpose: PhantomData,
        }
    }
}

