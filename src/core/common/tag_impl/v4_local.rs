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
        // let mut tag_context = Blake2bMac::<U32>::new_with_salt_and_personal(authentication_key.as_ref(), Default::default(), Default::default()).expect("Failure in V4, Local Tag creation.");
        tag_context.update(pae.as_ref());
        let mut buf = [0u8; 32];
        let binding = tag_context.finalize_fixed();
        let tag = binding.as_slice();
        Self {
            tag: Vec::from(tag),
            version: PhantomData,
            purpose: PhantomData,
        }
    }
}

