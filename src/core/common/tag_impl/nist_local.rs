#![cfg(any(feature = "v1_local", feature = "v3_local"))]
use std::marker::PhantomData;
use hmac::{Hmac, Mac};
use crate::core::{Local, V1orV3};
use crate::core::common::PreAuthenticationEncoding;

impl<Version> crate::core::common::tag::Tag<Version, Local>
    where
        Version: V1orV3,
{
    pub(crate) fn from(authentication_key: impl AsRef<[u8]>, pae: &PreAuthenticationEncoding) -> Self {
        type HmacSha384 = Hmac<sha2::Sha384>;

        let mut mac = HmacSha384::new_from_slice(authentication_key.as_ref()).expect("HMAC can take key of any size");
        mac.update(pae.as_ref());

        let out = mac.finalize();

        Self {
            tag: out.into_bytes().to_vec(),
            version: PhantomData,
            purpose: PhantomData,
        }
    }
}