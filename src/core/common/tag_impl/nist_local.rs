#![cfg(any(feature = "v1_local", feature = "v3_local"))]
use std::marker::PhantomData;
use hmac::{Hmac, Mac};
use crate::core::{Local, PasetoError, V1orV3};
use crate::core::common::PreAuthenticationEncoding;

impl<Version> crate::core::common::tag::Tag<Version, Local>
    where
        Version: V1orV3,
{
    pub(crate) fn try_from(authentication_key: impl AsRef<[u8]>, pae: &PreAuthenticationEncoding) -> Result<Self, PasetoError> {
        type HmacSha384 = Hmac<sha2::Sha384>;

        let mut mac = HmacSha384::new_from_slice(authentication_key.as_ref())
            .map_err(|_| PasetoError::InvalidKey)?;
        mac.update(pae.as_ref());

        let out = mac.finalize();

        Ok(Self {
            value: out.into_bytes().to_vec(),
            version: PhantomData,
            purpose: PhantomData,
        })
    }
}