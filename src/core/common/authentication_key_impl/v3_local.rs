#![cfg(feature = "v3_local")]
use std::marker::PhantomData;
use ring::hkdf;
use crate::core::{Key, Local, PasetoError, PasetoSymmetricKey, V3};
use crate::core::common::HkdfKey;

impl crate::core::common::authentication_key::AuthenticationKey<V3, Local> {
    pub(crate) fn try_from(message: &Key<56>, key: &PasetoSymmetricKey<V3, Local>) -> Result<Self, PasetoError> {
        let info = message.as_ref();
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA384, &[]);
        let HkdfKey(out) = salt.extract(key.as_ref()).expand(&[info], HkdfKey(48))?.try_into()?;

        Ok(Self {
            version: PhantomData,
            purpose: PhantomData,
            key: out,
        })
    }
}