#![cfg(feature = "v1_local")]
use std::marker::PhantomData;
use ring::hkdf;
use crate::core::{Local, PasetoError, PasetoNonce, PasetoSymmetricKey, V1};
use crate::core::common::authentication_key::AuthenticationKey;
use crate::core::common::hkdf_key::HkdfKey;

impl AuthenticationKey<V1, Local> {
    pub(crate) fn try_from(
        message: &[u8; 24],
        key: &PasetoSymmetricKey<V1, Local>,
        nonce: &PasetoNonce<V1, Local>,
    ) -> Result<Self, PasetoError> {
        let info = message.as_ref();
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA384, &nonce[..16]);
        let HkdfKey(out) = salt.extract(key.as_ref()).expand(&[info], HkdfKey(32))?.try_into()?;

        Ok(Self {
            version: PhantomData,
            purpose: PhantomData,
            key: out,
        })
    }
}
