#![cfg(feature = "v1_local")]
use std::marker::PhantomData;
use ring::hkdf;
use crate::core::common::EncryptionKey;
use crate::core::{Key, Local, PasetoError, PasetoNonce, PasetoSymmetricKey, V1};
use crate::core::common::hkdf_key::HkdfKey;
impl EncryptionKey<V1, Local> {
    pub(crate) fn try_from(
        message: &Key<21>,
        key: &PasetoSymmetricKey<V1, Local>,
        nonce: &PasetoNonce<V1, Local>,
    ) -> Result<Self, PasetoError> {
        let info = message.as_ref();
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA384, &nonce[..16]);
        let HkdfKey(out) = salt.extract(key.as_ref()).expand(&[info], HkdfKey(32))?.try_into()?;

        Ok(Self {
            version: PhantomData,
            purpose: PhantomData,
            key: out.to_vec(),
            nonce: nonce[16..].to_vec(),
        })
    }

    pub(crate) fn counter_nonce(&self) -> &Vec<u8> {
        &self.nonce
    }
}