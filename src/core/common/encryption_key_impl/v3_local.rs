#![cfg(feature = "v3_local")]
use std::marker::PhantomData;
use ring::hkdf;
use crate::core::{Key, Local, PasetoError, PasetoSymmetricKey, V3};
use crate::core::common::{EncryptionKey, HkdfKey};
impl EncryptionKey<V3, Local> {
    pub(crate) fn try_from(message: &Key<53>, key: &PasetoSymmetricKey<V3, Local>) -> Result<Self, PasetoError> {
        let info = message.as_ref();
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA384, &[]);

        let HkdfKey(out) = salt.extract(key.as_ref()).expand(&[info], HkdfKey(48))?.try_into()?;

        Ok(Self {
            version: PhantomData,
            purpose: PhantomData,
            key: out[..32].to_vec(),
            nonce: out[32..].to_vec(),
        })
    }

    pub(crate) fn counter_nonce(&self) -> &Vec<u8> {
        &self.nonce
    }
}
