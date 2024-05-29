#![cfg(any(feature = "v1_local", feature = "v3_local"))]
use base64::prelude::*;
use crate::core::common::RawPayload;
use crate::core::{Local, PasetoError, PasetoNonce, V1orV3};

impl<Version> RawPayload<Version, Local>
    where
        Version: V1orV3,
{
    pub(crate) fn from(
        nonce: &PasetoNonce<Version, Local>,
        ciphertext: &impl AsRef<Vec<u8>>,
        tag: &impl AsRef<[u8]>,
    ) -> Result<String, PasetoError> {
        let tag_len = tag.as_ref().len();
        let concat_len: usize = match (nonce.len() + tag_len).checked_add(ciphertext.as_ref().len()) {
            Some(len) => len,
            None => return Err(PasetoError::Signature),
        };

        let mut raw_token = vec![0u8; concat_len];
        raw_token[..nonce.as_ref().len()].copy_from_slice(nonce.as_ref());
        raw_token[nonce.as_ref().len()..nonce.as_ref().len() + ciphertext.as_ref().len()]
            .copy_from_slice(ciphertext.as_ref());
        raw_token[concat_len - tag_len..].copy_from_slice(tag.as_ref());

        Ok(BASE64_URL_SAFE_NO_PAD.encode(&raw_token))
    }
}
