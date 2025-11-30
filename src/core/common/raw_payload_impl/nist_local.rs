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
        let nonce_len = nonce.as_ref().len();
        let ciphertext_len = ciphertext.as_ref().len();
        let tag_len = tag.as_ref().len();
        let concat_len: usize = nonce_len
            .checked_add(tag_len)
            .and_then(|n| n.checked_add(ciphertext_len))
            .ok_or(PasetoError::Signature)?;

        let mut raw_token = vec![0u8; concat_len];

        // Safe slicing using get_mut with bounds validation
        raw_token
            .get_mut(..nonce_len)
            .ok_or(PasetoError::IncorrectSize)?
            .copy_from_slice(nonce.as_ref());

        raw_token
            .get_mut(nonce_len..nonce_len + ciphertext_len)
            .ok_or(PasetoError::IncorrectSize)?
            .copy_from_slice(ciphertext.as_ref());

        raw_token
            .get_mut(concat_len - tag_len..)
            .ok_or(PasetoError::IncorrectSize)?
            .copy_from_slice(tag.as_ref());

        Ok(BASE64_URL_SAFE_NO_PAD.encode(&raw_token))
    }
}
