#![cfg(feature = "v4_local")]
use base64::prelude::*;
use crate::core::common::RawPayload;
use crate::core::{Local, PasetoError, PasetoNonce, V4};

impl RawPayload<V4, Local> {
    pub(crate) fn try_from(
        nonce: &PasetoNonce<V4, Local>,
        ciphertext: &impl AsRef<Vec<u8>>,
        tag: &impl AsRef<[u8]>,
    ) -> Result<String, PasetoError> {
        let nonce_len = nonce.as_ref().len();
        let ciphertext_len = ciphertext.as_ref().len();
        let tag_len = tag.as_ref().len();
        let concat_len: usize = nonce_len
            .checked_add(tag_len)
            .and_then(|n| n.checked_add(ciphertext_len))
            .ok_or(PasetoError::Cryption)?;

        let mut raw_token = vec![0u8; concat_len];

        // Safe slicing using get_mut with bounds validation
        raw_token
            .get_mut(..nonce_len)
            .ok_or(PasetoError::IncorrectSize)?
            .copy_from_slice(nonce.as_ref());

        let ciphertext_end = nonce_len
            .checked_add(ciphertext_len)
            .ok_or(PasetoError::IncorrectSize)?;
        raw_token
            .get_mut(nonce_len..ciphertext_end)
            .ok_or(PasetoError::IncorrectSize)?
            .copy_from_slice(ciphertext.as_ref());

        let tag_start = concat_len
            .checked_sub(tag_len)
            .ok_or(PasetoError::IncorrectSize)?;
        raw_token
            .get_mut(tag_start..)
            .ok_or(PasetoError::IncorrectSize)?
            .copy_from_slice(tag.as_ref());

        Ok(BASE64_URL_SAFE_NO_PAD.encode(&raw_token))
    }
}
