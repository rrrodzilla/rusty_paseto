#![cfg(feature = "v2_local")]
use base64::prelude::*;
use crate::core::common::RawPayload;
use crate::core::{Local, V2};

impl RawPayload<V2, Local> {
    pub(crate) fn from(blake2_hash: &[u8], ciphertext: &[u8]) -> String {
        let mut raw_token = Vec::new();
        raw_token.extend_from_slice(blake2_hash);
        raw_token.extend_from_slice(ciphertext);

        BASE64_URL_SAFE_NO_PAD.encode(&raw_token)
    }
}
