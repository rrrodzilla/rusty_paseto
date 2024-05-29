#![cfg(any(feature = "v1_public", feature = "v2_public", feature = "v3_public", feature = "v4_public"))]
use base64::prelude::*;
use crate::core::common::RawPayload;
use crate::core::Public;

impl<Version> RawPayload<Version, Public> {
    pub(crate) fn from(payload: &[u8], signature: &impl AsRef<[u8]>) -> String {
        let mut raw_token = Vec::from(payload);
        raw_token.extend_from_slice(signature.as_ref());

        BASE64_URL_SAFE_NO_PAD.encode(&raw_token)
    }
}