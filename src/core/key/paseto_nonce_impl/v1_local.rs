#![cfg(feature = "v1_local")]
use std::marker::PhantomData;
use crate::core::{Key, Local, PasetoNonce, V1};

impl<'a> From<&'a Key<32>> for PasetoNonce<'a, V1, Local> {
    fn from(key: &'a Key<32>) -> Self {
        Self {
            version: PhantomData,
            purpose: PhantomData,
            key: key.as_ref(),
        }
    }
}
