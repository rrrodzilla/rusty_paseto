#![cfg(feature = "v2_public")]
use std::marker::PhantomData;
use crate::core::{PasetoNonce, Public, V2};

impl<'a, T> From<&'a T> for PasetoNonce<'a, V2, Public>
    where
        T: Into<&'a [u8]>,
        &'a [u8]: From<&'a T>,
{
    fn from(key: &'a T) -> Self {
        Self {
            version: PhantomData,
            purpose: PhantomData,
            key: key.into(),
        }
    }
}
