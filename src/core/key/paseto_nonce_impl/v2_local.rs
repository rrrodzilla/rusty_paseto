#![cfg(feature = "v2_local")]
use std::marker::PhantomData;
use crate::core::{Key, Local, PasetoNonce, V2};

impl<'a> From<&'a Key<24>> for PasetoNonce<'a, V2, Local> {
    fn from(key: &'a Key<24>) -> Self {
        Self {
            version: PhantomData,
            purpose: PhantomData,
            key: key.as_ref(),
        }
    }
}

impl<'a> From<&'a Key<32>> for PasetoNonce<'a, V2, Local> {
    fn from(key: &'a Key<32>) -> Self {
        Self {
            version: PhantomData,
            purpose: PhantomData,
            key: key.as_ref(),
        }
    }
}

#[cfg(all(test, feature = "v2_local"))]
mod builders {
    use std::convert::From;

    use crate::core::*;
    use anyhow::Result;

    use super::PasetoNonce;

    #[test]
    fn v2_local_key_test() -> Result<()> {
        let key = Key::<32>::from(b"wubbalubbadubdubwubbalubbadubdub");
        let paseto_key = PasetoNonce::<V2, Local>::from(&key);
        assert_eq!(paseto_key.as_ref().len(), key.as_ref().len());
        Ok(())
    }
}
