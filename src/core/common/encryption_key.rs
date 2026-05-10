use std::marker::PhantomData;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Default, Zeroize, ZeroizeOnDrop)]
pub struct EncryptionKey<Version, Purpose> {
    #[zeroize(skip)]
    pub(crate) version: PhantomData<Version>,
    #[zeroize(skip)]
    pub(crate) purpose: PhantomData<Purpose>,
    pub(crate) key: Vec<u8>,
    #[cfg(any(feature = "v1_local", feature = "v3_local", feature = "v4_local"))]
    pub(crate) nonce: Vec<u8>,
}
