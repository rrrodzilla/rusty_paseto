use std::marker::PhantomData;

#[derive(Default)]
pub(crate) struct EncryptionKey<Version, Purpose> {
    pub(crate) version: PhantomData<Version>,
    pub(crate) purpose: PhantomData<Purpose>,
    pub(crate) key: Vec<u8>,
    #[cfg(any(feature = "v1_local", feature = "v3_local", feature = "v4_local"))]
    pub(crate) nonce: Vec<u8>,
}

