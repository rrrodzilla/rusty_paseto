use std::marker::PhantomData;

pub(crate) struct CipherText<Version, Purpose> {
    pub(crate) ciphertext: Vec<u8>,
    pub(crate) version: PhantomData<Version>,
    pub(crate) purpose: PhantomData<Purpose>,
}

impl<Version, Purpose> AsRef<Vec<u8>> for CipherText<Version, Purpose> {
    fn as_ref(&self) -> &Vec<u8> {
        &self.ciphertext
    }
}

impl<Version, Purpose> std::ops::Deref for CipherText<Version, Purpose> {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        &self.ciphertext
    }
}