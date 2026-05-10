use std::marker::PhantomData;
use std::ops::Deref;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AuthenticationKey<Version, Purpose> {
    #[zeroize(skip)]
    pub(crate) version: PhantomData<Version>,
    #[zeroize(skip)]
    pub(crate) purpose: PhantomData<Purpose>,
    pub(crate) key: Vec<u8>,
}

impl<Version, Purpose> AsRef<[u8]> for AuthenticationKey<Version, Purpose> {
    fn as_ref(&self) -> &[u8] {
        &self.key
    }
}

impl<Version, Purpose> Deref for AuthenticationKey<Version, Purpose> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.key
    }
}
