use std::marker::PhantomData;
use std::ops::Deref;

pub struct Tag<Version, Purpose> {
    pub(crate) version: PhantomData<Version>,
    pub(crate) purpose: PhantomData<Purpose>,
    pub(crate) value: Vec<u8>,
}



impl<Version, Purpose> AsRef<[u8]> for Tag<Version, Purpose> {
    fn as_ref(&self) -> &[u8] {
        &self.value
    }
}

impl<Version, Purpose> Deref for Tag<Version, Purpose> {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.value
    }
}