use std::marker::PhantomData;
use std::ops::Deref;

pub(crate) struct Tag<Version, Purpose> {
    pub(crate) version: PhantomData<Version>,
    pub(crate) purpose: PhantomData<Purpose>,
    pub(crate) tag: Vec<u8>,
}



impl<Version, Purpose> AsRef<[u8]> for Tag<Version, Purpose> {
    fn as_ref(&self) -> &[u8] {
        &self.tag
    }
}

impl<Version, Purpose> Deref for Tag<Version, Purpose> {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.tag
    }
}