use ring::hkdf;
use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::core::PasetoError;

#[derive(Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct HkdfKey<T: core::fmt::Debug + PartialEq + Zeroize>(pub T);

impl hkdf::KeyType for HkdfKey<usize> {
    fn len(&self) -> usize {
        self.0
    }
}

impl TryFrom<hkdf::Okm<'_, HkdfKey<usize>>> for HkdfKey<Vec<u8>> {
    type Error = PasetoError;
    fn try_from(okm: hkdf::Okm<HkdfKey<usize>>) -> Result<Self, Self::Error> {
        let mut r = vec![0u8; okm.len().0];
        okm.fill(&mut r)?;
        Ok(Self(r))
    }
}
