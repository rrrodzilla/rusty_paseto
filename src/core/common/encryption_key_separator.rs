use std::fmt;
use std::fmt::Display;
use std::ops::{Add, Deref};
use crate::core::{Key, Local, PasetoNonce};

#[derive(Debug)]
pub (crate) struct EncryptionKeySeparator(&'static str);

impl Display for EncryptionKeySeparator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", &self.0)
    }
}

impl Default for EncryptionKeySeparator {
    fn default() -> Self {
        Self("paseto-encryption-key")
    }
}

impl Deref for EncryptionKeySeparator {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.as_bytes()
    }
}

impl AsRef<str> for EncryptionKeySeparator {
    fn as_ref(&self) -> &str {
        self.0
    }
}

impl<'a, Version> Add<&PasetoNonce<'a, Version, Local>> for EncryptionKeySeparator {
    type Output = Key<53>;

    fn add(self, rhs: &PasetoNonce<Version, Local>) -> Self::Output {
        let mut output = [0u8; 53];
        output[..21].copy_from_slice(self.0.as_bytes());
        output[21..].copy_from_slice(rhs.as_ref());
        Key::<53>::from(output)
    }
}
