use std::fmt;
use std::fmt::Display;
use std::ops::{Add, Deref};
use crate::core::{Key, Local, PasetoNonce};

#[derive(Debug)]
pub (crate) struct AuthenticationKeySeparator(&'static str);

impl Display for AuthenticationKeySeparator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", &self.0)
    }
}

impl Default for AuthenticationKeySeparator {
    fn default() -> Self {
        Self("paseto-auth-key-for-aead")
    }
}

impl Deref for AuthenticationKeySeparator {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.as_bytes()
    }
}

impl AsRef<str> for AuthenticationKeySeparator {
    fn as_ref(&self) -> &str {
        self.0
    }
}

impl<'a, Version> Add<&PasetoNonce<'a, Version, Local>> for AuthenticationKeySeparator {
    type Output = Key<56>;

    fn add(self, rhs: &PasetoNonce<Version, Local>) -> Self::Output {
        let mut output = [0u8; 56];
        output[..24].copy_from_slice(self.0.as_bytes());
        output[24..].copy_from_slice(rhs.as_ref());
        Key::<56>::from(output)
    }
}
