use std::ops::Deref;
use crate::core::common::EncryptionKey;
use crate::core::{Local, V1orV3};

impl<Version> AsRef<Vec<u8>> for EncryptionKey<Version, Local>
    where
        Version: V1orV3,
{
    fn as_ref(&self) -> &Vec<u8> {
        &self.key
    }
}

impl<Version> Deref for EncryptionKey<Version, Local>
    where
        Version: V1orV3,
{
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.key
    }
}