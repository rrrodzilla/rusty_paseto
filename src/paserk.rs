//! PASERK (Platform-Agnostic Serialized Keys) integration for rusty_paseto.
//!
//! This module provides seamless conversion between PASETO key types and their
//! PASERK representations, enabling key serialization, identification, and
//! secure key management operations.
//!
//! # Features
//!
//! Enable PASERK support by adding the `paserk` feature to your Cargo.toml:
//!
//! ```toml
//! rusty_paseto = { version = "0.8", features = ["paserk", "v4_local"] }
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use rusty_paseto::prelude::*;
//! use rusty_paseto::paserk::*;
//!
//! // Create a PASETO key
//! let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(b"wubbalubbadubdubwubbalubbadubdub"));
//!
//! // Convert to PASERK string
//! let paserk_string = key.to_paserk_string();
//! assert!(paserk_string.starts_with("k4.local."));
//!
//! // Get the key ID for use in token footers
//! let key_id = key.paserk_id();
//! assert!(key_id.starts_with("k4.lid."));
//! ```

// Re-export paserk types
pub use paserk::core::error::{PaserkError, PaserkResult};
pub use paserk::core::operations::wrap::{Pie, WrapProtocol};
pub use paserk::core::types::{
    PaserkLocal, PaserkLocalId, PaserkLocalPw, PaserkLocalWrap, PaserkPublic, PaserkPublicId,
    PaserkSeal, PaserkSecret, PaserkSecretId, PaserkSecretPw, PaserkSecretWrap,
};
pub use paserk::core::version::{K1, K2, K3, K4, PaserkVersion};

// Re-export Argon2 params when using V2 or V4 (which support Argon2)
#[cfg(any(feature = "v2", feature = "v4"))]
pub use paserk::core::operations::pbkw::Argon2Params;

use crate::core::{Key, Local, Public};

/// Extension trait for converting PASETO keys to PASERK format.
///
/// This trait provides methods to serialize PASETO keys as PASERK strings
/// and compute key identifiers.
pub trait ToPaserk {
    /// The corresponding PASERK type for this key.
    type PaserkType;
    /// The corresponding PASERK ID type for this key.
    type PaserkIdType;

    /// Converts this key to its PASERK representation.
    fn to_paserk(&self) -> Self::PaserkType;

    /// Returns the PASERK string representation of this key.
    fn to_paserk_string(&self) -> String;

    /// Computes the PASERK key ID for this key.
    ///
    /// Key IDs are safe to include in token footers and can be used
    /// to identify which key was used to create a token.
    fn paserk_id(&self) -> String;
}

/// Extension trait for creating PASETO keys from PASERK format.
///
/// This trait provides methods to parse PASERK strings and create
/// PASETO keys from PASERK representations.
pub trait FromPaserk: Sized {
    /// The corresponding PASERK type for this key.
    type PaserkType;

    /// Creates a PASETO key from its PASERK representation.
    fn from_paserk(paserk: Self::PaserkType) -> Self;

    /// Parses a PASERK string and creates a PASETO key.
    ///
    /// # Errors
    ///
    /// Returns `PaserkError` if the string is not a valid PASERK representation
    /// for this key type.
    fn try_from_paserk_str(paserk: &str) -> Result<Self, PaserkError>;
}

// ============================================================================
// V4 Local Key Implementations
// ============================================================================

#[cfg(feature = "v4_local")]
mod v4_local_impl {
    use super::*;
    use crate::core::{PasetoSymmetricKey, V4};

    impl ToPaserk for PasetoSymmetricKey<V4, Local> {
        type PaserkType = PaserkLocal<K4>;
        type PaserkIdType = PaserkLocalId<K4>;

        fn to_paserk(&self) -> Self::PaserkType {
            let bytes: &[u8] = self.as_ref();
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(bytes);
            PaserkLocal::<K4>::from(key_bytes)
        }

        fn to_paserk_string(&self) -> String {
            self.to_paserk().to_string()
        }

        fn paserk_id(&self) -> String {
            let paserk = self.to_paserk();
            let id: PaserkLocalId<K4> = (&paserk).into();
            id.to_string()
        }
    }

    impl FromPaserk for PasetoSymmetricKey<V4, Local> {
        type PaserkType = PaserkLocal<K4>;

        fn from_paserk(paserk: Self::PaserkType) -> Self {
            let key = Key::<32>::from(paserk.as_bytes());
            PasetoSymmetricKey::<V4, Local>::from(key)
        }

        fn try_from_paserk_str(paserk: &str) -> Result<Self, PaserkError> {
            let parsed = PaserkLocal::<K4>::try_from(paserk)?;
            Ok(Self::from_paserk(parsed))
        }
    }

    // Implement Into/From for seamless conversion
    impl From<&PasetoSymmetricKey<V4, Local>> for PaserkLocal<K4> {
        fn from(key: &PasetoSymmetricKey<V4, Local>) -> Self {
            key.to_paserk()
        }
    }

    impl From<PaserkLocal<K4>> for PasetoSymmetricKey<V4, Local> {
        fn from(paserk: PaserkLocal<K4>) -> Self {
            Self::from_paserk(paserk)
        }
    }
}

// ============================================================================
// V4 Public Key Implementations
// ============================================================================

#[cfg(feature = "v4_public")]
mod v4_public_impl {
    use super::*;
    use crate::core::{PasetoAsymmetricPrivateKey, PasetoAsymmetricPublicKey, V4};

    impl<'a> ToPaserk for PasetoAsymmetricPublicKey<'a, V4, Public> {
        type PaserkType = PaserkPublic<K4>;
        type PaserkIdType = PaserkPublicId<K4>;

        fn to_paserk(&self) -> Self::PaserkType {
            let bytes: &[u8] = self.as_ref();
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(bytes);
            PaserkPublic::<K4>::from(key_bytes)
        }

        fn to_paserk_string(&self) -> String {
            self.to_paserk().to_string()
        }

        fn paserk_id(&self) -> String {
            let paserk = self.to_paserk();
            let id: PaserkPublicId<K4> = (&paserk).into();
            id.to_string()
        }
    }

    impl<'a> ToPaserk for PasetoAsymmetricPrivateKey<'a, V4, Public> {
        type PaserkType = PaserkSecret<K4>;
        type PaserkIdType = PaserkSecretId<K4>;

        fn to_paserk(&self) -> Self::PaserkType {
            let bytes: &[u8] = self.as_ref();
            let mut key_bytes = [0u8; 64];
            key_bytes.copy_from_slice(bytes);
            PaserkSecret::<K4>::from(key_bytes)
        }

        fn to_paserk_string(&self) -> String {
            self.to_paserk().to_string()
        }

        fn paserk_id(&self) -> String {
            let paserk = self.to_paserk();
            let id: PaserkSecretId<K4> = (&paserk).into();
            id.to_string()
        }
    }
}

// ============================================================================
// V2 Local Key Implementations
// ============================================================================

#[cfg(feature = "v2_local")]
mod v2_local_impl {
    use super::*;
    use crate::core::{PasetoSymmetricKey, V2};

    impl ToPaserk for PasetoSymmetricKey<V2, Local> {
        type PaserkType = PaserkLocal<K2>;
        type PaserkIdType = PaserkLocalId<K2>;

        fn to_paserk(&self) -> Self::PaserkType {
            let bytes: &[u8] = self.as_ref();
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(bytes);
            PaserkLocal::<K2>::from(key_bytes)
        }

        fn to_paserk_string(&self) -> String {
            self.to_paserk().to_string()
        }

        fn paserk_id(&self) -> String {
            let paserk = self.to_paserk();
            let id: PaserkLocalId<K2> = (&paserk).into();
            id.to_string()
        }
    }

    impl FromPaserk for PasetoSymmetricKey<V2, Local> {
        type PaserkType = PaserkLocal<K2>;

        fn from_paserk(paserk: Self::PaserkType) -> Self {
            let key = Key::<32>::from(paserk.as_bytes());
            PasetoSymmetricKey::<V2, Local>::from(key)
        }

        fn try_from_paserk_str(paserk: &str) -> Result<Self, PaserkError> {
            let parsed = PaserkLocal::<K2>::try_from(paserk)?;
            Ok(Self::from_paserk(parsed))
        }
    }

    impl From<&PasetoSymmetricKey<V2, Local>> for PaserkLocal<K2> {
        fn from(key: &PasetoSymmetricKey<V2, Local>) -> Self {
            key.to_paserk()
        }
    }

    impl From<PaserkLocal<K2>> for PasetoSymmetricKey<V2, Local> {
        fn from(paserk: PaserkLocal<K2>) -> Self {
            Self::from_paserk(paserk)
        }
    }
}

// ============================================================================
// V2 Public Key Implementations
// ============================================================================

#[cfg(feature = "v2_public")]
mod v2_public_impl {
    use super::*;
    use crate::core::{PasetoAsymmetricPrivateKey, PasetoAsymmetricPublicKey, V2};

    impl<'a> ToPaserk for PasetoAsymmetricPublicKey<'a, V2, Public> {
        type PaserkType = PaserkPublic<K2>;
        type PaserkIdType = PaserkPublicId<K2>;

        fn to_paserk(&self) -> Self::PaserkType {
            let bytes: &[u8] = self.as_ref();
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(bytes);
            PaserkPublic::<K2>::from(key_bytes)
        }

        fn to_paserk_string(&self) -> String {
            self.to_paserk().to_string()
        }

        fn paserk_id(&self) -> String {
            let paserk = self.to_paserk();
            let id: PaserkPublicId<K2> = (&paserk).into();
            id.to_string()
        }
    }

    impl<'a> ToPaserk for PasetoAsymmetricPrivateKey<'a, V2, Public> {
        type PaserkType = PaserkSecret<K2>;
        type PaserkIdType = PaserkSecretId<K2>;

        fn to_paserk(&self) -> Self::PaserkType {
            let bytes: &[u8] = self.as_ref();
            let mut key_bytes = [0u8; 64];
            key_bytes.copy_from_slice(bytes);
            PaserkSecret::<K2>::from(key_bytes)
        }

        fn to_paserk_string(&self) -> String {
            self.to_paserk().to_string()
        }

        fn paserk_id(&self) -> String {
            let paserk = self.to_paserk();
            let id: PaserkSecretId<K2> = (&paserk).into();
            id.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "v4_local")]
    mod v4_local_tests {
        use super::*;
        use crate::core::{PasetoSymmetricKey, V4};

        #[test]
        fn test_to_paserk_string() {
            let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(
                b"wubbalubbadubdubwubbalubbadubdub",
            ));
            let paserk_string = key.to_paserk_string();
            assert!(paserk_string.starts_with("k4.local."));
        }

        #[test]
        fn test_paserk_id() {
            let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(
                b"wubbalubbadubdubwubbalubbadubdub",
            ));
            let key_id = key.paserk_id();
            assert!(key_id.starts_with("k4.lid."));
        }

        #[test]
        fn test_roundtrip() {
            let original = PasetoSymmetricKey::<V4, Local>::from(Key::from(
                b"wubbalubbadubdubwubbalubbadubdub",
            ));
            let paserk_string = original.to_paserk_string();

            let parsed =
                PasetoSymmetricKey::<V4, Local>::try_from_paserk_str(&paserk_string).unwrap();

            // Compare the underlying bytes
            assert_eq!(original.as_ref(), parsed.as_ref());
        }

        #[test]
        fn test_from_paserk() {
            let paserk_string = "k4.local.d3ViYmFsdWJiYWR1YmR1Ynd1YmJhbHViYmFkdWJkdWI";
            let result = PasetoSymmetricKey::<V4, Local>::try_from_paserk_str(paserk_string);
            assert!(result.is_ok());
        }

        #[test]
        fn test_invalid_paserk_string() {
            let result = PasetoSymmetricKey::<V4, Local>::try_from_paserk_str("k4.local.invalid");
            assert!(result.is_err());
        }

        #[test]
        fn test_wrong_version_paserk_string() {
            // K2 string should not work for V4 key
            let result = PasetoSymmetricKey::<V4, Local>::try_from_paserk_str(
                "k2.local.d3ViYmFsdWJiYWR1YmR1Ynd1YmJhbHViYmFkdWJkdWI",
            );
            assert!(result.is_err());
        }
    }

    #[cfg(feature = "v4_public")]
    mod v4_public_tests {
        use super::*;
        use crate::core::{PasetoAsymmetricPublicKey, V4};

        #[test]
        fn test_public_key_to_paserk_string() {
            let key_bytes = Key::<32>::from([0x42u8; 32]);
            let key = PasetoAsymmetricPublicKey::<V4, Public>::from(&key_bytes);
            let paserk_string = key.to_paserk_string();
            assert!(paserk_string.starts_with("k4.public."));
        }

        #[test]
        fn test_public_key_paserk_id() {
            let key_bytes = Key::<32>::from([0x42u8; 32]);
            let key = PasetoAsymmetricPublicKey::<V4, Public>::from(&key_bytes);
            let key_id = key.paserk_id();
            assert!(key_id.starts_with("k4.pid."));
        }
    }
}
