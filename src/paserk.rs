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
// K1 is deprecated due to RUSTSEC-2023-0071 (Marvin Attack on RSA) but re-exported
// for users who need backward compatibility with v1_public_insecure tokens.
#[allow(deprecated)]
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

    // ========================================================================
    // V4 Local Key Tests
    // ========================================================================

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

        #[test]
        fn test_from_trait_conversion() {
            let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(
                b"wubbalubbadubdubwubbalubbadubdub",
            ));
            let paserk: PaserkLocal<K4> = (&key).into();
            assert!(paserk.to_string().starts_with("k4.local."));
        }

        #[test]
        fn test_into_trait_conversion() {
            let paserk_string = "k4.local.d3ViYmFsdWJiYWR1YmR1Ynd1YmJhbHViYmFkdWJkdWI";
            let paserk = PaserkLocal::<K4>::try_from(paserk_string).unwrap();
            let key: PasetoSymmetricKey<V4, Local> = paserk.into();
            assert_eq!(key.as_ref().len(), 32);
        }

        #[test]
        fn test_paserk_id_deterministic() {
            let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(
                b"wubbalubbadubdubwubbalubbadubdub",
            ));
            let id1 = key.paserk_id();
            let id2 = key.paserk_id();
            assert_eq!(id1, id2, "Key IDs should be deterministic");
        }

        #[test]
        fn test_different_keys_different_ids() {
            let key1 = PasetoSymmetricKey::<V4, Local>::from(Key::from(
                b"wubbalubbadubdubwubbalubbadubdub",
            ));
            let key2 = PasetoSymmetricKey::<V4, Local>::from(Key::from(
                b"different-key-different-keyXXXXZ",
            ));
            assert_ne!(
                key1.paserk_id(),
                key2.paserk_id(),
                "Different keys should have different IDs"
            );
        }
    }

    // ========================================================================
    // V4 Public Key Tests
    // ========================================================================

    #[cfg(feature = "v4_public")]
    mod v4_public_tests {
        use super::*;
        use crate::core::{PasetoAsymmetricPrivateKey, PasetoAsymmetricPublicKey, V4};

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

        #[test]
        fn test_public_key_roundtrip() {
            let key_bytes = Key::<32>::from([0x42u8; 32]);
            let original = PasetoAsymmetricPublicKey::<V4, Public>::from(&key_bytes);
            let paserk_string = original.to_paserk_string();

            // Verify the PASERK string can be parsed back
            let parsed = PaserkPublic::<K4>::try_from(paserk_string.as_str()).unwrap();
            assert_eq!(original.as_ref(), parsed.as_bytes());
        }

        #[test]
        fn test_secret_key_to_paserk_string() {
            let key_bytes = Key::<64>::from([0x42u8; 64]);
            let key = PasetoAsymmetricPrivateKey::<V4, Public>::from(&key_bytes);
            let paserk_string = key.to_paserk_string();
            assert!(paserk_string.starts_with("k4.secret."));
        }

        #[test]
        fn test_secret_key_paserk_id() {
            let key_bytes = Key::<64>::from([0x42u8; 64]);
            let key = PasetoAsymmetricPrivateKey::<V4, Public>::from(&key_bytes);
            let key_id = key.paserk_id();
            assert!(key_id.starts_with("k4.sid."));
        }

        #[test]
        fn test_secret_key_roundtrip() {
            let key_bytes = Key::<64>::from([0x42u8; 64]);
            let original = PasetoAsymmetricPrivateKey::<V4, Public>::from(&key_bytes);
            let paserk_string = original.to_paserk_string();

            // Verify the PASERK string can be parsed back
            let parsed = PaserkSecret::<K4>::try_from(paserk_string.as_str()).unwrap();
            assert_eq!(original.as_ref(), parsed.as_bytes());
        }

        #[test]
        fn test_public_key_id_deterministic() {
            let key_bytes = Key::<32>::from([0x42u8; 32]);
            let key = PasetoAsymmetricPublicKey::<V4, Public>::from(&key_bytes);
            let id1 = key.paserk_id();
            let id2 = key.paserk_id();
            assert_eq!(id1, id2);
        }

        #[test]
        fn test_secret_key_id_deterministic() {
            let key_bytes = Key::<64>::from([0x42u8; 64]);
            let key = PasetoAsymmetricPrivateKey::<V4, Public>::from(&key_bytes);
            let id1 = key.paserk_id();
            let id2 = key.paserk_id();
            assert_eq!(id1, id2);
        }

        #[test]
        fn test_different_public_keys_different_ids() {
            let key1_bytes = Key::<32>::from([0x42u8; 32]);
            let key1 = PasetoAsymmetricPublicKey::<V4, Public>::from(&key1_bytes);

            let key2_bytes = Key::<32>::from([0x43u8; 32]);
            let key2 = PasetoAsymmetricPublicKey::<V4, Public>::from(&key2_bytes);

            assert_ne!(key1.paserk_id(), key2.paserk_id());
        }
    }

    // ========================================================================
    // V2 Local Key Tests
    // ========================================================================

    #[cfg(feature = "v2_local")]
    mod v2_local_tests {
        use super::*;
        use crate::core::{PasetoSymmetricKey, V2};

        #[test]
        fn test_to_paserk_string() {
            let key = PasetoSymmetricKey::<V2, Local>::from(Key::from(
                b"wubbalubbadubdubwubbalubbadubdub",
            ));
            let paserk_string = key.to_paserk_string();
            assert!(paserk_string.starts_with("k2.local."));
        }

        #[test]
        fn test_paserk_id() {
            let key = PasetoSymmetricKey::<V2, Local>::from(Key::from(
                b"wubbalubbadubdubwubbalubbadubdub",
            ));
            let key_id = key.paserk_id();
            assert!(key_id.starts_with("k2.lid."));
        }

        #[test]
        fn test_roundtrip() {
            let original = PasetoSymmetricKey::<V2, Local>::from(Key::from(
                b"wubbalubbadubdubwubbalubbadubdub",
            ));
            let paserk_string = original.to_paserk_string();

            let parsed =
                PasetoSymmetricKey::<V2, Local>::try_from_paserk_str(&paserk_string).unwrap();

            assert_eq!(original.as_ref(), parsed.as_ref());
        }

        #[test]
        fn test_from_paserk() {
            let paserk_string = "k2.local.d3ViYmFsdWJiYWR1YmR1Ynd1YmJhbHViYmFkdWJkdWI";
            let result = PasetoSymmetricKey::<V2, Local>::try_from_paserk_str(paserk_string);
            assert!(result.is_ok());
        }

        #[test]
        fn test_invalid_paserk_string() {
            let result = PasetoSymmetricKey::<V2, Local>::try_from_paserk_str("k2.local.invalid");
            assert!(result.is_err());
        }

        #[test]
        fn test_wrong_version_paserk_string() {
            // K4 string should not work for V2 key
            let result = PasetoSymmetricKey::<V2, Local>::try_from_paserk_str(
                "k4.local.d3ViYmFsdWJiYWR1YmR1Ynd1YmJhbHViYmFkdWJkdWI",
            );
            assert!(result.is_err());
        }

        #[test]
        fn test_from_trait_conversion() {
            let key = PasetoSymmetricKey::<V2, Local>::from(Key::from(
                b"wubbalubbadubdubwubbalubbadubdub",
            ));
            let paserk: PaserkLocal<K2> = (&key).into();
            assert!(paserk.to_string().starts_with("k2.local."));
        }

        #[test]
        fn test_into_trait_conversion() {
            let paserk_string = "k2.local.d3ViYmFsdWJiYWR1YmR1Ynd1YmJhbHViYmFkdWJkdWI";
            let paserk = PaserkLocal::<K2>::try_from(paserk_string).unwrap();
            let key: PasetoSymmetricKey<V2, Local> = paserk.into();
            assert_eq!(key.as_ref().len(), 32);
        }

        #[test]
        fn test_paserk_id_deterministic() {
            let key = PasetoSymmetricKey::<V2, Local>::from(Key::from(
                b"wubbalubbadubdubwubbalubbadubdub",
            ));
            let id1 = key.paserk_id();
            let id2 = key.paserk_id();
            assert_eq!(id1, id2);
        }
    }

    // ========================================================================
    // V2 Public Key Tests
    // ========================================================================

    #[cfg(feature = "v2_public")]
    mod v2_public_tests {
        use super::*;
        use crate::core::{PasetoAsymmetricPrivateKey, PasetoAsymmetricPublicKey, V2};

        #[test]
        fn test_public_key_to_paserk_string() {
            let key_bytes = Key::<32>::from([0x42u8; 32]);
            let key = PasetoAsymmetricPublicKey::<V2, Public>::from(&key_bytes);
            let paserk_string = key.to_paserk_string();
            assert!(paserk_string.starts_with("k2.public."));
        }

        #[test]
        fn test_public_key_paserk_id() {
            let key_bytes = Key::<32>::from([0x42u8; 32]);
            let key = PasetoAsymmetricPublicKey::<V2, Public>::from(&key_bytes);
            let key_id = key.paserk_id();
            assert!(key_id.starts_with("k2.pid."));
        }

        #[test]
        fn test_public_key_roundtrip() {
            let key_bytes = Key::<32>::from([0x42u8; 32]);
            let original = PasetoAsymmetricPublicKey::<V2, Public>::from(&key_bytes);
            let paserk_string = original.to_paserk_string();

            let parsed = PaserkPublic::<K2>::try_from(paserk_string.as_str()).unwrap();
            assert_eq!(original.as_ref(), parsed.as_bytes());
        }

        #[test]
        fn test_secret_key_to_paserk_string() {
            let key_bytes = Key::<64>::from([0x42u8; 64]);
            let key = PasetoAsymmetricPrivateKey::<V2, Public>::from(&key_bytes);
            let paserk_string = key.to_paserk_string();
            assert!(paserk_string.starts_with("k2.secret."));
        }

        #[test]
        fn test_secret_key_paserk_id() {
            let key_bytes = Key::<64>::from([0x42u8; 64]);
            let key = PasetoAsymmetricPrivateKey::<V2, Public>::from(&key_bytes);
            let key_id = key.paserk_id();
            assert!(key_id.starts_with("k2.sid."));
        }

        #[test]
        fn test_secret_key_roundtrip() {
            let key_bytes = Key::<64>::from([0x42u8; 64]);
            let original = PasetoAsymmetricPrivateKey::<V2, Public>::from(&key_bytes);
            let paserk_string = original.to_paserk_string();

            let parsed = PaserkSecret::<K2>::try_from(paserk_string.as_str()).unwrap();
            assert_eq!(original.as_ref(), parsed.as_bytes());
        }
    }

    // ========================================================================
    // Advanced Operations Tests - PIE Key Wrapping
    // ========================================================================

    #[cfg(feature = "v4_local")]
    mod v4_pie_wrap_tests {
        use super::*;
        use crate::core::{PasetoSymmetricKey, V4};

        #[test]
        fn test_local_key_wrap_roundtrip() {
            let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(
                b"wubbalubbadubdubwubbalubbadubdub",
            ));
            let wrapping_key = PaserkLocal::<K4>::from([0x42u8; 32]);

            // Convert to PASERK and wrap
            let paserk = key.to_paserk();
            let wrapped = PaserkLocalWrap::<K4, Pie>::try_wrap(&paserk, &wrapping_key).unwrap();
            let wrapped_string = wrapped.to_string();

            assert!(wrapped_string.starts_with("k4.local-wrap.pie."));

            // Unwrap and verify
            let parsed_wrapped =
                PaserkLocalWrap::<K4, Pie>::try_from(wrapped_string.as_str()).unwrap();
            let unwrapped = parsed_wrapped.try_unwrap(&wrapping_key).unwrap();

            assert_eq!(paserk.as_bytes(), unwrapped.as_bytes());
        }

        #[test]
        fn test_wrap_wrong_key_fails() {
            let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(
                b"wubbalubbadubdubwubbalubbadubdub",
            ));
            let wrapping_key = PaserkLocal::<K4>::from([0x42u8; 32]);
            let wrong_key = PaserkLocal::<K4>::from([0x43u8; 32]);

            let paserk = key.to_paserk();
            let wrapped = PaserkLocalWrap::<K4, Pie>::try_wrap(&paserk, &wrapping_key).unwrap();

            // Unwrapping with wrong key should fail
            let result = wrapped.try_unwrap(&wrong_key);
            assert!(result.is_err());
        }
    }

    #[cfg(feature = "v4_public")]
    mod v4_secret_wrap_tests {
        use super::*;
        use crate::core::{PasetoAsymmetricPrivateKey, V4};

        #[test]
        fn test_secret_key_wrap_roundtrip() {
            let key_bytes = Key::<64>::from([0x42u8; 64]);
            let key = PasetoAsymmetricPrivateKey::<V4, Public>::from(&key_bytes);
            let wrapping_key = PaserkLocal::<K4>::from([0x55u8; 32]);

            // Convert to PASERK and wrap
            let paserk = key.to_paserk();
            let wrapped = PaserkSecretWrap::<K4, Pie>::try_wrap(&paserk, &wrapping_key).unwrap();
            let wrapped_string = wrapped.to_string();

            assert!(wrapped_string.starts_with("k4.secret-wrap.pie."));

            // Unwrap and verify
            let parsed_wrapped =
                PaserkSecretWrap::<K4, Pie>::try_from(wrapped_string.as_str()).unwrap();
            let unwrapped = parsed_wrapped.try_unwrap(&wrapping_key).unwrap();

            assert_eq!(paserk.as_bytes(), unwrapped.as_bytes());
        }
    }

    // ========================================================================
    // Advanced Operations Tests - Password-Based Key Wrapping
    // ========================================================================

    #[cfg(feature = "v4_local")]
    mod v4_password_wrap_tests {
        use super::*;
        use crate::core::{PasetoSymmetricKey, V4};

        #[test]
        fn test_local_key_password_wrap_roundtrip() {
            let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(
                b"wubbalubbadubdubwubbalubbadubdub",
            ));
            let password = b"super-secret-password";

            // Use low-cost params for testing
            let params = Argon2Params {
                memory_kib: 1024,
                iterations: 1,
                parallelism: 1,
            };

            let paserk = key.to_paserk();
            let wrapped = PaserkLocalPw::<K4>::try_wrap(&paserk, password, params).unwrap();
            let wrapped_string = wrapped.to_string();

            assert!(wrapped_string.starts_with("k4.local-pw."));

            // Unwrap and verify
            let parsed = PaserkLocalPw::<K4>::try_from(wrapped_string.as_str()).unwrap();
            // Parameters are extracted from the serialized data, but we pass dummy params
            let unwrapped = parsed.try_unwrap(password, params).unwrap();

            assert_eq!(paserk.as_bytes(), unwrapped.as_bytes());
        }

        #[test]
        fn test_password_wrap_wrong_password_fails() {
            let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(
                b"wubbalubbadubdubwubbalubbadubdub",
            ));
            let password = b"correct-password";
            let wrong_password = b"wrong-password";

            let params = Argon2Params {
                memory_kib: 1024,
                iterations: 1,
                parallelism: 1,
            };

            let paserk = key.to_paserk();
            let wrapped = PaserkLocalPw::<K4>::try_wrap(&paserk, password, params).unwrap();

            let result = wrapped.try_unwrap(wrong_password, params);
            assert!(result.is_err());
        }
    }

    #[cfg(feature = "v4_public")]
    mod v4_secret_password_wrap_tests {
        use super::*;
        use crate::core::{PasetoAsymmetricPrivateKey, V4};

        #[test]
        fn test_secret_key_password_wrap_roundtrip() {
            let key_bytes = Key::<64>::from([0x42u8; 64]);
            let key = PasetoAsymmetricPrivateKey::<V4, Public>::from(&key_bytes);
            let password = b"my-secret-password";

            let params = Argon2Params {
                memory_kib: 1024,
                iterations: 1,
                parallelism: 1,
            };

            let paserk = key.to_paserk();
            let wrapped = PaserkSecretPw::<K4>::try_wrap(&paserk, password, params).unwrap();
            let wrapped_string = wrapped.to_string();

            assert!(wrapped_string.starts_with("k4.secret-pw."));

            // Unwrap and verify
            let parsed = PaserkSecretPw::<K4>::try_from(wrapped_string.as_str()).unwrap();
            let unwrapped = parsed.try_unwrap(password, params).unwrap();

            assert_eq!(paserk.as_bytes(), unwrapped.as_bytes());
        }
    }

    // ========================================================================
    // Advanced Operations Tests - Public Key Encryption (Seal)
    // ========================================================================

    #[cfg(all(feature = "v4_local", feature = "v4_public"))]
    mod v4_seal_tests {
        use super::*;
        use crate::core::{PasetoSymmetricKey, V4};

        /// Creates a valid Ed25519 keypair for testing.
        /// Returns (secret_key_bytes, PaserkSecret)
        fn create_test_keypair() -> (PaserkSecret<K4>, PaserkSecret<K4>) {
            // Use a fixed seed for reproducibility
            let seed = [0x42u8; 32];

            // Create Ed25519 signing key from seed using ed25519-dalek
            // The keypair format is: seed (32 bytes) || public_key (32 bytes)
            use ed25519_dalek::SigningKey;
            let signing_key = SigningKey::from_bytes(&seed);
            let keypair_bytes = signing_key.to_keypair_bytes();

            let secret = PaserkSecret::<K4>::from(keypair_bytes);
            (secret.clone(), secret)
        }

        /// Creates a different Ed25519 keypair for testing wrong key scenarios.
        fn create_different_keypair() -> PaserkSecret<K4> {
            let seed = [0x55u8; 32];
            use ed25519_dalek::SigningKey;
            let signing_key = SigningKey::from_bytes(&seed);
            PaserkSecret::<K4>::from(signing_key.to_keypair_bytes())
        }

        #[test]
        fn test_seal_unseal_roundtrip() {
            let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(
                b"wubbalubbadubdubwubbalubbadubdub",
            ));

            let (secret, _) = create_test_keypair();
            let paserk = key.to_paserk();

            // Seal with secret key (derives public key internally)
            let sealed = PaserkSeal::<K4>::try_seal(&paserk, &secret).unwrap();
            let sealed_string = sealed.to_string();

            assert!(sealed_string.starts_with("k4.seal."));

            // Unseal with secret key
            let parsed_sealed = PaserkSeal::<K4>::try_from(sealed_string.as_str()).unwrap();
            let unsealed = parsed_sealed.try_unseal(&secret).unwrap();

            assert_eq!(paserk.as_bytes(), unsealed.as_bytes());
        }

        #[test]
        fn test_seal_produces_different_output_each_time() {
            let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(
                b"wubbalubbadubdubwubbalubbadubdub",
            ));

            let (secret, _) = create_test_keypair();
            let paserk = key.to_paserk();

            let sealed1 = PaserkSeal::<K4>::try_seal(&paserk, &secret)
                .unwrap()
                .to_string();
            let sealed2 = PaserkSeal::<K4>::try_seal(&paserk, &secret)
                .unwrap()
                .to_string();

            // Each seal operation uses a random ephemeral key, so outputs should differ
            assert_ne!(sealed1, sealed2);
        }

        #[test]
        fn test_unseal_wrong_key_fails() {
            let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(
                b"wubbalubbadubdubwubbalubbadubdub",
            ));

            let (secret, _) = create_test_keypair();
            let wrong_secret = create_different_keypair();

            let paserk = key.to_paserk();
            let sealed = PaserkSeal::<K4>::try_seal(&paserk, &secret).unwrap();

            let result = sealed.try_unseal(&wrong_secret);
            assert!(result.is_err());
        }
    }

    // ========================================================================
    // PASERK Type Parsing Tests
    // ========================================================================

    #[cfg(feature = "v4_local")]
    mod paserk_parsing_tests {
        use super::*;

        #[test]
        fn test_parse_local_wrong_type() {
            // Try to parse a public key as local
            let result = PaserkLocal::<K4>::try_from("k4.public.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
            assert!(result.is_err());
        }

        #[test]
        fn test_parse_empty_string() {
            let result = PaserkLocal::<K4>::try_from("");
            assert!(result.is_err());
        }

        #[test]
        fn test_parse_malformed_header() {
            let result = PaserkLocal::<K4>::try_from("k4local.AAAA");
            assert!(result.is_err());
        }
    }

    // ========================================================================
    // Cross-Version Compatibility Tests
    // ========================================================================

    #[cfg(all(feature = "v4_local", feature = "v2_local"))]
    mod cross_version_tests {
        use super::*;
        use crate::core::{PasetoSymmetricKey, V2, V4};

        #[test]
        fn test_same_key_different_versions_different_paserk() {
            let key_bytes = b"wubbalubbadubdubwubbalubbadubdub";

            let v4_key = PasetoSymmetricKey::<V4, Local>::from(Key::from(key_bytes));
            let v2_key = PasetoSymmetricKey::<V2, Local>::from(Key::from(key_bytes));

            let v4_paserk = v4_key.to_paserk_string();
            let v2_paserk = v2_key.to_paserk_string();

            // Same key bytes should produce different PASERK strings (different version prefix)
            assert!(v4_paserk.starts_with("k4.local."));
            assert!(v2_paserk.starts_with("k2.local."));

            // The encoded data part should be the same
            let v4_data = v4_paserk.strip_prefix("k4.local.").unwrap();
            let v2_data = v2_paserk.strip_prefix("k2.local.").unwrap();
            assert_eq!(v4_data, v2_data);
        }

        #[test]
        fn test_key_ids_different_across_versions() {
            let key_bytes = b"wubbalubbadubdubwubbalubbadubdub";

            let v4_key = PasetoSymmetricKey::<V4, Local>::from(Key::from(key_bytes));
            let v2_key = PasetoSymmetricKey::<V2, Local>::from(Key::from(key_bytes));

            let v4_id = v4_key.paserk_id();
            let v2_id = v2_key.paserk_id();

            // Different versions should produce different key IDs
            assert!(v4_id.starts_with("k4.lid."));
            assert!(v2_id.starts_with("k2.lid."));
            assert_ne!(v4_id, v2_id);
        }
    }

    // ========================================================================
    // Prelude Re-exports Tests
    // ========================================================================

    #[cfg(all(feature = "v4_local", feature = "batteries_included"))]
    mod prelude_tests {
        use crate::prelude::*;

        #[test]
        fn test_prelude_topaserk_reexport() {
            use crate::paserk::ToPaserk;

            let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(
                b"wubbalubbadubdubwubbalubbadubdub",
            ));
            let paserk_string = key.to_paserk_string();
            assert!(paserk_string.starts_with("k4.local."));
        }

        #[test]
        fn test_prelude_frompaserk_reexport() {
            use crate::paserk::FromPaserk;

            let paserk_string = "k4.local.d3ViYmFsdWJiYWR1YmR1Ynd1YmJhbHViYmFkdWJkdWI";
            let result = PasetoSymmetricKey::<V4, Local>::try_from_paserk_str(paserk_string);
            assert!(result.is_ok());
        }
    }
}
