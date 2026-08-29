// Allow deprecated error types within this module - we need to convert from them.
#![allow(deprecated)]

//! Unified error type for rusty_paseto.
//!
//! This module provides a single [`Error`] type that consolidates all error variants
//! from the core, generic, and prelude layers. New code should use this type instead
//! of the individual error types from each layer.
//!
//! # Example
//!
//! ```rust
//! use rusty_paseto::Error;
//!
//! fn handle_error(err: Error) {
//!     match err {
//!         Error::Expired => println!("Token expired"),
//!         Error::InvalidSignature => println!("Signature verification failed"),
//!         _ => println!("Other error: {}", err),
//!     }
//! }
//! ```

use thiserror::Error;

/// Unified error type for all rusty_paseto operations.
///
/// This enum consolidates errors from token building, parsing, claim validation,
/// and cryptographic operations into a single type for easier error handling.
///
/// # Non-exhaustive
///
/// This enum is marked `#[non_exhaustive]` to allow adding new variants in future
/// versions without breaking existing code.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    // ==================== Claim Errors ====================
    /// Token has expired (exp claim validation failed)
    #[error("token has expired")]
    Expired,

    /// Token cannot be used yet (nbf claim validation failed)
    #[error("token cannot be used before {0}")]
    NotYetValid(String),

    /// A required claim is missing from the token
    #[error("missing required claim: {0}")]
    MissingClaim(String),

    /// Claim value does not match expected value
    #[error("claim '{claim}' invalid: expected {expected}, got {actual}")]
    InvalidClaimValue {
        /// The claim key that failed validation
        claim: String,
        /// The expected value
        expected: String,
        /// The actual value found
        actual: String,
    },

    /// Attempted to use a reserved PASETO claim key for a custom claim
    #[error("'{0}' is a reserved claim key")]
    ReservedClaimKey(String),

    /// The same claim key appears multiple times in the token
    #[error("duplicate claim: '{0}'")]
    DuplicateClaim(String),

    /// A claim value could not be converted to its expected type
    #[error("could not convert claim '{0}' to expected type")]
    UnexpectedClaimType(String),

    /// A custom validation function failed for the specified claim
    #[error("custom validation failed for claim '{0}'")]
    CustomValidationFailed(String),

    /// Invalid RFC3339 date format in a time-based claim
    #[error("malformed RFC3339 date: {0}")]
    MalformedDate(String),

    /// Invalid email address format
    #[error("invalid email address: {0}")]
    InvalidEmail(String),

    // ==================== Crypto Errors ====================
    /// A cryptographic operation failed (details intentionally vague for security)
    #[error("cryptographic operation failed")]
    CryptoError,

    /// The provided key is in an invalid format
    #[error("invalid key format")]
    InvalidKey,

    /// Signature verification failed
    #[error("signature verification failed")]
    InvalidSignature,

    // ==================== Token Structure Errors ====================
    /// The token string has an invalid structure (wrong number of parts)
    #[error("invalid token structure")]
    InvalidTokenStructure,

    /// The token header is invalid or doesn't match the expected version/purpose
    #[error("invalid token header")]
    InvalidHeader,

    /// The token footer doesn't match the expected footer
    #[error("footer mismatch")]
    FooterMismatch,

    /// The token exceeds the maximum permitted size (default 64 KiB)
    #[error("token exceeds maximum permitted size")]
    TokenTooLarge,

    /// The footer exceeds the maximum permitted size (default 1024 bytes per PASETO spec recommendation)
    #[error("footer exceeds maximum permitted size")]
    FooterTooLarge,

    // ==================== Serialization Errors ====================
    /// JSON serialization or deserialization error
    #[cfg(feature = "generic")]
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Base64 decoding error
    #[error("base64 decoding failed: {0}")]
    Base64Decode(#[from] base64::DecodeError),

    /// UTF-8 string conversion error
    #[error("UTF-8 error: {0}")]
    Utf8(#[from] std::str::Utf8Error),

    /// UTF-8 string conversion error from owned bytes
    #[error("UTF-8 error: {0}")]
    FromUtf8(#[from] std::string::FromUtf8Error),

    // ==================== Time Format Errors ====================
    /// Error formatting time values
    #[error("time format error: {0}")]
    TimeFormat(#[from] time::error::Format),
}

/// A specialized Result type for rusty_paseto operations.
pub type Result<T> = std::result::Result<T, Error>;

// ==================== From implementations for existing error types ====================

#[cfg(feature = "generic")]
impl From<crate::generic::PasetoClaimError> for Error {
    fn from(err: crate::generic::PasetoClaimError) -> Self {
        use crate::generic::PasetoClaimError;
        match err {
            PasetoClaimError::Expired => Error::Expired,
            PasetoClaimError::UseBeforeAvailable(time) => Error::NotYetValid(time),
            PasetoClaimError::RFC3339Date(date) => Error::MalformedDate(date),
            PasetoClaimError::Missing(claim) => Error::MissingClaim(claim),
            PasetoClaimError::Unexpected(claim) => Error::UnexpectedClaimType(claim),
            PasetoClaimError::CustomValidation(claim) => Error::CustomValidationFailed(claim),
            PasetoClaimError::Invalid(claim, expected, actual) => Error::InvalidClaimValue {
                claim,
                expected,
                actual,
            },
            PasetoClaimError::Reserved(key) => Error::ReservedClaimKey(key),
            PasetoClaimError::DuplicateTopLevelPayloadClaim(claim) => Error::DuplicateClaim(claim),
        }
    }
}

#[cfg(feature = "generic")]
impl From<crate::generic::GenericBuilderError> for Error {
    fn from(err: crate::generic::GenericBuilderError) -> Self {
        use crate::generic::GenericBuilderError;
        match err {
            GenericBuilderError::ClaimError { source } => source.into(),
            GenericBuilderError::BadEmailAddress(email) => Error::InvalidEmail(email),
            GenericBuilderError::DuplicateTopLevelPayloadClaim(claim) => {
                Error::DuplicateClaim(claim)
            }
            GenericBuilderError::CipherError { source } => source.into(),
            GenericBuilderError::PayloadJsonError { source } => Error::Json(source),
        }
    }
}

#[cfg(feature = "generic")]
impl From<crate::generic::GenericParserError> for Error {
    fn from(err: crate::generic::GenericParserError) -> Self {
        use crate::generic::GenericParserError;
        match err {
            GenericParserError::ClaimError { source } => source.into(),
            GenericParserError::CipherError { source } => source.into(),
            GenericParserError::PayloadJsonError { source } => Error::Json(source),
        }
    }
}

#[cfg(feature = "core")]
impl From<crate::core::PasetoError> for Error {
    fn from(err: crate::core::PasetoError) -> Self {
        use crate::core::PasetoError;
        match err {
            PasetoError::PasetoCipherError(_) => Error::CryptoError,
            PasetoError::Cryption => Error::CryptoError,
            PasetoError::InvalidKey => Error::InvalidKey,
            PasetoError::Signature => Error::CryptoError,
            PasetoError::KeyRejected { .. } => Error::InvalidKey,
            PasetoError::Cipher { .. } => Error::CryptoError,
            #[cfg(feature = "ed25519-dalek")]
            PasetoError::RsaCipher { .. } => Error::CryptoError,
            #[cfg(feature = "p384")]
            PasetoError::ECSDAError { .. } => Error::CryptoError,
            #[cfg(feature = "blake2")]
            PasetoError::InvalidLength { .. } => Error::CryptoError,
            PasetoError::InvalidSignature => Error::InvalidSignature,
            PasetoError::TryFromSlice { .. } => Error::CryptoError,
            PasetoError::IncorrectSize => Error::InvalidTokenStructure,
            PasetoError::WrongHeader => Error::InvalidHeader,
            PasetoError::FooterInvalid => Error::FooterMismatch,
            PasetoError::PayloadBase64Decode { source } => Error::Base64Decode(source),
            PasetoError::Utf8Error { source } => Error::Utf8(source),
            PasetoError::ChaChaCipherError => Error::CryptoError,
            PasetoError::Infallible { .. } => {
                // This should never happen
                unreachable!("Infallible error should never be constructed")
            }
            PasetoError::FromUtf8Error { source } => Error::FromUtf8(source),
            PasetoError::TokenTooLarge => Error::TokenTooLarge,
            PasetoError::FooterTooLarge => Error::FooterTooLarge,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        assert_eq!(format!("{}", Error::Expired), "token has expired");
        assert_eq!(
            format!("{}", Error::NotYetValid("2024-01-01T00:00:00Z".to_string())),
            "token cannot be used before 2024-01-01T00:00:00Z"
        );
        assert_eq!(
            format!("{}", Error::MissingClaim("sub".to_string())),
            "missing required claim: sub"
        );
        assert_eq!(
            format!(
                "{}",
                Error::InvalidClaimValue {
                    claim: "aud".to_string(),
                    expected: "api".to_string(),
                    actual: "web".to_string(),
                }
            ),
            "claim 'aud' invalid: expected api, got web"
        );
    }

    #[test]
    fn test_error_is_non_exhaustive() {
        // This test just ensures the #[non_exhaustive] attribute compiles correctly
        // by using a wildcard pattern
        let err = Error::Expired;
        match err {
            Error::Expired => {}
            _ => {}
        }
    }
}
