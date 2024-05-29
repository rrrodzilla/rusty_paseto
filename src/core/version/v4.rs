#![cfg(any(feature = "v4", doc))]
use crate::core::traits::*;
use std::fmt;
use std::fmt::Display;

/// ## Version 4: Sodium Modern
///
/// See [the version 4 specification](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md) for details. At a glance:
///
/// * **`v4.local`**: Symmetric Authenticated Encryption:
///     * XChaCha20 + BLAKE2b-MAC (Encrypt-then-MAC)
///     * Key-splitting: BLAKE2b
///         * Info for encryption key: `paseto-encryption-key`
///           The encryption key and implicit counter nonce are both returned
///           from BLAKE2b in this version.
///         * Info for authentication key: `paseto-auth-key-for-aead`
///     * 32-byte nonce (no longer prehashed), passed entirely to BLAKE2b.
///     * The BLAKE2b-MAC covers the header, nonce, and ciphertext
///         * It also covers the footer, if provided
///         * It also covers the implicit assertions, if provided
/// * **`v4.public`**: Asymmetric Authentication (Public-Key Signatures):
///     * Ed25519 (EdDSA over Curve25519)
///     * Signing: `sodium_crypto_sign_detached()`
///     * Verifying: `sodium_crypto_sign_verify_detached()`
#[derive(Debug, Clone, Copy)]
pub struct V4(&'static str);
impl VersionTrait for V4 {}
impl ImplicitAssertionCapable for V4 {}
impl V2orV4 for V4 {}
impl AsRef<str> for V4 {
  fn as_ref(&self) -> &str {
    self.0
  }
}
impl Default for V4 {
  fn default() -> Self {
    Self("v4")
  }
}
impl Display for V4 {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", self.0)
  }
}
