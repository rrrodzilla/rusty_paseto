#![cfg(any(feature = "v1", doc))]
use crate::core::traits::*;
use std::fmt;
use std::fmt::Display;

/// ## Version 1: NIST Compatibility
///
/// See [the version 1 specification](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version1.md) for details. At a glance:
///
/// * **`v1.local`**: Symmetric Authenticated Encryption:
///   * AES-256-CTR + HMAC-SHA384 (Encrypt-then-MAC)
///   * Key-splitting: HKDF-SHA384
///     * Info for encryption key: `paseto-encryption-key`
///     * Info for authentication key: `paseto-auth-key-for-aead`
///   * 32-byte nonce (first half for AES-CTR, latter half for the HKDF salt)
///   * The nonce calculated from HMAC-SHA384(message, `random_bytes(32)`)
///     truncated to 32 bytes, during encryption only
///   * The HMAC covers the header, nonce, and ciphertext
///       * It also covers the footer, if provided
/// * **`v1.public`**: Asymmetric Authentication (Public-Key Signatures):
///   * 2048-bit RSA keys
///   * RSASSA-PSS with
///     * Hash function: SHA384 as the hash function
///     * Mask generation function: MGF1+SHA384
///     * Public exponent: 65537
///
/// Version 1 implements the best possible RSA + AES + SHA2 ciphersuite. We only use
/// OAEP and PSS for RSA encryption and RSA signatures (respectively), never PKCS1v1.5.
///
/// Version 1 is recommended only for legacy systems that cannot use modern cryptography.
#[derive(Debug, Clone, Copy)]
pub struct V1(&'static str);
impl AsRef<str> for V1 {
  fn as_ref(&self) -> &str {
    self.0
  }
}
impl V1orV3 for V1 {}
impl VersionTrait for V1 {}
impl Default for V1 {
  fn default() -> Self {
    Self("v1")
  }
}
impl Display for V1 {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", self.0)
  }
}
