#![cfg(any(feature = "v3", doc))]
use crate::core::traits::*;
use std::fmt;
use std::fmt::Display;

/// ## Version 3: NIST Modern
///
/// See [the version 3 specification](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version3.md) for details. At a glance:
///
/// * **`v3.local`**: Symmetric Authenticated Encryption:
///     * AES-256-CTR + HMAC-SHA384 (Encrypt-then-MAC)
///     * Key-splitting: HKDF-SHA384
///         * Info for encryption key: `paseto-encryption-key`
///           The encryption key and implicit counter nonce are both returned
///           from HKDF in this version.
///         * Info for authentication key: `paseto-auth-key-for-aead`
///     * 32-byte nonce (no longer prehashed), passed entirely to HKDF
///       (as part of the `info` tag, rather than as a salt).
///     * The HMAC covers the header, nonce, and ciphertext
///       * It also covers the footer, if provided
///       * It also covers the implicit assertions, if provided
/// * **`v3.public`**: Asymmetric Authentication (Public-Key Signatures):
///     * ECDSA over NIST P-384, with SHA-384,
///       using [RFC 6979 deterministic k-values](https://tools.ietf.org/html/rfc6979)
///       (if reasonably practical; otherwise a CSPRNG **MUST** be used).
///       Hedged signatures are allowed too.
///     * The public key is also included in the PAE step, to ensure
///       `v3.public` tokens provide Exclusive Ownership.
#[derive(Debug, Clone, Copy)]
pub struct V3(&'static str);
impl VersionTrait for V3 {}
impl AsRef<str> for V3 {
  fn as_ref(&self) -> &str {
    self.0
  }
}
impl ImplicitAssertionCapable for V3 {}
impl V1orV3 for V3 {}
impl Default for V3 {
  fn default() -> Self {
    Self("v3")
  }
}
impl Display for V3 {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", self.0)
  }
}
