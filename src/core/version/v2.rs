#![cfg(any(feature = "v2", doc))]
use crate::core::traits::*;
use std::fmt;
use std::fmt::Display;

/// ## Version 2: Sodium Original
///
/// See [the version 2 specification](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version2.md) for details. At a glance:
///
/// * **`v2.local`**: Symmetric Encryption:
///   * XChaCha20-Poly1305 (192-bit nonce, 256-bit key, 128-bit authentication tag)
///   * Encrypting: `sodium_crypto_aead_xchacha20poly1305_ietf_encrypt()`
///   * Decrypting: `sodium_crypto_aead_xchacha20poly1305_ietf_decrypt()`
///   * The nonce is calculated from `sodium_crypto_generichash()` of the message,
///     with a BLAKE2b key provided by `random_bytes(24)` and an output length of 24,
///     during encryption only
///   * Reference implementation in [Version2.php](https://github.com/paragonie/paseto/blob/master/src/Protocol/Version2.php):
///     * See `aeadEncrypt()` for encryption
///     * See `aeadDecrypt()` for decryption
/// * **`v2.public`**: Asymmetric Authentication (Public-Key Signatures):
///   * Ed25519 (EdDSA over Curve25519)
///   * Signing: `sodium_crypto_sign_detached()`
///   * Verifying: `sodium_crypto_sign_verify_detached()`
///   * Reference implementation in [Version2.php](https://github.com/paragonie/paseto/blob/master/src/Protocol/Version2.php):
///     * See `sign()` for signature generation
///     * See `verify()` for signature verification
#[derive(Debug, Clone, Copy)]
pub struct V2(&'static str);
impl VersionTrait for V2 {}
impl AsRef<str> for V2 {
  fn as_ref(&self) -> &str {
    self.0
  }
}
impl V2orV4 for V2 {}
impl Default for V2 {
  fn default() -> Self {
    Self("v2")
  }
}
impl Display for V2 {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", self.0)
  }
}
